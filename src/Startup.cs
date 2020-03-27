using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace HMACAuth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            services.AddAuthentication("HMAC")
                .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>("HMAC", options => { });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.Use(async (context, next) =>
            {
                if (context.Request.Headers[HeaderNames.Authorization] != "test")
                {
                    context.Response.StatusCode = 401;
                }

                await next();
            });

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
    {
        public ApiKeyAuthenticationHandler(IOptionsMonitor<ApiKeyAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder urlEncoder, ISystemClock systemClock)
            : base(options, logger, urlEncoder, systemClock)
        {
            Secrets.Add("088546f2-aba0-49d0-9323-4b07bf926ab1", "pWN4NAwKk+SUokEvDNZ4fcX3t2ozTFPgypXKchk1ulM=");
        }

        private Dictionary<string, string> Secrets { get; } = new Dictionary<string, string>();

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var header = Request.Headers[HeaderNames.Authorization].SingleOrDefault();

            if (!TryValidateAuthorizationHeader(header, out var credentials))
            {
                return Task.FromResult(AuthenticateResult.Fail("Invalid Authorization header value, expected 'HMAC <access key>:<message digest>'"));
            }

            if (Secrets.ContainsKey(credentials.Key))
            {
                return Task.FromResult(AuthenticateResult.Fail("Unrecognized access key"));
            }


            throw new NotImplementedException();
        }

        private bool TryValidateAuthorizationHeader(string header, out (string Key, string Digest) credentials)
        {
            credentials = (null, null);

            var pattern = "^hmac [a-zA-Z0-9-]{36}:[a-zA-Z0-9]{64}$";

            if (!Regex.IsMatch(header, pattern, RegexOptions.IgnoreCase))
            {
                return false;
            }

            var parts = header.Split(' ', ':');
            var key = parts[1];
            var digest = parts[2];

            if (!Guid.TryParseExact(key, "D", out _))
            {
                return false;
            }

            credentials = (key, digest);
            return true;
        }
    }

    public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
    {

    }

    public static class Utility
    {
        public static string GenerateSecretKey()
        {
            using (var cryptoProvider = new RNGCryptoServiceProvider())
            {
                byte[] secretKeyByteArray = new byte[32]; //256 bit
                cryptoProvider.GetBytes(secretKeyByteArray);
                return Convert.ToBase64String(secretKeyByteArray);
            }
        }
    }
}
