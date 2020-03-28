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
                .AddScheme<HMACAuthenticationOptions, HMACAuthenticationHandler>("HMAC", options => { });
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

    public class HMACAuthenticationHandler : AuthenticationHandler<HMACAuthenticationOptions>
    {
        public HMACAuthenticationHandler(IOptionsMonitor<HMACAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder urlEncoder, ISystemClock systemClock)
            : base(options, logger, urlEncoder, systemClock)
        {
            Secrets.Add("088546f2-aba0-49d0-9323-4b07bf926ab1", "pWN4NAwKk+SUokEvDNZ4fcX3t2ozTFPgypXKchk1ulM=");
        }

        private Dictionary<string, string> Secrets { get; } = new Dictionary<string, string>();
        private string[] RequiredHeaders { get; } = new[] {
            HeaderNames.Authorization,
            HeaderNames.Date,
            HeaderNames.RequestId,
            HeaderNames.ContentLength,
            HeaderNames.ContentMD5
        };

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            static Task<AuthenticateResult> Fail(string reason, AuthenticationProperties props = null) =>
                Task.FromResult(AuthenticateResult.Fail(reason, props));

            if (!TryValidateRequiredHeaders(Request, RequiredHeaders, out var missingHeaders))
            {
                return Fail($"Missing one or more required headers: {missingHeaders}");
            }

            if (!TryValidateRequestTime(Request, out var message))
            {
                return Fail($"something about request being too old");
            }

            if (!TryValidateAuthorizationHeader(Request, out var credentials, out message))
            {
                return Fail($"Invalid Authorization header value: {message}");
            }

            if (!Secrets.ContainsKey(credentials.Key))
            {
                return Fail("Unrecognized access key");
            }

            var secret = Secrets[credentials.Key];

            // todo: compute digest and compare

            throw new NotImplementedException();
        }

        public bool TryValidateRequestTime(HttpRequest request, out string message)
        {
            message = null;

            // todo: validate Date header against clock/drift settings to ensure it is within the window

            return true;
        }

        public bool TryValidateRequiredHeaders(HttpRequest request, string[] requiredHeaders, out string missingHeaders)
        {
            missingHeaders = null;
            var missing = requiredHeaders.Where(header => request.Headers[header] == string.Empty);

            if (missing.Any())
            {
                missingHeaders = string.Join(" ,", missing);
                return false;
            }

            return true;
        }

        public bool TryValidateAuthorizationHeader(HttpRequest request, out (string Key, string Digest) credentials, out string error)
        {
            credentials = (null, null);
            error = "Unknown error";

            var headers = request.Headers[HeaderNames.Authorization].ToList();

            if (headers.Count > 1)
            {
                error = "Multiple Authorization headers provided with request";
                return false;
            }

            var header = headers[0];
            var pattern = "^hmac [a-zA-Z0-9-]{36}:[a-zA-Z0-9]{64}$";

            if (!Regex.IsMatch(header, pattern, RegexOptions.IgnoreCase))
            {
                error = $"Invalid format; expected 'HMAC <access key:36>:<message digest:64>', received {header}";
                return false;
            }

            var parts = header.Split(' ', ':');
            var key = parts[1];
            var digest = parts[2];

            if (!Guid.TryParseExact(key, "D", out _))
            {
                error = $"Access key is not a valid GUID/UUID; expected format '00000000-0000-0000-0000-000000000000', received {key}";
                return false;
            }

            credentials = (key, digest);
            return true;
        }
    }

    public class HMACAuthenticationOptions : AuthenticationSchemeOptions
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
