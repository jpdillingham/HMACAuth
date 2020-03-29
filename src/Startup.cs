using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
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
                .AddScheme<HMACAuthenticationOptions, HMACAuthenticationHandler>("HMAC", options => 
                {
                    options.ClockDrift = new TimeSpan(hours: 0, minutes: 5, seconds: 0);
                    options.RequiredHeaders = new[] { 
                        HeaderNames.Date, 
                        HeaderNames.RequestId, 
                        HeaderNames.Authorization, 
                        HeaderNames.ContentLength
                    };
                });
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
        public HMACAuthenticationHandler(IOptionsMonitor<HMACAuthenticationOptions> optionsMonitor, ILoggerFactory logger, UrlEncoder urlEncoder, ISystemClock systemClock)
            : base(optionsMonitor, logger, urlEncoder, systemClock)
        {
            Secrets.Add("088546f2-aba0-49d0-9323-4b07bf926ab1", "pWN4NAwKk+SUokEvDNZ4fcX3t2ozTFPgypXKchk1ulM=");
        }

        private Dictionary<string, string> Secrets { get; } = new Dictionary<string, string>();

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.HasHMACAuthorizationHeader())
            {
                return AuthenticateResult.NoResult();
            }

            if (!Request.TryGetHMACCredentials(out var credentials, out var error))
            {
                return AuthenticateResult.Fail($"Invalid HMAC Authorization: {error}");
            }

            if (!Request.HasRequiredHeaders(Options.RequiredHeaders, out var missingHeaders))
            {
                return AuthenticateResult.Fail($"Missing one or more required headers: {missingHeaders}");
            }

            if (!Request.HasAcceptableClockDrift(Clock, Options.ClockDrift, out var timestamp))
            {
                return AuthenticateResult.Fail($"something about request being too old");
            }

            if (!Secrets.ContainsKey(credentials.Key))
            {
                return AuthenticateResult.Fail("Unrecognized access key");
            }

            var secret = Encoding.UTF8.GetBytes(Secrets[credentials.Key]);

            var signature = new StringBuilder()
                .AppendLine(Request.Method)
                .AppendLine(Request.Path)
                .AppendLine(Request.QueryString.Value)
                .AppendLine(timestamp.ToString("o"))
                .AppendLine($"{(Request.ContentLength ?? 0)}")
                .Append(await Request.GetBodyMD5());

            var digest = string.Empty;

            using (HMAC hmac = new HMACSHA256(secret))
            {
                digest = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(signature.ToString())));
            }

            if (digest == credentials.Digest)
            {
                return AuthenticateResult.Success(new AuthenticationTicket(
                    new GenericPrincipal(new GenericIdentity(credentials.Key), new[] { "ApiKeyHolder" }), new AuthenticationProperties() { IsPersistent = false, AllowRefresh = false }, "HMAC"));
            }

            return AuthenticateResult.Fail("Invalid digest");
        }
    }

    public static class HMACAuthenticationExtensions
    {
        public static async Task<string> GetBodyMD5(this HttpRequest request)
        {
            request.EnableBuffering();

            try
            {
                // Leave the body open so the next middleware can read it.
                using (var reader = new StreamReader(
                request.Body,
                encoding: Encoding.UTF8,
                detectEncodingFromByteOrderMarks: false,
                leaveOpen: true))
                {
                    var body = await reader.ReadToEndAsync();

                    using (var md5 = MD5.Create())
                    {
                        byte[] data = md5.ComputeHash(Encoding.UTF8.GetBytes(body));

                        StringBuilder builder = new StringBuilder();

                        for (int i = 0; i < data.Length; i++)
                        {
                            builder.Append(data[i].ToString("x2"));
                        }

                        return builder.ToString();
                    }
                }
            }
            finally
            {
                request.Body.Position = 0;
            }
        }

        public static bool HasAcceptableClockDrift(this HttpRequest request, ISystemClock systemClock, TimeSpan allowedClockDrift, out DateTime timestamp)
        {
            var date = request.Headers[HeaderNames.Date];

            if (!DateTime.TryParseExact(date, "o", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out timestamp))
            { 
                return false;
            }

            if (timestamp > systemClock.UtcNow.Add(allowedClockDrift) || timestamp < systemClock.UtcNow.Subtract(allowedClockDrift))
            {
                return false;
            }

            return true;
        }

        public static bool HasRequiredHeaders(this HttpRequest request, IEnumerable<string> requiredHeaders, out string missingHeaders)
        {
            missingHeaders = null;
            var missing = requiredHeaders.Where(header => string.IsNullOrEmpty(request.Headers[header]));

            if (missing.Any())
            {
                missingHeaders = string.Join(" ,", missing);
                return false;
            }

            return true;
        }

        public static bool HasHMACAuthorizationHeader(this HttpRequest request) =>
            request.Headers[HeaderNames.Authorization]
                .Any(value => value.StartsWith("HMAC", StringComparison.InvariantCultureIgnoreCase));

        public static bool TryGetHMACCredentials(this HttpRequest request, out (string Key, string Digest) credentials, out string error)
        {
            credentials = (null, null);
            error = "Unknown error";

            var headers = request.Headers[HeaderNames.Authorization].ToList();

            if (headers.Count > 1)
            {
                error = "Multiple HMAC Authorization headers provided with request";
                return false;
            }

            var header = headers[0];
            var pattern = @"^HMAC [a-zA-Z0-9-]{36}:[A-Za-z0-9+\/=]{44}$";

            if (!Regex.IsMatch(header, pattern, RegexOptions.IgnoreCase))
            {
                error = $"Invalid format; expected 'HMAC <access key:36>:<message digest:44>', received {header}";
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
        public HMACAuthenticationOptions()
        {
        }

        public TimeSpan ClockDrift { get; set; } = new TimeSpan(hours: 0, minutes: 5, seconds: 0);
        public IEnumerable<string> RequiredHeaders { get; set; }
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
