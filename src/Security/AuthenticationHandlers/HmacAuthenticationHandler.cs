namespace HMACAuth.Security
{
    using HMACAuth.Security.Cryptography;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Microsoft.Net.Http.Headers;
    using NetTools;
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

    public class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationOptions>
    {
        private const string EncryptionKeyBase64 = "8QvabgTFjjxbO6pcPvMxzo8lQ8gCXGwSHUJ5GbJ4TggXkRJD7Np4NzHZpn8UA0EZ";

        public HmacAuthenticationHandler(IOptionsMonitor<HmacAuthenticationOptions> optionsMonitor, ILoggerFactory logger, UrlEncoder urlEncoder, ISystemClock systemClock)
            : base(optionsMonitor, logger, urlEncoder, systemClock)
        {
            var localHostOnly = "127.0.0.1/32,::1/128";
            var wideOpen = "0.0.0.0/0,::/0";

            ApiKeys.Add("088546f2-aba0-49d0-9323-4b07bf926ab1", new ApiKey()
            {
                AccessKey = "088546f2-aba0-49d0-9323-4b07bf926ab1",
                EncryptedSecretKey = Encryption.Encrypt("pWN4NAwKk+SUokEvDNZ4fcX3t2ozTFPgypXKchk1ulM=", EncryptionKey.Value),
                CIDRs = localHostOnly
            });
        }

        private Lazy<EncryptionKey> EncryptionKey { get; } = new Lazy<EncryptionKey>(() => Cryptography.EncryptionKey.FromBase64String(EncryptionKeyBase64));
        private Dictionary<string, ApiKey> ApiKeys { get; } = new Dictionary<string, ApiKey>();
        private IEnumerable<string> RequiredSignatureHeaders { get; } = new[]
        {
            HeaderNames.Date,
            HeaderNames.RequestId,
            HeaderNames.Authorization,
            HeaderNames.ContentLength,
            HeaderNames.ContentMD5
        };

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {            
            if (!HasHMACAuthorizationHeader(Request))
            {
                return AuthenticateResult.NoResult();
            }

            static AuthenticateResult Fail(string message)
            {
                return AuthenticateResult.Fail(message);
            }

            if (!TryGetHMACCredentials(Request, out var credentials, out var error))
            {
                return Fail($"Invalid HMAC Authorization: {error}");
            }

            if (!HasRequiredSignatureHeaders(Request, RequiredSignatureHeaders, out var missingHeaders))
            {
                return Fail($"Missing one or more required headers: {missingHeaders}");
            }

            if (!HasAcceptableClockDrift(Request, Clock, Options.ClockDrift, Options.DateTimeFormat, out var timestamp, out error))
            {
                return Fail($"Invalid Date value: {error}");
            }

            if (!ApiKeys.ContainsKey(credentials.Key))
            {
                return Fail($"Unrecognized access key: {credentials.Key}");
            }

            var apiKey = ApiKeys[credentials.Key];

            if (!RemoteIPIsInRange(Request, apiKey.CIDRs, out var remoteIP, out _))
            {
                return Fail($"Origin IP {remoteIP} not authorized");
            }

            var parts = new string[]
            {
                Request.Method,
                Request.Path,
                Request.QueryString.Value,
                Request.Headers[HeaderNames.RequestId],
                timestamp.ToString(Options.DateTimeFormat),
                $"{Request.ContentLength ?? 0}",
                await GetBodyMd5(Request)
            };

            var signature = string.Join(':', parts);

            var key = Convert.FromBase64String(Encryption.Decrypt(apiKey.EncryptedSecretKey, EncryptionKey.Value));

            var digest = string.Empty;

            using (HMAC hmac = new HMACSHA256(key))
            {
                digest = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(signature)));
            }

            if (digest == credentials.Digest)
            {
                Logger.LogInformation($"Request from {Request.HttpContext.Connection.RemoteIpAddress} authenticated successfully.");
                return AuthenticateResult.Success(new AuthenticationTicket(
                    new GenericPrincipal(new GenericIdentity(credentials.Key), new[] { "ApiKeyHolder" }), new AuthenticationProperties() { IsPersistent = false, AllowRefresh = false }, "HMAC"));
            }

            return Fail($"Invalid digest; computed {digest}, received {credentials.Digest}");
        }

        private static async Task<string> GetBodyMd5(HttpRequest request)
        {
            request.EnableBuffering();

            try
            {
                using var reader = new StreamReader(
                    request.Body,
                    encoding: Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: false,
                    leaveOpen: true);

                var body = await reader.ReadToEndAsync();
                return body.ComputeMd5Hash();
            }
            finally
            {
                request.Body.Position = 0;
            }
        }

        public static bool RemoteIPIsInRange(HttpRequest request, string cidrs, out IPAddress ip, out IPAddressRange matchedRange)
        {
            IEnumerable<IPAddressRange> ranges;

            try
            {
                ranges = cidrs.Split(',').Select(cidr => IPAddressRange.Parse(cidr));
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Failed to parse CIDRs from given value", nameof(cidrs), ex);
            }

            IPAddress rip;

            // when running behind a load balancer, the original client IP will be stored in the X-Forwarded-For header
            if (request.Headers.ContainsKey("X-Forwarded-For"))
            {
                rip = IPAddress.Parse(request.Headers["X-Forwarded-For"]);
            }
            else
            {
                rip = request.HttpContext.Connection.RemoteIpAddress;
            }

            ip = rip;

            foreach (var range in ranges)
            {
                if (range.Contains(rip))
                {
                    ip = rip;
                    matchedRange = range;
                    return true;
                }
            }

            matchedRange = null;
            return false;
        }

        public static bool HasAcceptableClockDrift(HttpRequest request, ISystemClock systemClock, TimeSpan allowedClockDrift, string dateTimeFormat, out DateTime timestamp, out string error)
        {
            var date = request.Headers[HeaderNames.Date];
            error = null;

            if (!DateTime.TryParseExact(date, dateTimeFormat, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out timestamp))
            {
                error = $"Invalid format; expected {DateTime.UnixEpoch.ToString(dateTimeFormat)}, received {date}";
                return false;
            }

            if (timestamp > systemClock.UtcNow.Add(allowedClockDrift) || timestamp < systemClock.UtcNow.Subtract(allowedClockDrift))
            {
                error = $"Clock drift exceeds allowance; server time {systemClock.UtcNow.ToString(dateTimeFormat)}, request time {timestamp.ToString(dateTimeFormat)}";
                return false;
            }

            return true;
        }

        public static bool HasRequiredSignatureHeaders(HttpRequest request, IEnumerable<string> requiredHeaders, out string missingHeaders)
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

        public static bool HasHMACAuthorizationHeader(HttpRequest request) =>
            request.Headers[HeaderNames.Authorization]
                .Any(value => value.StartsWith("HMAC", StringComparison.InvariantCultureIgnoreCase));

        public static bool TryGetHMACCredentials(HttpRequest request, out (string Key, string Digest) credentials, out string error)
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
}
