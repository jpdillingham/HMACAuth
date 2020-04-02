namespace HMACAuth
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using HMACAuth.Security;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Hosting;

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

            var (key, iv) = Utility.GenerateAESKeyAndInitializationVector();

            services.AddAuthentication("HMAC")
                .AddScheme<HMACAuthenticationOptions, HMACAuthenticationHandler>("HMAC", options => 
                {
                    options.DateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffK";
                    options.ClockDrift = new TimeSpan(hours: 24, minutes: 0, seconds: 0);
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            
            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }

    public static class Utility
    {
        public static string GenerateSecretKey()
        {
            using var cryptoProvider = new RNGCryptoServiceProvider();
            byte[] secretKeyByteArray = new byte[32]; //256 bit
            cryptoProvider.GetBytes(secretKeyByteArray);
            return Convert.ToBase64String(secretKeyByteArray);
        }

        public static (string EncrytionKey, string InitializationVector) GenerateAESKeyAndInitializationVector()
        {
            using Aes aes = Aes.Create();
            return (Convert.ToBase64String(aes.Key), Convert.ToBase64String(aes.IV));
        }

        public static string Encrypt(string plainText, string key, string iv)
        {
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Convert.FromBase64String(key);
                aesAlg.IV = Convert.FromBase64String(iv);

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using MemoryStream msEncrypt = new MemoryStream();
                using CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                }

                encrypted = msEncrypt.ToArray();
            }

            return Convert.ToBase64String(encrypted);
        }

        public static string Decrypt(string cipherText, string key, string iv)
        {
            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Convert.FromBase64String(key);
                aesAlg.IV = Convert.FromBase64String(iv);

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText));
                using CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    plaintext = srDecrypt.ReadToEnd();
                }
            }

            return plaintext;
        }
    }
}
