namespace HMACAuth
{
    using System;
    using System.IO;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;
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
            var m = Aes.Create();
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

    public class Encryption
    {
        public static readonly int BlockSizeInBits = 128;
        public static readonly int KeySizeInBits = 256;

        public static readonly int SaltSizeInBits = 128;
        public static readonly int KeyDerivationIterations = 10000;

        public static string Encrypt(string plainText, AESEncryptionKey key)
        {
            using (var aesManaged = new AesManaged() { KeySize = KeySizeInBits, BlockSize = BlockSizeInBits })
            {
                // Retrieve the Salt, Key and IV
                byte[] saltBytes = AESEncryptionKey.GenerateRandomSalt();

                // Create an encryptor to perform the stream transform.
                // Create the streams used for encryption.
                using (var encryptor = aesManaged.CreateEncryptor(key.Key, key.IV))
                using (var memoryStream = new MemoryStream())
                {

                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    using (var streamWriter = new StreamWriter(cryptoStream))
                    {
                        // Send the data through the StreamWriter, through the CryptoStream, to the underlying MemoryStream
                        streamWriter.Write(plainText);
                    }

                    // Return the encrypted bytes from the memory stream in Base64 form.
                    var cipherTextBytes = memoryStream.ToArray();

                    // Resize saltBytes and append IV
                    Array.Resize(ref saltBytes, saltBytes.Length + key.IV.Length);
                    Array.Copy(key.IV, 0, saltBytes, SaltSizeInBits / 8, key.IV.Length);

                    // Resize saltBytes with IV and append cipherText
                    Array.Resize(ref saltBytes, saltBytes.Length + cipherTextBytes.Length);
                    Array.Copy(cipherTextBytes, 0, saltBytes, (SaltSizeInBits / 8) + key.IV.Length, cipherTextBytes.Length);

                    return Convert.ToBase64String(saltBytes);
                }
            }
        }

        public class AESEncryptionKey
        {
            public AESEncryptionKey()
                : this(GenerateRandomKey(), GenerateRandomIV())
            {
            }

            public AESEncryptionKey(string password)
                : this(GenerateKeyFromPassword(password), GenerateRandomIV())
            {
            }

            private AESEncryptionKey((byte[] Key, byte[] Salt) passwordGeneratedKey, byte[] iv)
                : this(passwordGeneratedKey.Key, iv, passwordGeneratedKey.Salt)
            {
            }

            public AESEncryptionKey(byte[] key, byte[] iv, byte[] salt = null)
            {
                if (key.Length != KeySizeInBits / 8)
                {
                    throw new ArgumentOutOfRangeException(nameof(key), actualValue: key.Length * 8, $"Key must be {KeySizeInBits} bits");
                }

                if (iv.Length != BlockSizeInBits / 8)
                {
                    throw new ArgumentOutOfRangeException(nameof(iv), actualValue: iv.Length * 8, $"Initialization vector must be {BlockSizeInBits} bits");
                }

                if (salt != null && salt.Length != SaltSizeInBits / 8)
                {
                    throw new ArgumentOutOfRangeException(nameof(iv), actualValue: iv.Length * 8, $"Salt must be {SaltSizeInBits} bits");
                }

                Key = key;
                IV = iv;
                Salt = salt ?? GenerateRandomSalt();
            }

            public byte[] GetBytes()
            {
                var bytes = new byte[BlockSizeInBits / 8 + KeySizeInBits / 8];
                IV.CopyTo(bytes, 0);
                Key.CopyTo(bytes, BlockSizeInBits / 8);

                return bytes;
            }

            public static (byte[] Key, byte[] Salt) GenerateKeyFromPassword(string password)
            {
                var passwordBytes = Encoding.UTF8.GetBytes(password);
                var saltBytes = GenerateRandomSalt();

                using var fn = new Rfc2898DeriveBytes(passwordBytes, saltBytes, KeyDerivationIterations);
                return (fn.GetBytes(KeySizeInBits / 8), saltBytes);
            }

            public static byte[] GenerateRandomKey() => GenerateRandomByteArray(KeySizeInBits / 8);

            public static byte[] GenerateRandomSalt() => GenerateRandomByteArray(SaltSizeInBits / 8);

            public static byte[] GenerateRandomIV()
            {
                using var aes = Aes.Create();
                aes.KeySize = KeySizeInBits;
                aes.BlockSize = BlockSizeInBits;

                aes.GenerateIV();

                return aes.IV;
            }

            private static byte[] GenerateRandomByteArray(int lengthInBytes)
            {
                using var rng = new RNGCryptoServiceProvider();
                var bytes = new byte[lengthInBytes];
                rng.GetBytes(bytes);
                return bytes;
            }

            public byte[] Key { get; private set; }
            public byte[] IV { get; private set; }
            public byte[] Salt { get; private set; }
            public byte[] Bytes => GetBytes();

            public override string ToString()
            {
                return Convert.ToBase64String(Bytes);
            }
        }

        /// <summary>
        /// Encrypts the plainText input using the given Key.
        /// A 128 bit random salt will be generated and prepended to the ciphertext before it is base64 encoded.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="key">The plain text encryption key.</param>
        /// <returns>The salt and the ciphertext, Base64 encoded for convenience.</returns>
        public static string Encrypt(string plainText, string key)
        {
            //User Error Checks
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key");
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException("plainText");

            // Derive a new Salt and IV from the Key, using a 128 bit salt and 10,000 iterations
            using (var keyDerivationFunction = new Rfc2898DeriveBytes(key, SaltBitSize / 8, Iterations))
            using (var aesManaged = new AesManaged() { KeySize = KeyBitSize, BlockSize = BlockBitSize })
            {
                // Generate random IV
                aesManaged.GenerateIV();

                // Retrieve the Salt, Key and IV
                byte[] saltBytes = keyDerivationFunction.Salt;
                byte[] keyBytes = keyDerivationFunction.GetBytes(KeyBitSize / 8);
                byte[] ivBytes = aesManaged.IV;

                // Create an encryptor to perform the stream transform.
                // Create the streams used for encryption.
                using (var encryptor = aesManaged.CreateEncryptor(keyBytes, ivBytes))
                using (var memoryStream = new MemoryStream())
                {

                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    using (var streamWriter = new StreamWriter(cryptoStream))
                    {
                        // Send the data through the StreamWriter, through the CryptoStream, to the underlying MemoryStream
                        streamWriter.Write(plainText);
                    }

                    // Return the encrypted bytes from the memory stream in Base64 form.
                    var cipherTextBytes = memoryStream.ToArray();

                    // Resize saltBytes and append IV
                    Array.Resize(ref saltBytes, saltBytes.Length + ivBytes.Length);
                    Array.Copy(ivBytes, 0, saltBytes, SaltBitSize / 8, ivBytes.Length);

                    // Resize saltBytes with IV and append cipherText
                    Array.Resize(ref saltBytes, saltBytes.Length + cipherTextBytes.Length);
                    Array.Copy(cipherTextBytes, 0, saltBytes, (SaltBitSize / 8) + ivBytes.Length, cipherTextBytes.Length);

                    return Convert.ToBase64String(saltBytes);
                }
            }
        }


        /// <summary>
        /// Decrypts the ciphertext using the Key.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="key">The plain text encryption key.</param>
        /// <returns>The decrypted text.</returns>
        public static string Decrypt(string ciphertext, string key)
        {
            if (string.IsNullOrEmpty(ciphertext))
                throw new ArgumentNullException("cipherText");
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key");

            // Prepare the Salt and IV arrays
            byte[] saltBytes = new byte[SaltBitSize / 8];
            byte[] ivBytes = new byte[BlockBitSize / 8];

            // Read all the bytes from the cipher text
            byte[] allTheBytes = Convert.FromBase64String(ciphertext);

            // Extract the Salt, IV from our ciphertext
            Array.Copy(allTheBytes, 0, saltBytes, 0, saltBytes.Length);
            Array.Copy(allTheBytes, saltBytes.Length, ivBytes, 0, ivBytes.Length);

            // Extract the Ciphered bytes
            byte[] ciphertextBytes = new byte[allTheBytes.Length - saltBytes.Length - ivBytes.Length];
            Array.Copy(allTheBytes, saltBytes.Length + ivBytes.Length, ciphertextBytes, 0, ciphertextBytes.Length);

            using (var keyDerivationFunction = new Rfc2898DeriveBytes(key, saltBytes, Iterations))
            {
                // Get the Key bytes
                var keyBytes = keyDerivationFunction.GetBytes(KeyBitSize / 8);

                // Create a decrytor to perform the stream transform.
                // Create the streams used for decryption.
                // The default Cipher Mode is CBC and the Padding is PKCS7 which are both good
                using (var aesManaged = new AesManaged() { KeySize = KeyBitSize, BlockSize = BlockBitSize })
                using (var decryptor = aesManaged.CreateDecryptor(keyBytes, ivBytes))
                using (var memoryStream = new MemoryStream(ciphertextBytes))
                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                using (var streamReader = new StreamReader(cryptoStream))
                {
                    // Return the decrypted bytes from the decrypting stream.
                    return streamReader.ReadToEnd();
                }
            }
        }

        /// <summary>
        /// A simple method to hash a string using SHA512 hashing algorithm.
        /// </summary>
        /// <param name="inputString">The string to be hashed.</param>
        /// <returns>The hashed text.</returns>
        public static string HashString(string inputString)
        {
            // Create the object used for hashing
            using (var hasher = SHA512Managed.Create())
            {
                // Get the bytes of the input string and hash them
                var inputBytes = System.Text.Encoding.UTF8.GetBytes(inputString);
                var hashedBytes = hasher.ComputeHash(inputBytes);

                return Convert.ToBase64String(hashedBytes);
            }
        }

    }
}
