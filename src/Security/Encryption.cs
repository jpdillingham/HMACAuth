namespace HMACAuth.Security
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

    public class Encryption
    {
        public static readonly int BlockSizeInBits = 128;
        public static readonly int KeySizeInBits = 256;
        public static readonly int BlockSizeInBytes = BlockSizeInBits / 8;
        public static readonly int KeySizeInBytes = KeySizeInBits / 8;
        public static readonly int SaltSizeInBits = 128;
        public static readonly int SaltSizeInBytes = SaltSizeInBits / 8;

        public static string Encrypt(string plainText, AesEncryptionKey key)
        {
            using var aes = Aes.Create();
            aes.KeySize = KeySizeInBits;
            aes.BlockSize = BlockSizeInBits;

            using var encryptor = aes.CreateEncryptor(key.Key, key.IV);
            using var memoryStream = new MemoryStream();
            using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
            using var streamWriter = new StreamWriter(cryptoStream);
            
            streamWriter.Write(plainText);
            streamWriter.Close();
            
            return Convert.ToBase64String(memoryStream.ToArray());
        }

        public static string Decrypt(string cipherText, AesEncryptionKey key)
        {
            using var aes = Aes.Create();
            aes.KeySize = KeySizeInBits;
            aes.BlockSize = BlockSizeInBits;

            using var decryptor = aes.CreateDecryptor(key.Key, key.IV);
            using var memoryStream = new MemoryStream(Convert.FromBase64String(cipherText));
            using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            using var streamReader = new StreamReader(cryptoStream);

            return streamReader.ReadToEnd();
        }

        public static byte[] GenerateRandomByteArray(int lengthInBytes)
        {
            using var rng = new RNGCryptoServiceProvider();
            var bytes = new byte[lengthInBytes];
            rng.GetBytes(bytes);
            return bytes;
        }

        public class AesEncryptionKey
        {
            public AesEncryptionKey()
                : this(GenerateRandomKey(), GenerateRandomIV())
            {
            }

            public AesEncryptionKey(byte[] key, byte[] iv)
            {
                if (key.Length != KeySizeInBytes)
                {
                    throw new ArgumentOutOfRangeException(nameof(key), actualValue: key.Length, $"Key must be {KeySizeInBytes} bytes");
                }

                if (iv.Length != BlockSizeInBits / 8)
                {
                    throw new ArgumentOutOfRangeException(nameof(iv), actualValue: iv.Length, $"Initialization vector must be {BlockSizeInBytes} bytes");
                }

                Key = key;
                IV = iv;
            }

            public static byte[] GenerateRandomKey()
            {
                using var aes = Aes.Create();
                aes.KeySize = KeySizeInBits;
                aes.BlockSize = BlockSizeInBits;

                aes.GenerateKey();

                return aes.Key;
            }

            public static byte[] GenerateRandomIV()
            {
                using var aes = Aes.Create();
                aes.KeySize = KeySizeInBits;
                aes.BlockSize = BlockSizeInBits;

                aes.GenerateIV();

                return aes.IV;
            }

            public byte[] Key { get; }
            public byte[] IV { get; }

            public byte[] ToByteArray()
            {
                var bytes = new byte[KeySizeInBytes + BlockSizeInBytes];
                Key.CopyTo(bytes, 0);
                IV.CopyTo(bytes, KeySizeInBytes);

                return bytes;
            }

            public override string ToString() => ToBase64String();
            public string ToBase64String() => Convert.ToBase64String(ToByteArray());

            public static AesEncryptionKey FromByteArray(byte[] bytes)
            {
                if (bytes.Length != KeySizeInBytes + BlockSizeInBytes)
                {
                    throw new ArgumentOutOfRangeException(nameof(bytes), actualValue: bytes.Length, $"Byte array must be {KeySizeInBytes + BlockSizeInBytes} bytes");
                }

                var mem = new Memory<byte>(bytes);
                var key = mem.Slice(0, KeySizeInBytes);
                var iv = mem.Slice(KeySizeInBytes, BlockSizeInBytes);

                return new AesEncryptionKey(key.ToArray(), iv.ToArray());
            }

            public static AesEncryptionKey FromBase64String(string base64Key)
            {
                return FromByteArray(Convert.FromBase64String(base64Key));
            }
        }
    }
}
