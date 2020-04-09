namespace HMACAuth.Security.Cryptography
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

    public class Encryption
    {
        public static string Encrypt(string plainText, EncryptionKey key)
        {
            using var aes = Aes.Create();
            aes.KeySize = Constants.KeySizeInBits;
            aes.BlockSize = Constants.BlockSizeInBits;
            aes.Mode = CipherMode.CBC;

            using var encryptor = aes.CreateEncryptor(key.Key, key.IV);
            using var memoryStream = new MemoryStream();
            using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
            using var streamWriter = new StreamWriter(cryptoStream);
            
            streamWriter.Write(plainText);
            streamWriter.Close();
            
            return Convert.ToBase64String(memoryStream.ToArray());
        }

        public static string Decrypt(string cipherText, EncryptionKey key)
        {
            using var aes = Aes.Create();
            aes.KeySize = Constants.KeySizeInBits;
            aes.BlockSize = Constants.BlockSizeInBits;
            aes.Mode = CipherMode.CBC;

            using var decryptor = aes.CreateDecryptor(key.Key, key.IV);
            using var memoryStream = new MemoryStream(Convert.FromBase64String(cipherText));
            using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            using var streamReader = new StreamReader(cryptoStream);

            return streamReader.ReadToEnd();
        }
    }
}
