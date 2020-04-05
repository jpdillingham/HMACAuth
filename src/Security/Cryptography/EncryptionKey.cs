
namespace HMACAuth.Security.Cryptography
{
    using System;
    using System.Security.Cryptography;

    public class EncryptionKey
    {
        public EncryptionKey()
            : this(GenerateRandomKey(), GenerateRandomIV())
        {
        }

        public EncryptionKey(byte[] key, byte[] iv)
        {
            if (key.Length != Constants.KeySizeInBytes)
            {
                throw new ArgumentOutOfRangeException(nameof(key), actualValue: key.Length, $"Key must be {Constants.KeySizeInBytes} bytes");
            }

            if (iv.Length != Constants.BlockSizeInBits / 8)
            {
                throw new ArgumentOutOfRangeException(nameof(iv), actualValue: iv.Length, $"Initialization vector must be {Constants.BlockSizeInBytes} bytes");
            }

            Key = key;
            IV = iv;
        }

        public static byte[] GenerateRandomKey()
        {
            using var aes = Aes.Create();
            aes.KeySize = Constants.KeySizeInBits;
            aes.BlockSize = Constants.BlockSizeInBits;

            aes.GenerateKey();

            return aes.Key;
        }

        public static byte[] GenerateRandomIV()
        {
            using var aes = Aes.Create();
            aes.KeySize = Constants.KeySizeInBits;
            aes.BlockSize = Constants.BlockSizeInBits;

            aes.GenerateIV();

            return aes.IV;
        }

        public byte[] Key { get; }
        public byte[] IV { get; }

        public byte[] ToByteArray()
        {
            var bytes = new byte[Constants.KeySizeInBytes + Constants.BlockSizeInBytes];
            Key.CopyTo(bytes, 0);
            IV.CopyTo(bytes, Constants.KeySizeInBytes);

            return bytes;
        }

        public override string ToString() => ToBase64String();
        public string ToBase64String() => Convert.ToBase64String(ToByteArray());

        public static EncryptionKey FromByteArray(byte[] bytes)
        {
            if (bytes.Length != Constants.KeySizeInBytes + Constants.BlockSizeInBytes)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes), actualValue: bytes.Length, $"Byte array must be {Constants.KeySizeInBytes + Constants.BlockSizeInBytes} bytes");
            }

            var mem = new Memory<byte>(bytes);
            var key = mem.Slice(0, Constants.KeySizeInBytes);
            var iv = mem.Slice(Constants.KeySizeInBytes, Constants.BlockSizeInBytes);

            return new EncryptionKey(key.ToArray(), iv.ToArray());
        }

        public static EncryptionKey FromBase64String(string base64Key)
        {
            return FromByteArray(Convert.FromBase64String(base64Key));
        }
    }
}
