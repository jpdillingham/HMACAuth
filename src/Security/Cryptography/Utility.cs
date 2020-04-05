namespace HMACAuth.Security.Cryptography
{
    using System.Security.Cryptography;

    public static class Utility
    {
        public static byte[] GenerateRandomByteArray(int lengthInBytes)
        {
            using var rng = new RNGCryptoServiceProvider();
            var bytes = new byte[lengthInBytes];
            rng.GetBytes(bytes);
            return bytes;
        }
    }
}
