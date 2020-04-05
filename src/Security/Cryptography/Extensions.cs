namespace HMACAuth.Security.Cryptography
{
    using System.Security.Cryptography;
    using System.Text;

    public static class Extensions
    {
        public static string ComputeMd5Hash(this string text)
        {
            using var md5 = MD5.Create();
            byte[] data = md5.ComputeHash(Encoding.UTF8.GetBytes(text));

            StringBuilder builder = new StringBuilder();

            for (int i = 0; i < data.Length; i++)
            {
                builder.Append(data[i].ToString("x2"));
            }

            return builder.ToString();
        }
    }
}
