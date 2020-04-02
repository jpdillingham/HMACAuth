namespace HMACAuth.Security
{
    using System;

    public class ApiKey
    {
        public string AccessKey { get; set; }
        public string EncryptedSecretKey { get; set; }
        public string CIDRs { get; set; } = "0.0.0.0/0";
        public DateTime CreationTime { get; set; } = DateTime.UtcNow;
        public DateTime LastUsedTime { get; set; } = DateTime.UtcNow;
        public DateTime? RevokedTime { get; set; } = null;
    }
}
