namespace HMACAuth.Security.Cryptography
{
    public class Constants
    {
        public static readonly int BlockSizeInBits = 128;
        public static readonly int KeySizeInBits = 256;
        public static readonly int BlockSizeInBytes = BlockSizeInBits / 8;
        public static readonly int KeySizeInBytes = KeySizeInBits / 8;
        public static readonly int SaltSizeInBits = 128;
        public static readonly int SaltSizeInBytes = SaltSizeInBits / 8;
    }
}
