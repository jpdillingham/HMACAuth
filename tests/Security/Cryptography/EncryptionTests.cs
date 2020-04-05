namespace HMACAuth.Tests.Security
{
    using AutoFixture.Xunit2;
    using HMACAuth.Security.Cryptography;
    using Xunit;

    public class EncryptionTests
    {
        [Theory, AutoData]
        public void EncryptionRoundTripMatches(string plainText)
        {
            var key = new EncryptionKey();

            var cipherText = Encryption.Encrypt(plainText, key);
            var uncipheredText = Encryption.Decrypt(cipherText, key);

            Assert.Equal(plainText, uncipheredText);
        }
    }
}
