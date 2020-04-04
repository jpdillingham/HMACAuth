namespace HMACAuth.Tests.Security
{
    using AutoFixture.Xunit2;
    using HMACAuth.Security;
    using Xunit;

    public class EncryptionTests
    {
        [Theory, AutoData]
        public void EncryptionRoundTripMatches(string plainText)
        {
            var key = new Encryption.AesEncryptionKey();

            var cipherText = Encryption.Encrypt(plainText, key);
            var uncipheredText = Encryption.Decrypt(cipherText, key);

            Assert.Equal(plainText, uncipheredText);
        }
    }
}
