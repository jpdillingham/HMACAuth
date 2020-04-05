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
            var key = new Cryptography.AesEncryptionKey();

            var cipherText = Cryptography.Encrypt(plainText, key);
            var uncipheredText = Cryptography.Decrypt(cipherText, key);

            Assert.Equal(plainText, uncipheredText);
        }
    }
}
