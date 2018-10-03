using System;
using Xunit;
using Sodium;
using ncryptf;

namespace ncryptf.Test
{
    public class UtilsTest
    {
        [Fact]
        public void ZeroTest()
        {
            byte[] data = new byte[32];
            Random random = new Random();
            random.NextBytes(data);

            bool result = Utils.zero(data);
            Assert.True(result);
            for (int i = 0; i < data.Length; i++) {
                Assert.Equal(0, data[i]);
            }
        }

        [Fact]
        public void KeyPairGenerationTest()
        {
            Keypair kp = Utils.GenerateKeypair();
            Assert.Equal(32, kp.PublicKey.Length);
            Assert.Equal(32, kp.SecretKey.Length);
        }

        [Fact]
        public void SigningKeypairGenerationTest()
        {
            Keypair kp = Utils.GenerateSigningKeypair();
            Assert.Equal(32, kp.PublicKey.Length);
            Assert.Equal(64, kp.SecretKey.Length);
        }
    }
}
