using System;
using Xunit;
using Sodium;
using ncryptf;
using Newtonsoft.Json.Linq;

namespace ncryptf.Test
{
    public class AuthorizationTest : IClassFixture<TestFixture>
    {
        TestFixture fixture;

        public AuthorizationTest(TestFixture fixture)
        {
            this.fixture = fixture;
        }

        [Fact]
        public void Testv1Signatures()
        {
            int index = 0;
            foreach (TestCase test in this.fixture.testCases) {
                Authorization auth = new Authorization(
                    test.HttpMethod,
                    test.Uri,
                    this.fixture.Token,
                    this.fixture.Date,
                    test.Payload,
                    1,
                    this.fixture.Salt
                );

                String header = this.fixture.v1HMACHeaders[index++];
                Assert.Equal(header, auth.GetHeader());
                String[] r = header.Split(",");
                byte[] hmac = System.Convert.FromBase64String(r[1]);
                Assert.False(auth.Verify(hmac, auth, 90));
            }
        }

        [Fact]
        public void Testv2Signatures()
        {
            int index = 0;
            foreach (TestCase test in this.fixture.testCases) {
                Authorization auth = new Authorization(
                    test.HttpMethod,
                    test.Uri,
                    this.fixture.Token,
                    this.fixture.Date,
                    test.Payload,
                    2,
                    this.fixture.Salt
                );

                String header = this.fixture.v2HMACHeaders[index++];
                Assert.Equal(header, auth.GetHeader());
                String h = header.Replace("HMAC ", "");
                JObject json = JObject.Parse(
                    System.Text.Encoding.UTF8.GetString(
                        System.Convert.FromBase64String(
                            header.Replace("HMAC ", "")
                        )
                    )
                );

                byte[] hmac = System.Text.Encoding.UTF8.GetBytes(json.GetValue("hmac").ToString());
                Assert.False(auth.Verify(hmac, auth, 90));
            }
        }

        [Fact]
        public void TestVerify()
        {
            foreach (TestCase test in this.fixture.testCases) {
                Authorization auth = new Authorization(
                    test.HttpMethod,
                    test.Uri,
                    this.fixture.Token,
                    DateTime.UtcNow,
                    test.Payload,
                    1,
                    this.fixture.Salt
                );

                Assert.True(auth.Verify(auth.GetHMAC(), auth, 90));

                Authorization auth2 = new Authorization(
                    test.HttpMethod,
                    test.Uri,
                    this.fixture.Token,
                    DateTime.UtcNow,
                    test.Payload,
                    2,
                    this.fixture.Salt
                );

                Assert.True(auth2.Verify(auth2.GetHMAC(), auth2, 90));
            }
        }
    }
}