using System;
using Xunit;
using Sodium;
using ncryptf;

namespace ncryptf.Test
{
    public class SignatureTest : IClassFixture<TestFixture>
    {
        TestFixture fixture;

        public SignatureTest(TestFixture fixture)
        {
            this.fixture = fixture;
        }

        [Fact]
        public void Testv1Signatures()
        {
            int index = 0;
            foreach (TestCase test in this.fixture.testCases) {
                String signature = Signature.Derive(
                    test.HttpMethod,
                    test.Uri,
                    this.fixture.Salt,
                    this.fixture.Date,
                    test.Payload,
                    1
                );

                String[] lines = signature.Split("\n");
                Assert.Equal(this.fixture.v1SignatureResults[index++], lines[0]);
            }
        }

        [Fact]
        public void Testv2Signatures()
        {
            int index = 0;
            foreach (TestCase test in this.fixture.testCases) {
                String signature = Signature.Derive(
                    test.HttpMethod,
                    test.Uri,
                    this.fixture.Salt,
                    this.fixture.Date,
                    test.Payload,
                    2
                );

                String[] lines = signature.Split("\n");
                Assert.Equal(this.fixture.v2SignatureResults[index++], lines[0]);
            }
        }
    }
}