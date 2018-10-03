using System;
using Xunit;
using Sodium;
using ncryptf;

namespace ncryptf.Test
{
    public class RequestResponseTest
    {
        private byte[] clientKeyPairSecret = System.Convert.FromBase64String("bvV/vnfB43spmprI8aBK/Fd8xxSBlx7EhuxfxxTVI2o=");
        private byte[] clientKeyPairPublic = System.Convert.FromBase64String("Ojnr0KQy6GJ6x+eQa+wNwdHejZo8vY5VNyZY5NfwBjU=");
        
        private byte[] serverKeyPairSecret = System.Convert.FromBase64String("gH1+ileX1W5fMeOWue8HxdREnK04u72ybxCQgivWoZ4=");
        private byte[] serverKeyPairPublic = System.Convert.FromBase64String("YU74X2OqHujLVDH9wgEHscD5eyiLPvcugRUZG6R3BB8=");

        private byte[] signatureKeyPairSecret = System.Convert.FromBase64String("9wdUWlSW2ZQB6ImeUZ5rVqcW+mgQncN1Cr5D2YvFdvEi42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsQ==");
        private byte[] signatureKeyPairPublic = System.Convert.FromBase64String("IuNjSiv+ueMxrcU0jnDRzxMLRQM9AOJNIcJSBaKWRLE=");

        private byte[] nonce = System.Convert.FromBase64String("bulRnKt/BvwnwiCMBLvdRM5+yNFP38Ut");

        private byte[] expectedCipher = System.Convert.FromBase64String("1odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0=");
        private byte[] expectedSignature = System.Convert.FromBase64String("dcvJclMxEx7pcW/jeVm0mFHGxVksY6h0/vNkZTfVf+wftofnP+yDFdrNs5TtZ+FQ0KEOm6mm9XUMXavLaU9yDg==");

        private byte[] expectedv2Cipher = System.Convert.FromBase64String("3iWQAm7pUZyrfwb8J8IgjAS73UTOfsjRT9/FLTo569CkMuhiesfnkGvsDcHR3o2aPL2OVTcmWOTX8AY11odrjBif71zRcZidfhEzSb80rXGJGB1J3upTb+TwhpxmFjXOXjwSDw45e7p/+FW4Y0/FDuLjHfGghOG0UC7j4xmX8qIVYUdbKCB/dLn34HQ0D0NIM6N9Qj83bpS5XgK1o+luonc0WxqA3tdXTcgkd2D+cSSSotJ/s+5fqN3w5xsKc7rKb1p3MpvRzyEmdNgJCFOk8EErn0bolz9LKyPEO0A2Mnkzr19bDwsgD1DGEYlo0i9KOw06RpaZRz2J+OJ+EveIlQGDdLT8Gh+nv65TOKJqCswOly0i42NKK/654zGtxTSOcNHPEwtFAz0A4k0hwlIFopZEsXXLyXJTMRMe6XFv43lZtJhRxsVZLGOodP7zZGU31X/sH7aH5z/sgxXazbOU7WfhUNChDpuppvV1DF2ry2lPcg4SwqYwa53inoY2+eCPP4Hkp/PKhSOEMFlWV+dlQirn6GGf5RQSsQ7ti/QCvi/BRIhb3ZHiPptZJZIbYwqIpvYu");

        private String payload = "{\n" +
        "    \"foo\": \"bar\",\n" +
        "    \"test\": {\n" +
        "        \"true\": false,\n" +
        "        \"zero\": 0.0,\n" +
        "        \"a\": 1,\n" +
        "        \"b\": 3.14,\n" +
        "        \"nil\": null,\n" +
        "        \"arr\": [\n" +
        "            \"a\", \"b\", \"c\", \"d\"\n" +
        "        ]\n" +
        "    }\n" +
        "}";

        [Fact]
        public void testPublicKeyExtraction()
        {
            byte[] publicKey = Response.GetPublicKeyFromResponse(this.expectedv2Cipher);
            Assert.Equal(Sodium.Utilities.BinaryToHex(this.clientKeyPairPublic), Sodium.Utilities.BinaryToHex(publicKey));
        }

        [Fact]
        public void testVersion()
        {
            Assert.Equal(1, Response.GetVersion(this.expectedCipher));
            Assert.Equal(2, Response.GetVersion(this.expectedv2Cipher));
        }
    }
}