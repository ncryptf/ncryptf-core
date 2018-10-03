using System;
using Sodium;
using ncryptf;

namespace ncryptf.Test
{
    public class TestCase
    {
        public String HttpMethod
        {
            get; private set;
        }

        public String Uri
        {
            get; private set;
        }

        public String Payload
        {
            get; private set;
        }

        public TestCase(String httpMethod, String uri, String payload)
        {
            this.HttpMethod = httpMethod;
            this.Uri = uri;
            this.Payload = payload;
        }
    }
}