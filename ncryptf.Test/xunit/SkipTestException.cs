using System;

namespace ncryptf.Test.xunit
{
    public class SkipTestException : Exception
    {
        public SkipTestException(string reason)
            : base(reason) { }
    }
}