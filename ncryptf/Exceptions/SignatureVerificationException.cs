using System;

namespace ncryptf.Exceptions
{
    public class SignatureVerificationException : Exception
    {
        public SignatureVerificationException()
        {
        }

        public SignatureVerificationException(String message) : base(message)
        {
        }

        public SignatureVerificationException(String message, Exception inner) : base(message, inner)
        {
        }
    }
}