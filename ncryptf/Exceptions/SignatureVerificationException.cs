using System;

namespace ncryptf.Exceptions
{
    /// <summary>
    /// An exception thrown when the signature associate with a message could not be verified
    /// </summary>
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