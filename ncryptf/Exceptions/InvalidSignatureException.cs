using System;

namespace ncryptf.Exceptions
{
    public class InvalidSignatureException : Exception
    {
        public InvalidSignatureException()
        {
        }

        public InvalidSignatureException(String message) : base(message)
        {
        }

        public InvalidSignatureException(String message, Exception inner) : base(message, inner)
        {
        }
    }
}