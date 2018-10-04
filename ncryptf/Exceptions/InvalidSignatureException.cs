using System;

namespace ncryptf.Exceptions
{
    /// <summary>
    /// An exception thrown when the signature associated to a v2 message is not valid
    /// </summary>
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