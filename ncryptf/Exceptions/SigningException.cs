using System;

namespace ncryptf.Exceptions
{
    /// <summary>
    /// An exception thrown when an error occurs during the signing of a message.
    /// </summary>
    public class SigningException : Exception
    {
        public SigningException()
        {
        }

        public SigningException(String message) : base(message)
        {
        }

        public SigningException(String message, Exception inner) : base(message, inner)
        {
        }
    }
}