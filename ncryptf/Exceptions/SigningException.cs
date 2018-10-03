using System;

namespace ncryptf.Exceptions
{
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