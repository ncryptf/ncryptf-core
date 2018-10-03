using System;

namespace ncryptf.Exceptions
{
    public class InvalidChecksumException : Exception
    {
        public InvalidChecksumException()
        {
        }

        public InvalidChecksumException(String message) : base(message)
        {
        }

        public InvalidChecksumException(String message, Exception inner) : base(message, inner)
        {
        }
    }
}