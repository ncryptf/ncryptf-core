using System;

namespace ncryptf.Exceptions
{
    /// <summary>
    /// An exception thrown when the checksum associate with a encrypted v2 message does not match the checksum calculated from the message
    /// </summary>
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