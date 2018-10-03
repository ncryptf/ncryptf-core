using System;

namespace ncryptf.Exceptions
{
    public class DecryptionFailedException : Exception
    {
        public DecryptionFailedException()
        {
        }

        public DecryptionFailedException(String message) : base(message)
        {
        }

        public DecryptionFailedException(String message, Exception inner) : base(message, inner)
        {
        }
    }
}