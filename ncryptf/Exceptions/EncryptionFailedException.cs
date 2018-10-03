using System;

namespace ncryptf.Exceptions
{
    public class EncryptionFailedException : Exception
    {
        public EncryptionFailedException()
        {
        }

        public EncryptionFailedException(String message) : base(message)
        {
        }

        public EncryptionFailedException(String message, Exception inner) : base(message, inner)
        {
        }
    }
}