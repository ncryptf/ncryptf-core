using System;

namespace ncryptf.Exceptions
{
    /// <summary>
    /// An exception thrown when encrypting a message fails
    /// </summary>
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