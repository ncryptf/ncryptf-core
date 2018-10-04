using System;

namespace ncryptf.Exceptions
{
    /// <summary>
    /// An exception thrown when decrypting a message fails
    /// </summary>
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