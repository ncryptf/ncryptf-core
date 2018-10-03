using System;
using System.Security.Cryptography;
using Sodium.Exceptions;

namespace ncryptf
{
    /// <summary>A public / private key pair.</summary>
    public class Keypair
    {
        private readonly byte[] _publicKey;
        
        private readonly byte[] _secretKey;

        /// <summary>
        /// Constructs a new keypair object
        /// </summary>
        /// <param name="publicKey">Public key bytes</param>
        /// <param name="secretKey">Secret key bytes</param>
        public Keypair(byte[] publicKey, byte[] secretKey)
        {
            //verify that the private key length is a multiple of 16
            if (secretKey.Length % 16 != 0)
                throw new KeyOutOfRangeException("Private Key length must be a multiple of 16 bytes.");

            this._publicKey = publicKey;

            this._secretKey = secretKey;
        }

        /// <summary>
        /// Public key bytes
        /// </summary>
        /// <value>Public key bytes</value>
        public byte[] PublicKey
        {
            get { return this._publicKey; }
        }

        /// <summary>
        /// Secret key bytes
        /// </summary>
        /// <value>Secret key bytes</value>
        public byte[] SecretKey
        {
            get
            {
                var tmp = new byte[this._secretKey.Length];
                Array.Copy(this._secretKey, tmp, tmp.Length);

                return tmp;
            }
        }
    }
}
