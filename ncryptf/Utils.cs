using System;
using Sodium;

namespace ncryptf
{
    /// <summary>
    /// Helper utilities
    /// </summary>
    public class Utils
    {
        /// <summary>
        /// Zeros a given byte array
        /// </summary>
        /// <param name="data">The byte[] data to zero</param>
        /// <returns>Bool</returns>
        public static bool zero(byte[] data)
        {
            // @todo: Sodium.Core should implement sodium_memzero for secure zero
            Array.Clear(data, 0, data.Length);
            for(int i = 0; i < data.Length; i++) {
                if (data[i] != 0) {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Generates a PublicKeyBox Keypair for use with encrypting and decrypting messages
        /// </summary>
        /// <returns>ncryptf.Keypair</returns>
        public static Keypair GenerateKeypair()
        {
            KeyPair kp = PublicKeyBox.GenerateKeyPair();
            return new Keypair(kp.PublicKey, kp.PrivateKey);

        }

        /// <summary>
        /// Generates a PublicKeyAuth Keypair for use with signing and verifying signature
        /// </summary>
        /// <returns>ncryptf.Keypair</returns>
        public static Keypair GenerateSigningKeypair()
        {
            KeyPair kp = PublicKeyAuth.GenerateKeyPair();
            return new Keypair(kp.PublicKey, kp.PrivateKey);
        }
    }
}