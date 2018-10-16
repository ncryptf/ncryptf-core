using System;
using Sodium;

using System.Security.Cryptography;

namespace ncryptf
{
    /// <summary>
    /// Generates a signature for use with ncryptf.Authentication
    /// </summary>
    public class Signature
    {
        /// <summary>
        /// Derives a versioned signature string
        /// </summary>
        /// <param name="httpMethod">The HTTP method</param>
        /// <param name="uri">The URI with query parameters</param>
        /// <param name="salt">32 byte salt</param>
        /// <param name="date">Date</param>
        /// <param name="payload">String representation of payload</param>
        /// <param name="version">Signature string version to generate. Defaults to 2</param>
        /// <returns>Versioned signature string</returns>
        public static String Derive(
            String httpMethod,
            String uri,
            byte[] salt,
            DateTime date,
            String payload,
            int version = 2
        ) {
            if (salt.Length != 32) {
                throw new ArgumentException("Salt should be 32 bytes in length.");
            }

            httpMethod = httpMethod.ToUpper();
            String hash = GetSignatureHash(payload, salt, version);
            String b64Salt = System.Convert.ToBase64String(salt);
            String timestamp = date.ToString("r").Replace(" GMT", " +0000");

            return hash + "\n" + 
               httpMethod + "+" + uri + "\n" +
               timestamp + "\n" +
               b64Salt;
        }

        /// <summary>
        /// Generates a versioned signature hash as a string
        /// </summary>
        /// <param name="data">String data to hash</param>
        /// <param name="salt">24 byte salt</param>
        /// <param name="version">Which version of the signature string to generate. Defaults to 2</param>
        /// <returns>Versioned signature hash</returns>
        private static String GetSignatureHash(String data, byte[] salt, int version = 2)
        {
            byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
            if (version == 2) {
                byte[] hash = GenericHash.Hash(dataBytes, salt, 64);
                return System.Convert.ToBase64String(hash);
            }

            using (SHA256 sha256 = SHA256.Create()) {
                byte[] hash = sha256.ComputeHash(dataBytes);
                return Sodium.Utilities.BinaryToHex(hash).ToLower();
            }
        }
    }
}