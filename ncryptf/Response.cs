using System;
using Sodium;
using ncryptf.Exceptions;

namespace ncryptf
{
    public class Response
    {
        /// <summary>
        /// 32 byte secret key
        /// </summary>
        private byte[] secretKey;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="secretKey">32 byte secret key</param>
        public Response(byte[] secretKey)
        {
            if (secretKey.Length != PublicKeyBox.SecretKeyBytes) {
                throw new ArgumentException(String.Format("Secret key should be %d bytes", PublicKeyBox.SecretKeyBytes));
            }

            this.secretKey = secretKey;
        }

        /// <summary>
        /// Decrypts a v2 message.false The nonce and public key will be extracted from the message.
        /// </summary>
        /// <param name="response">The byte array encrypted message</param>
        /// <returns>The decrypt message</returns>
        public String Decrypt(byte[] response)
        {
            if (response.Length < 236) {
                throw new ArgumentException();
            }

            byte[] nonce = new byte[24];
            Array.Copy(response, 4, nonce, 0, 24);

            return this.Decrypt(response, null, nonce);
        }

        /// <summary>
        /// Decrypts a v2 message given it's public key. The nonce will be extracted from the message
        /// </summary>
        /// <param name="response">The byte array encrypted message</param>
        /// <param name="publicKey">32 byte public key</param>
        /// <returns>The decrypt message</returns>
        public String Decrypt(byte[] response, byte[] publicKey)
        {
            if (response.Length < 236) {
                throw new ArgumentException();
            }

            byte[] nonce = new byte[24];
            Array.Copy(response, 4, nonce, 0, 24);

            return this.Decrypt(response, publicKey, nonce);
        }

        /// <summary>
        /// Decrypts a versioned message given it's public key and nonce
        /// </summary>
        /// <param name="response">The byte array encrypted message</param>
        /// <param name="publicKey">32 byte public key</param>
        /// <param name="nonce">24 byte nonce</param>
        /// <returns>The decrypt message</returns>
        public String Decrypt(byte[] response, byte[] publicKey, byte[] nonce)
        {
            int version = GetVersion(response);
            if (nonce.Length != 24) {
                throw new ArgumentException(String.Format("Nonce should be %d bytes.", 24));
            }

            if (version == 2) {
                if (response.Length < 236) {
                    throw new ArgumentException();
                }

                byte[] payload = new byte[response.Length - 64];
                byte[] checksum = new byte[64];
                Array.Copy(response, 0, payload, 0, response.Length - 64);
                Array.Copy(response, response.Length - 64, checksum, 0, 64);

                byte[] calculatedChecksum = GenericHash.Hash(payload, nonce, 64);
                if (!Internal.memcmp(checksum, calculatedChecksum)) {
                    throw new InvalidChecksumException();
                }

                publicKey = new byte[32];
                byte[] signature = new byte[64];
                byte[] sigPubKey = new byte[32];
                byte[] body = new byte[payload.Length - 156];
                Array.Copy(response, 28, publicKey, 0, 32);
                Array.Copy(payload, payload.Length - 64, signature, 0, 64);
                Array.Copy(payload, payload.Length - 96, sigPubKey, 0, 32);
                Array.Copy(payload, 60, body, 0, payload.Length - 156);

                String decryptedBody = this.DecryptBody(body, publicKey, nonce);
                try {
                    if (!this.IsSignatureValid(decryptedBody, signature, sigPubKey)) {
                        throw new InvalidSignatureException();
                    }
                } catch (Exception e) {
                    throw new InvalidSignatureException("Signature associated with message is not valid.", e);
                }

                return decryptedBody;
            }

            if (publicKey.Length != PublicKeyBox.PublicKeyBytes) {
                throw new ArgumentException(String.Format("Public key should be %d bytes.", PublicKeyBox.PublicKeyBytes));
            }

            return this.DecryptBody(response, publicKey, nonce);
        }

        /// <summary>
        /// Internal implementation to decrypt a message given a public key and nonce
        /// </summary>
        /// <param name="response">The byte array encrypted message</param>
        /// <param name="publicKey">32 byte public key</param>
        /// <param name="nonce">24 byte nonce</param>
        /// <returns>Decrypted message as a string</returns>
        private String DecryptBody(byte[] response, byte[] publicKey, byte[] nonce)
        {
            try {
                if (publicKey.Length != PublicKeyBox.PublicKeyBytes) {
                    throw new ArgumentException(String.Format("Public key should be %d bytes.", PublicKeyBox.PublicKeyBytes));
                }

                if (response.Length < 16) { // PublicKeyBox.MAC_BYTES
                    throw new ArgumentException(String.Format("Message should be at minimum %d bytes.", 16));
                }

                byte[] message = PublicKeyBox.Open(
                    response,
                    nonce,
                    this.secretKey,
                    publicKey
                );

                return System.Text.Encoding.UTF8.GetString(message);
            } catch (Exception e) {
                Console.WriteLine(e);
                throw new DecryptionFailedException("Unable to decrypt message.", e);
            }
        }

        /// <summary>
        /// Returns true if the signature associated with a given message is valid
        /// </summary>
        /// <param name="response">Decrypted string representation of the response</param>
        /// <param name="signature">64 byte signature</param>
        /// <param name="publicKey">32 byte public key</param>
        /// <returns>`true` if the signature is valid, and false otherwise</returns>
        public bool IsSignatureValid(String response, byte[] signature, byte[] publicKey)
        {
            try {
                return PublicKeyAuth.VerifyDetached(
                    signature,
                    System.Text.Encoding.UTF8.GetBytes(response),
                    publicKey
                );
            } catch (Exception e) {
                throw new SignatureVerificationException("Unable to calculate signature.", e);
            }
        }

        /// <summary>
        /// Extracts the public key from the response
        /// </summary>
        /// <param name="response">The byte array encrypted message</param>
        /// <returns>32 byte public key</returns>
        public static byte[] GetPublicKeyFromResponse(byte[] response)
        {
            int version = GetVersion(response);
            if (version == 2) {
                if (response.Length < 236) {
                    throw new ArgumentException();
                }

                byte[] publicKey = new byte[32];
                Array.Copy(response, 28, publicKey, 0, 32);
                return publicKey;
            }

            throw new ArgumentException("The response provided is not suitable for public key extraction.");
        }

        /// <summary>
        /// Determines the version of an encrypted message
        /// </summary>
        /// <param name="response">The byte array encrypted message</param>
        /// <returns>The integer version of the encrypted message, if it can be detected.</returns>
        public static int GetVersion(byte[] response)
        {
            if (response.Length < 16) {
                throw new ArgumentException();
            }

            byte[] header = new byte[4];
            Array.Copy(response, header, 4);

            String hex = Sodium.Utilities.BinaryToHex(header).ToUpper();

            if (hex.Equals("DE259002")) {
                return 2;
            }

            return 1;
        }
    }
}