using System;
using Sodium;
using ncryptf.Exceptions;

namespace ncryptf
{
    public class Response
    {
        private byte[] secretKey;

        public Response(byte[] secretKey)
        {
            if (secretKey.Length != PublicKeyBox.SecretKeyBytes) {
                throw new ArgumentException(String.Format("Secret key should be %d bytes", PublicKeyBox.SecretKeyBytes));
            }

            this.secretKey = secretKey;
        }

        public String Decrypt(byte[] response)
        {
            if (response.Length < 236) {
                throw new ArgumentException();
            }

            byte[] nonce = new byte[24];
            Array.Copy(response, 4, nonce, 0, 24);

            return this.Decrypt(response, null, nonce);
        }

        public String Decrypt(byte[] response, byte[] publicKey)
        {
            if (response.Length < 236) {
                throw new ArgumentException();
            }

            byte[] nonce = new byte[24];
            Array.Copy(response, 4, nonce, 0, 24);

            return this.Decrypt(response, publicKey, nonce);
        }

        public String Decrypt(byte[] response, byte[] publicKey, byte[] nonce)
        {
            int version = GetVersion(response);
            if (version == 2) {
                
            }

            return this.DecryptBody(response, publicKey, nonce);
        }

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
                throw new DecryptionFailedException("Unable to decrypt message.", e);
            }
        }

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