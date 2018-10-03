using System;
using Sodium;

namespace ncryptf
{
    public class Request
    {
        private byte[] secretKey;

        private byte[] signatureSecretKey;

        private byte[] nonce;

        public Request(byte[] secretKey, byte[] signatureSecretKey)
        {
            if (secretKey.Length != PublicKeyBox.SecretKeyBytes) {
                throw new ArgumentException(String.Format("Secret key should be %d bytes", PublicKeyBox.SecretKeyBytes));
            }
            
            this.secretKey = secretKey;

            if (signatureSecretKey.Length != 64) { // PublicKeyAuth.SECRET_KEY_BYTES
                throw new ArgumentException(String.Format("Signature secret key should be %d bytes", 64));
            }

            this.signatureSecretKey = signatureSecretKey;
        }

        
    }
}