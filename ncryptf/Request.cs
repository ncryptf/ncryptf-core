using System;
using System.IO;
using Sodium;

using ncryptf.Exceptions;

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

        public byte[] Encrypt(String data, byte[] publicKey)
        {
            byte[] nonce = PublicKeyBox.GenerateNonce();
            return Encrypt(data, publicKey, 2, nonce);
        }

        public byte[] Encrypt(String data, byte[] publicKey, int version)
        {
            byte[] nonce = PublicKeyBox.GenerateNonce();
            return Encrypt(data, publicKey, version, nonce);
        }

        public byte[] Encrypt(String data, byte[] remotePublicKey, int version, byte[] nonce)
        {
            if (remotePublicKey.Length != PublicKeyBox.PublicKeyBytes) {
                throw new ArgumentException(String.Format("Public key should be %d bytes", PublicKeyBox.PublicKeyBytes));
            }
            
            if (nonce.Length != 24) {
                throw new ArgumentException(String.Format("Nonce should be %d bytes", 24));
            }

            this.nonce = nonce;
            if (version == 2) {
                try {
                    byte[] header = Sodium.Utilities.HexToBinary("DE259002");
                    byte[] body = this.EncryptBody(data, remotePublicKey, nonce);

                    if (body == null) {
                        throw new EncryptionFailedException();
                    }

                    byte[] publicKey = ScalarMult.Base(this.secretKey);
                    byte[] sigPubKey = PublicKeyAuth.ExtractEd25519PublicKeyFromEd25519SecretKey(this.signatureSecretKey);

                    byte[] signature = this.Sign(data);
                    if (signature == null) {
                        throw new EncryptionFailedException();
                    }

                    MemoryStream m = new MemoryStream();
                    m.Write(header, 0, header.Length);
                    m.Write(nonce, 0, nonce.Length);
                    m.Write(publicKey, 0, publicKey.Length);
                    m.Write(body, 0, body.Length);
                    m.Write(sigPubKey, 0, sigPubKey.Length);
                    m.Write(signature, 0, signature.Length);

                    byte[] payload = m.ToArray();
                    byte[] checksum = GenericHash.Hash(payload, nonce, 64);
                
                    m.Write(checksum, 0, checksum.Length);

                    return m.ToArray();
                } catch (Exception e) {
                    throw new EncryptionFailedException("Unable to encrypt message.", e);
                }
            }

            return this.EncryptBody(data, remotePublicKey, nonce);

        }

        private byte[] EncryptBody(String data, byte[] publicKey, byte[] nonce)
        {
            if (publicKey.Length != PublicKeyBox.PublicKeyBytes) {
                throw new ArgumentException(String.Format("Public key should be %d bytes", PublicKeyBox.PublicKeyBytes));
            }

            if (nonce.Length != 24) { // PublicKeyBox.NONCE_BYTES
                throw new ArgumentException(String.Format("Nonce should be %d bytes", 24));
            }

            try {
                return PublicKeyBox.Create(
                    data,
                    nonce,
                    this.secretKey,
                    publicKey
                );
            } catch (Exception e) {
                throw new EncryptionFailedException("Unable to encrypt message", e);
            }
        }

        public byte[] Sign(String data)
        {
            try {
                return PublicKeyAuth.SignDetached(data, this.signatureSecretKey);
            } catch (Exception e) {
                throw new SigningException("Unable to sign message", e);
            }
        }

        public byte[] GetNonce()
        {
            return this.nonce;
        }
    }
}