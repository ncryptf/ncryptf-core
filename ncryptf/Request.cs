using System;
using System.IO;
using Sodium;

using ncryptf.Exceptions;

namespace ncryptf
{
    /// <summary>
    /// Encrypts a request
    /// </summary>
    public class Request
    {
        /// <summary>
        /// 32 byte secret key
        /// </summary>
        private byte[] secretKey;

        /// <summary>
        /// 32 byte signature secret key
        /// </summary>
        private byte[] signatureSecretKey;

        /// <summary>
        /// 24 byte nonce
        /// </summary>
        private byte[] nonce;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="secretKey">32 byte secret key</param>
        /// <param name="signatureSecretKey">32 byte signature secret key</param>
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

        /// <summary>
        /// Encrypts data with a public key
        /// </summary>
        /// <param name="data">String data to encrypt</param>
        /// <param name="publicKey">32 byte public key</param>
        /// <returns>byte[] containing the encrypted data</returns>
        public byte[] Encrypt(String data, byte[] publicKey)
        {
            byte[] nonce = PublicKeyBox.GenerateNonce();
            return Encrypt(data, publicKey, 2, nonce);
        }

        /// <summary>
        /// Encrypts data with a public key
        /// </summary>
        /// <param name="data">String data to encrypt</param>
        /// <param name="publicKey">32 byte public key</param>
        /// <param name="version">Int version to generated</param>
        /// <returns>byte[] containing the encrypted data</returns>
        public byte[] Encrypt(String data, byte[] publicKey, int version = 2)
        {
            byte[] nonce = PublicKeyBox.GenerateNonce();
            return Encrypt(data, publicKey, version, nonce);
        }

        /// <summary>
        /// Encrypts data with a public key
        /// </summary>
        /// <param name="data">String data to encrypt</param>
        /// <param name="publicKey">32 byte public key</param>
        /// <param name="version">Int version to generated</param>
        /// <param name="nonce">24 byte nonce.</param>
        /// <returns>byte[] containing the encrypted data</returns>
        public byte[] Encrypt(String data, byte[] publicKey, int version, byte[] nonce)
        {
            if (publicKey.Length != PublicKeyBox.PublicKeyBytes) {
                throw new ArgumentException(String.Format("Public key should be %d bytes", PublicKeyBox.PublicKeyBytes));
            }

            if (nonce.Length != 24) {
                throw new ArgumentException(String.Format("Nonce should be %d bytes", 24));
            }

            this.nonce = nonce;
            if (version == 2) {
                try {
                    byte[] header = Sodium.Utilities.HexToBinary("DE259002");
                    byte[] body = this.EncryptBody(data, publicKey, nonce);

                    if (body == null) {
                        throw new EncryptionFailedException();
                    }

                    publicKey = ScalarMult.Base(this.secretKey);
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

            return this.EncryptBody(data, publicKey, nonce);

        }

        /// <summary>
        /// Encrypts a message with a public key and nonce
        /// </summary>
        /// <param name="data">String data to encrypt</param>
        /// <param name="publicKey">32 byte public key</param>
        /// <param name="nonce">24 byte nonce</param>
        /// <returns>byte[] encrypted data</returns>
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

        /// <summary>
        /// Generated a detached signature from the provided data
        /// </summary>
        /// <param name="data">String payload to sign</param>
        /// <returns>byte[] of the detached signature</returns>
        public byte[] Sign(String data)
        {
            try {
                return PublicKeyAuth.SignDetached(data, this.signatureSecretKey);
            } catch (Exception e) {
                throw new SigningException("Unable to sign message", e);
            }
        }

        /// <summary>
        /// Returns the generated or provided 24 byte noce
        /// </summary>
        /// <returns>byte[]</returns>
        public byte[] GetNonce() => this.nonce;
    }
}