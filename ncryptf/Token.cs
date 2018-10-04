using System;

namespace ncryptf
{
    /// <summary>
    /// Represents a API token
    /// </summary>
    public class Token
    {
        /// <summary>
        /// Access token
        /// </summary>
        private readonly String _accessToken;

        /// <summary>
        /// Refresh token
        /// </summary>
        private readonly String _refreshToken;

        /// <summary>
        /// 32 byte initial key material
        /// </summary>
        private readonly byte[] _ikm;

        /// <summary>
        /// 64 byte signautre 
        /// </summary>
        private readonly byte[] _signature;

        /// <summary>
        /// Expiration time
        /// </summary>
        private readonly long _expiresAt;

        /// <summary>
        /// Constructs a new access token
        /// </summary>
        /// <param name="accessToken">Access token that identifies the user</param>
        /// <param name="refreshToken">Refresh token</param>
        /// <param name="ikm">32 byte initial key material</param>
        /// <param name="signature">64 byte signature</param>
        /// <param name="expiresAt">The unix timestamp when this token expires</param>
        public Token(String accessToken, String refreshToken, byte[] ikm, byte[] signature, long expiresAt)
        {
            this._accessToken = accessToken;
            this._refreshToken = refreshToken;
            this._ikm = ikm;
            this._signature = signature;
            this._expiresAt = expiresAt;
        }

        /// <summary>
        /// The access token that identifies the user
        /// </summary>
        /// <value>String</value>
        public String AccessToken
        {
            get { return this._accessToken; }
        }

        /// <summary>
        /// The refresh token provided by the server
        /// </summary>
        /// <value>String</value>
        public String RefreshToken
        {
            get { return this._refreshToken; }
        }

        /// <summary>
        /// 32 byte initial key material used for signing
        /// </summary>
        /// <value>32 byte[]</value>
        public byte[] IKM
        {
            get { return this._ikm; }
        }

        /// <summary>
        /// The signature private key provided by the API
        /// </summary>
        /// <value>64 byte[] signature private key</value>
        public byte[] Signature
        {
            get { return this._signature; }
        }

        /// <summary>
        /// The expiration time of this token
        /// </summary>
        /// <value>byte[]</value>
        public long ExpiresAt
        {
            get { return this._expiresAt; }
        }
    }
}