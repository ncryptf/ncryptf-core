using System;

namespace ncryptf
{
    public class Token
    {
        private readonly String _accessToken;

        private readonly String _refreshToken;

        private readonly byte[] _ikm;

        private readonly byte[] _signature;

        private long _expiresAt;

        public Token(String accessToken, String refreshToken, byte[] ikm, byte[] signature, long expiresAt)
        {
            this._accessToken = accessToken;
            this._refreshToken = refreshToken;
            this._ikm = ikm;
            this._signature = signature;
            this._expiresAt = expiresAt;
        }

        public String AccessToken
        {
            get { return this._accessToken; }
        }

        public String RefreshToken
        {
            get { return this._refreshToken; }
        }

        public byte[] IKM
        {
            get { return this._ikm; }
        }

        public byte[] Signature
        {
            get { return this._signature; }
        }

        public long ExpiresAt
        {
            get { return this._expiresAt; }
        }
    }
}