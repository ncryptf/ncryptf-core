using System;
using Sodium;
using System.Security.Cryptography;
using AronParker.Hkdf;

namespace ncryptf
{
    /// <summary>
    /// Generates a signed authentication header
    /// </summary>
    public class Authorization
    {
        /// <summary>
        /// Authorization info for HKDF
        /// </summary>
        public const String AUTH_INFO = "HMAC|AuthenticationKey";

        /// <summary>
        /// ncryptf.Token instance
        /// </summary>
        private Token token;

        /// <summary>
        /// 32 byte salt
        /// </summary>
        private byte[] salt;

        /// <summary>
        /// DateTime date
        /// </summary>
        private DateTime date;

        /// <summary>
        /// Generated signature string
        /// </summary>
        private String signature;

        /// <summary>
        /// Calculated HMAC
        /// </summary>
        private byte[] hmac;

        /// <summary>
        /// Authorization header version
        /// </summary>
        private int version = 2;

        /// <summary>
        /// Generates a v2 authentication header
        /// </summary>
        /// <param name="httpMethod">The HTTP method</param>
        /// <param name="uri">The URI</param>
        /// <param name="token">A ncryptf.Token instance</param>
        /// <param name="date">DateTime date</param>
        /// <param name="payload">String payload</param>
        public Authorization(
            String httpMethod,
            String uri,
            Token token,
            DateTime date,
            String payload
        ) : this(httpMethod, uri, token, date, payload, 2)
        {
        }

        /// <summary>
        /// Generates a versioned authentication header
        /// </summary>
        /// <param name="httpMethod">The HTTP method</param>
        /// <param name="uri">The URI</param>
        /// <param name="token">A ncryptf.Token instance</param>
        /// <param name="date">DateTime date</param>
        /// <param name="payload">String payload</param>
        /// <param name="version">Authorization version to generate. Defaults to 2</param>
        public Authorization(
            String httpMethod,
            String uri,
            Token token,
            DateTime date,
            String payload,
            int version = 2
        ) : this(httpMethod, uri, token, date, payload, version, null)
        {
        }

        /// <summary>
        /// Generates a versioned authentication header
        /// </summary>
        /// <param name="httpMethod">The HTTP method</param>
        /// <param name="uri">The URI</param>
        /// <param name="token">A ncryptf.Token instance</param>
        /// <param name="date">DateTime date</param>
        /// <param name="payload">String payload</param>
        /// <param name="version">Authorization version to generate. Defaults to 2</param>
        /// <param name="salt">32 byte salt value. If not provided, one will be generated.</param>
        public Authorization(
            String httpMethod,
            String uri,
            Token token,
            DateTime date,
            String payload,
            int version = 2,
            byte[] salt = null
        ) {
            httpMethod = httpMethod.ToUpper();
            if (salt == null) {
                salt = SodiumCore.GetRandomBytes(32);
            }

            if (salt.Length != 32) {
                throw new ArgumentException("Salt must be 32 bytes");
            }

            this.salt = salt;
            this.signature = Signature.Derive(httpMethod, uri, salt, date, payload, version);
            this.date = date;
            this.version = version;
            this.token = token;

           Hkdf hkdf = new Hkdf(HashAlgorithmName.SHA256);

           byte[] kdf = hkdf.Expand(
               hkdf.Extract(token.IKM, salt),
               32,
               System.Text.Encoding.UTF8.GetBytes(AUTH_INFO)
           );

           String hkdfString = Sodium.Utilities.BinaryToHex(kdf);
           byte[] key = System.Text.Encoding.UTF8.GetBytes(hkdfString.ToLower());
           byte[] sig = System.Text.Encoding.UTF8.GetBytes(this.signature);

           HMACSHA256 hmac = new HMACSHA256(key);
           this.hmac = hmac.ComputeHash(sig);
        }

        /// <summary>
        /// Returns the DateTime used
        /// </summary>
        /// <returns>DateTime</returns>
        public DateTime GetDate()
        {
            return this.date;
        }

        /// <summary>
        /// Returns an RFC 2822 formatted date
        /// </summary>
        /// <returns>String</returns>
        public String GetDateString()
        {
            return this.date.ToString("r").Replace(" GMT", " +0000");
        }

        /// <summary>
        /// Returns the raw calculated HMAC
        /// </summary>
        /// <returns>byte[]</returns>
        public byte[] GetHMAC()
        {
            return this.hmac;
        }

        /// <summary>
        /// Returns the base64 encoded HMAC value
        /// </summary>
        /// <returns>String</returns>
        public String GetEncodedHMAC()
        {
            return System.Convert.ToBase64String(this.hmac);
        }

        /// <summary>
        /// Returns the base64 encoded salt value
        /// </summary>
        /// <returns>String</returns>
        public String GetEncodedSalt()
        {
            return System.Convert.ToBase64String(this.salt);
        }

        /// <summary>
        /// Returns the calculated signature string
        /// </summary>
        /// <returns>String</returns>
        public String GetSignatureString()
        {
            return this.signature;
        }

        /// <summary>
        /// Returns a versioned header
        /// </summary>
        /// <returns>String</returns>
        public String GetHeader()
        {
            String salt = this.GetEncodedSalt();
            String hmac = this.GetEncodedHMAC();

            if (this.version == 2) {
                String json = "{\"access_token\":\"" + this.token.AccessToken + "\",\"date\":\"" + this.GetDateString() + "\",\"hmac\":\"" + hmac + "\",\"salt\":\"" + salt + "\",\"v\":2}";
                json = json.Replace("/", "\\/");

                return "HMAC " + System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json));
            }

            return "HMAC " + this.token.AccessToken + "," + hmac + "," + salt;
        }

        /// <summary>
        /// Returns true if the HMAC provided and the HMAC from the auth object match
        /// </summary>
        /// <param name="hmac">byte[] HMAC</param>
        /// <param name="auth">Authorization object</param>
        /// <param name="driftAllowance">Maximum drift allowance</param>
        /// <returns>Boolean</returns>
        public bool Verify(byte[] hmac, Authorization auth, int driftAllowance = 90)
        {
            int drift = this.GetTimeDrift(auth.GetDate());
            if (drift >= driftAllowance) {
                return false;
            }

            if (Internal.memcmp(hmac, auth.GetHMAC())) {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Returns the number of seconds between two unix timestamps
        /// </summary>
        /// <param name="date">DateTime to check against</param>
        /// <returns>Number of seconds between now and the drift time</returns>
        private int GetTimeDrift(DateTime date)
        {
            DateTime now = DateTime.UtcNow;

            return (int)Math.Abs(
                ((DateTimeOffset)now).ToUnixTimeSeconds() - ((DateTimeOffset)date).ToUnixTimeSeconds()
            );
        }
    }
}