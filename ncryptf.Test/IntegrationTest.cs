using System;
using Xunit;
using Sodium;
using ncryptf;
using ncryptf.Test.xunit;

namespace ncryptf.Test
{
    /// <summary>
    /// This class demonstrates a practical end-to-end implementation via HttpClient
    /// </summary>
    /// <remarks>
    ///  Implementation may be inferred from this implementation, and is broken out into the following stages:
    ///  1. Create a \ncryptf\Keypair instance
    ///  2. Bootstrap an encrypted session by sending an unauthenticated requests to the ephemeral key endpoint with the following headers:
    ///   - Accept: application/vnd.ncryptf+json
    ///   - Content-Type: application/vnd.ncryptf+json
    ///   - X-PubKey: <base64_encoded_$key->getPublicKey()>
    ///  3. Decrypt the V2 response from the server. This contains a single use ephemeral key we can use to encrypt future requests in the payload.
    ///     The servers public key is embedded in the response, and can be extracted by `Response::getPublicKeyFromResponse($response);`
    ///  4. Perform an authenticated request using the clients secret key, and the servers public key.
    ///
    ///  Implementation Details
    ///  - The server WILL always advertise at minimum the following 2 headers:
    ///       - X-HashId: A string used to represent the identifier to use to select which key to use.
    ///       - X-Public-Key-Expiration: A unix timestamp representing the time at which the key will expire. This is used to determine if rekeying is required.
    ///  - The server WILL always generate a new keypair for each request. You may continue to use existing keys until they expire.
    ///  - To achieve perfect-forward-secrecy, it is advised to rekey the client key on each request. The server does not store the shared secret for prior requests.
    ///  - The client SHOULD keep a record of public keys offered by the server, along with their expiration time.
    ///  - The client SHOULD always use the most recent key offered by the server.
    ///  - If the client does not have any active keys, it should bootstrap a new session by calling the ephemeral key endpoint to retrieve a new public key from the server.
    /// </remarks>
    public class IntegrationTest
    {
        /// <summary>
        /// This is the URL provided by the `NCRYPTF_TEST_API` environment variable
        /// </summary>
        private String url;

        /// <summary>
        /// A keypair object
        /// </summary>
        private Keypair key;

        /// <summary>
        /// An access token to identify this client
        /// </summary>
        private String token;

        /// <summary>
        /// Run this method before each test to ensure skippable behavior
        /// </summary>
        private void Before()
        {
            if (this.url == null || this.url == "") {
                throw new SkipTestException("NCRYOTF_TEST_API environment variable is not set. Unable to proceed.");
            }
        }

        /// <summary>
        /// IsNullOrEmpty implementation
        /// </summary>
        /// <param name="str">The string to check</param>
        /// <returns>true if the provided string is null or empty, fale otherwise</returns>
        private bool IsNullOrEmpty(String str)
        {
            if (str == null || str == "") {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Constructor to populate the url, token, and keypair
        /// </summary>
        public IntegrationTest()
        {
            String url;
            if (!IsNullOrEmpty(url = Environment.GetEnvironmentVariable("NCRYPTF_TEST_API"))) {
                this.url = url;
            }

            String token;
            if (!IsNullOrEmpty(token = Environment.GetEnvironmentVariable("ACCESS_TOKEN"))) {
                this.token = token;
            }

            this.key = Utils.GenerateKeypair();
        }
    }
}