using System;
using System.Collections;
using System.IO;
using Newtonsoft.Json.Linq;
using System.Net.Http;
using Flurl;
using Flurl.Http;
using System.Threading.Tasks;
using Xunit;
using Sodium;
using ncryptf;
using ncryptf.Exceptions;
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
                throw new SkipTestException("NCRYPTF_TEST_API environment variable is not set. Unable to proceed.");
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

        /// <summary>
        /// Tests the bootstrap process with an encrypted response
        /// </summary>
        /// <returns>ArrayList containing the server public key, hashId, and the JSON response</returns>
        [SkippableFact]
        public ArrayList TestEphemeralKeyBootstrap()
        {
            this.Before();
            try {
                HttpResponseMessage response = Task.Run(async () => {
                    var request = (this.url + "/ek")
                        .WithHeader("Accept", "application/vnd.ncryptf+json")
                        .WithHeader("Content-Type", "application/vnd.ncryptf+json")
                        .WithHeader("x-pubkey", System.Convert.ToBase64String(this.key.PublicKey));
                    if (!this.IsNullOrEmpty(this.token)) {
                        request.WithHeader("X-Access-Token", this.token);
                    }
                    return await request.GetAsync();
                }).GetAwaiter().GetResult();

                String responseBody = Task.Run(async () => await response.Content.ReadAsStringAsync())
                    .GetAwaiter().GetResult();

                if (!response.IsSuccessStatusCode) {
                    Assert.True(false, "HTTP Status: " + response.StatusCode.ToString());
                }

                String message = (new Response(this.key.SecretKey))
                    .Decrypt(System.Convert.FromBase64String(responseBody));

                Assert.NotEmpty(message);

                JObject json = JObject.Parse(message);

                Assert.NotEmpty(json.GetValue("public").ToString());
                Assert.NotEmpty(json.GetValue("signature").ToString());

                var t = response.Headers.GetValues("X-HashId").GetEnumerator();
                    t.MoveNext();
                String hashId = t.Current;
                return new ArrayList()
                {
                    Response.GetPublicKeyFromResponse(System.Convert.FromBase64String(responseBody)),
                    hashId,
                    json
                };
            } catch (FlurlHttpException e) {
                String content = Task.Run(async () => {
                    return await e.Call.Response.Content.ReadAsStringAsync();
                }).GetAwaiter().GetResult();
                Assert.True(false, e.Message + " : " + content);
                return null;
            } catch (SkipTestException e) {
                throw new SkipTestException(e.Message);
            } catch (Exception e) {
                Assert.True(false, e.Message);
                return null;
            }
        }

        /// <summary>
        /// This request illustrates making an unauthenticated encrypted request and receiving
        /// an encrypted response in reply.
        /// </summary>
        [SkippableFact]
        public void TestUnauthenticatedRequest()
        {
            try {
                ArrayList stack = this.TestEphemeralKeyBootstrap();
                String payload = "{\"hello\":\"world\"}";
                HttpResponseMessage response = Task.Run(async () => {
                    var request = (this.url + "/echo")
                        .WithHeader("Accept", "application/vnd.ncryptf+json")
                        .WithHeader("Content-Type", "application/vnd.ncryptf+json")
                        .WithHeader("X-HashId", stack[1]);

                    // We don't need to include the public key (x-pubkey) header, as it's
                    // included in our request body.

                    if (!this.IsNullOrEmpty(this.token)) {
                        request.WithHeader("X-Access-Token", this.token);
                    }
                    Request r = new Request(
                        this.key.SecretKey,
                        Utils.GenerateSigningKeypair().SecretKey
                    );

                    String encryptedPayload = System.Convert.ToBase64String(
                        r.Encrypt(payload, (byte[])stack[0])
                    );

                    return await request.PostAsync(new StringContent(encryptedPayload));
                }).GetAwaiter().GetResult();

                String responseBody = Task.Run(async () => await response.Content.ReadAsStringAsync())
                    .GetAwaiter().GetResult();

                if (!response.IsSuccessStatusCode) {
                    Assert.True(false, "HTTP Status: " + response.StatusCode.ToString());
                    return;
                }

                String message = (new Response(this.key.SecretKey))
                    .Decrypt(System.Convert.FromBase64String(responseBody));

                Assert.Equal(payload, message);
            } catch (FlurlHttpException e) {
                String content = Task.Run(async () => {
                    return await e.Call.Response.Content.ReadAsStringAsync();
                }).GetAwaiter().GetResult();
                Assert.True(false, e.Message + " : " + content);
            } catch (SkipTestException e) {
                throw new SkipTestException(e.Message);
            } catch (Exception e) {
                Assert.True(false, e.Message);
            }
        }

        /// <summary>
        /// Authenticates against the API with an encrypted request and with an encrypted response
        /// </summary>
        /// <returns>ArrayList containing the token aquired, and the previously generated stack</returns>
        [SkippableFact]
        public ArrayList TestAuthenticateWithEncryptedRequest()
        {
            try {
                ArrayList stack = this.TestEphemeralKeyBootstrap();
                String payload = "{\"email\":\"clara.oswald@example.com\",\"password\":\"c0rect h0rs3 b@tt3y st@Pl3\"}";

                HttpResponseMessage response = Task.Run(async () => {
                    var request = (this.url + "/authenticate")
                        .WithHeader("Accept", "application/vnd.ncryptf+json")
                        .WithHeader("Content-Type", "application/vnd.ncryptf+json")
                        .WithHeader("X-HashId", stack[1]);

                    // We don't need to include the public key (x-pubkey) header, as it's
                    // included in our request body.

                    if (!this.IsNullOrEmpty(this.token)) {
                        request.WithHeader("X-Access-Token", this.token);
                    }
                    Request r = new Request(
                        this.key.SecretKey,
                        Utils.GenerateSigningKeypair().SecretKey
                    );

                    String encryptedPayload = System.Convert.ToBase64String(
                        r.Encrypt(payload, (byte[])stack[0])
                    );

                    return await request.PostAsync(new StringContent(encryptedPayload));
                }).GetAwaiter().GetResult();

                String responseBody = Task.Run(async () => await response.Content.ReadAsStringAsync())
                    .GetAwaiter().GetResult();

                if (!response.IsSuccessStatusCode) {
                    Assert.True(false, "HTTP Status: " + response.StatusCode.ToString());
                    return null;
                }

                String message = (new Response(this.key.SecretKey))
                    .Decrypt(System.Convert.FromBase64String(responseBody));

                Assert.NotEmpty(message);

                JObject json = JObject.Parse(message);

                Assert.NotEmpty(json.GetValue("access_token").ToString());
                Assert.NotEmpty(json.GetValue("refresh_token").ToString());
                Assert.NotEmpty(json.GetValue("ikm").ToString());
                Assert.NotEmpty(json.GetValue("signing").ToString());
                Assert.NotEmpty(json.GetValue("expires_at").ToString());

                Token token = new Token(
                    json.GetValue("access_token").ToString(),
                    json.GetValue("refresh_token").ToString(),
                    System.Convert.FromBase64String(json.GetValue("ikm").ToString()),
                    System.Convert.FromBase64String(json.GetValue("signing").ToString()),
                    System.Convert.ToInt64(json.GetValue("expires_at").ToString())
                );

                return new ArrayList()
                {
                    stack,
                    token
                };

            } catch (FlurlHttpException e) {
                String content = Task.Run(async () => {
                    return await e.Call.Response.Content.ReadAsStringAsync();
                }).GetAwaiter().GetResult();
                Assert.True(false, e.Message + " : " + content);
                return null;
            } catch (SkipTestException e) {
                throw new SkipTestException(e.Message);
            } catch (Exception e) {
                Assert.True(false, e.Message);
                return null;
            }
        }

        /// <summary>
        /// Tests an authenticated and encrypted echo request with an encrypted response
        /// </summary>
        [SkippableFact]
        public void TestAuthenticatedEchoWithEncryptedRequest()
        {
            try {
                ArrayList tawer = this.TestAuthenticateWithEncryptedRequest();
                ArrayList stack = (ArrayList)tawer[0];
                Token token = (Token)tawer[1];

                String payload = "{\"hello\":\"world\"}";

                HttpResponseMessage response = Task.Run(async () => {
                    var request = (this.url + "/echo")
                        .WithHeader("Accept", "application/vnd.ncryptf+json")
                        .WithHeader("Content-Type", "application/vnd.ncryptf+json")
                        .WithHeader("X-HashId", stack[1]);

                    // We don't need to include the public key (x-pubkey) header, as it's
                    // included in our request body.

                    if (!this.IsNullOrEmpty(this.token)) {
                        request.WithHeader("X-Access-Token", this.token);
                    }

                    Authorization auth = new Authorization(
                        "PUT",
                        "/echo",
                        token,
                        DateTime.UtcNow,
                        payload
                    );

                    request.WithHeader("Authorization", auth.GetHeader());

                    Request r = new Request(
                        this.key.SecretKey,
                        token.Signature
                    );

                    String encryptedPayload = System.Convert.ToBase64String(
                        r.Encrypt(payload, (byte[])stack[0])
                    );

                    return await request.PutAsync(new StringContent(encryptedPayload));
                }).GetAwaiter().GetResult();

                String responseBody = Task.Run(async () => await response.Content.ReadAsStringAsync())
                    .GetAwaiter().GetResult();

                if (!response.IsSuccessStatusCode) {
                    Assert.True(false, "HTTP Status: " + response.StatusCode.ToString());
                }

                String message = (new Response(this.key.SecretKey))
                    .Decrypt(System.Convert.FromBase64String(responseBody));

                /**
                 * As an added integrity check, the API will sign the message with the same key it issued during authentication
                 * Therefore, we can verify that the signing public key associated to the message matches the public key from the
                 * token we were issued.
                 *
                 * If the keys match, then we have assurance that the message is authenticated
                 * If the keys don't match, then the request has been tampered with and should be discarded.
                 *
                 * This check should ALWAYS be performed for authenticated requests as it ensures the validity of the message
                 * and the origin of the message.
                 */
                Assert.True(memcmp(
                    token.GetSignaturePublicKey(),
                    Response.GetSigningPublicKeyFromResponse(System.Convert.FromBase64String(responseBody))
                ));
                Assert.Equal(payload, message);
            } catch (FlurlHttpException e) {
                String content = Task.Run(async () => {
                    return await e.Call.Response.Content.ReadAsStringAsync();
                }).GetAwaiter().GetResult();
                Assert.True(false, e.Message + " : " + content);
            } catch (SkipTestException e) {
                throw new SkipTestException(e.Message);
            } catch (Exception e) {
                Assert.True(false, e.Message);
            }
        }

        /************************************************************************************************
         *
         * The requests that follow are for implementation sanity checks, and should not be referenced
         * for other client implementations
         *
         ************************************************************************************************/

        [SkippableFact]
        public void TestAuthenticatedEchoWithBadSignature()
        {
            try {
                ArrayList tawer = this.TestAuthenticateWithEncryptedRequest();
                ArrayList stack = (ArrayList)tawer[0];
                Token token = (Token)tawer[1];

                String payload = "{\"hello\":\"world\"}";

                HttpResponseMessage response = Task.Run(async () => {
                    var request = (this.url + "/echo")
                        .WithHeader("Accept", "application/vnd.ncryptf+json")
                        .WithHeader("Content-Type", "application/vnd.ncryptf+json")
                        .WithHeader("X-HashId", stack[1]);

                    // We don't need to include the public key (x-pubkey) header, as it's
                    // included in our request body.

                    if (!this.IsNullOrEmpty(this.token)) {
                        request.WithHeader("X-Access-Token", this.token);
                    }

                    Authorization auth = new Authorization(
                        "PUT",
                        "/echo",
                        token,
                        DateTime.UtcNow,
                        payload
                    );

                    request.WithHeader("Authorization", auth.GetHeader());

                    Request r = new Request(
                        this.key.SecretKey,
                        Utils.GenerateSigningKeypair().SecretKey
                    );

                    String encryptedPayload = System.Convert.ToBase64String(
                        r.Encrypt(payload, (byte[])stack[0])
                    );

                    return await request.PutAsync(new StringContent(encryptedPayload));
                }).GetAwaiter().GetResult();

            } catch (FlurlHttpException e) {
                Assert.Equal(401, (int)e.Call.Response.StatusCode);
            } catch (SkipTestException e) {
                throw new SkipTestException(e.Message);
            } catch (Exception e) {
                Assert.True(false, e.Message);
            }
        }

        [SkippableFact]
        public void TestMalformedEncryptedRequest()
        {
            try {
                ArrayList stack = this.TestEphemeralKeyBootstrap();

                String payload = "{\"hello\":\"world\"}";

                HttpResponseMessage response = Task.Run(async () => {
                    var request = (this.url + "/echo")
                        .WithHeader("Accept", "application/vnd.ncryptf+json")
                        .WithHeader("Content-Type", "application/vnd.ncryptf+json")
                        .WithHeader("X-HashId", stack[1]);

                    // We don't need to include the public key (x-pubkey) header, as it's
                    // included in our request body.

                    if (!this.IsNullOrEmpty(this.token)) {
                        request.WithHeader("X-Access-Token", this.token);
                    }

                    Request r = new Request(
                        this.key.SecretKey,
                        Utils.GenerateSigningKeypair().SecretKey
                    );

                    Random rnd = new Random();
                    Byte[] b = new Byte[32];
                    rnd.NextBytes(b);

                    byte[] bPayload = r.Encrypt(payload, (byte[])stack[0]);
                    Array.Copy(b, 0, bPayload, 60, 32);
                    String encryptedPayload = System.Convert.ToBase64String(
                        r.Encrypt(payload, (byte[])stack[0])
                    );
                    return await request.PostAsync(new StringContent(encryptedPayload));
                }).GetAwaiter().GetResult();

            } catch (FlurlHttpException e) {
                Assert.Equal(400, (int)e.Call.Response.StatusCode);
            } catch (SkipTestException e) {
                throw new SkipTestException(e.Message);
            } catch (Exception e) {
                Assert.True(false, e.Message);
            }
        }

        /// <summary>
        /// Constant time byte[] comparison since Sodium.Core does not provide this implementation
        /// </summary>
        /// <param name="a">byte[] a</param>
        /// <param name="b">byte[] a</param>
        /// <returns>Boolean</returns>
        internal static bool memcmp(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++) {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }
    }
}