using System;
using Sodium;

namespace ncryptf
{
    public class Utils {
        public static bool zero(byte[] data)
        {
            Array.Clear(data, 0, data.Length);
            for(int i = 0; i < data.Length; i++) {
                if (data[i] != 0) {
                    return false;
                }
            }

            return true;
        }

        public static Keypair GenerateKeypair()
        {
            KeyPair kp = PublicKeyBox.GenerateKeyPair();
            return new Keypair(kp.PublicKey, kp.PrivateKey);

        }

        public static Keypair GenerateSigningKeypair()
        {
            KeyPair kp = PublicKeyAuth.GenerateKeyPair();
            return new Keypair(kp.PublicKey, kp.PrivateKey);
        }
    }
}