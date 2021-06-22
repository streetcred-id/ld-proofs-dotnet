using System;
using System.Security.Cryptography;

namespace Chaos.NaCl
{
    public class Ed25519KeyPair
    {
        public ArraySegment<byte> PublicKey { get; set; }

        public ArraySegment<byte>? PrivateKey { get; set; }

        /// <summary>
        /// Generates new <see cref="Ed25519KeyPair"/> from a random seed.
        /// </summary>
        /// <returns></returns>
        public static Ed25519KeyPair Generate()
        {
            var seed = new byte[32];
            new RNGCryptoServiceProvider().GetBytes(seed);
            return Generate(seed);
        }

        /// <summary>
        /// Generates new <see cref="Ed25519KeyPair"/> from the specified seed.
        /// </summary>
        /// <param name="seed">The seed.</param>
        /// <returns></returns>
        public static Ed25519KeyPair Generate(byte[] seed)
        {
            Ed25519.KeyPairFromSeed(out var pk, out var sk, seed);
            return new Ed25519KeyPair { PublicKey = pk, PrivateKey = sk };
        }
    }
}