using Multiformats.Base;
using Newtonsoft.Json.Linq;
using System;
using W3C.CCG.DidCore;

namespace LinkedDataProofs.Suites
{
    public class Ed25519VerificationKey2018 : VerificationMethod, ISigner
    {
        public const string Name = "Ed25519VerificationKey2018";

        public Ed25519VerificationKey2018()
        {
            TypeName = Name;
        }

        public Ed25519VerificationKey2018(JObject obj) : base(obj)
        {
            TypeName ??= Name;
        }

        public string PublicKeyBase58
        {
            get => this["publicKeyBase58"]?.Value<string>();
            set => this["publicKeyBase58"] = value;
        }

        public string PrivateKeyBase58
        {
            get => this["privateKeyBase58"]?.Value<string>();
            set => this["privateKeyBase58"] = value;
        }

        /// <summary>
        /// Sign a payload using this method's private key
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public byte[] Sign(IVerifyData input)
        {
            if (PrivateKeyBase58 == null)
            {
                throw new Exception("Private key not found.");
            }
            if (input is ByteArray data)
            {
                var decoded = Multibase.Base58.Decode(PrivateKeyBase58);
                if (decoded.Length == Chaos.NaCl.Ed25519.PrivateKeySeedSizeInBytes)
                {
                    Chaos.NaCl.Ed25519.KeyPairFromSeed(out var _, out decoded, decoded);
                }
                return Chaos.NaCl.Ed25519.Sign(data.Data, decoded);
            }

            throw new ArgumentException($"Invalid input type data. Expected '{typeof(ByteArray).Name}', found '{input?.GetType().Name}'");
        }

        /// <summary>
        /// Gets the public data for this method
        /// </summary>
        /// <returns></returns>
        public override VerificationMethod GetPublicNode()
        {
            var clone = DeepClone();
            clone.Remove("privateKeyBase58");

            return new Ed25519VerificationKey2018(clone as JObject);
        }

        /// <summary>
        /// Verify a signature using this method's public key
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="input"></param>
        /// <returns></returns>
        public bool Verify(byte[] signature, IVerifyData input)
        {
            if (PublicKeyBase58 == null)
            {
                throw new Exception("Public key not found.");
            }
            if (input is ByteArray data)
            {
                return Chaos.NaCl.Ed25519.Verify(signature, data.Data, Multibase.Base58.Decode(PublicKeyBase58));
            }

            throw new ArgumentException($"Invalid input type data. Expected '{typeof(ByteArray).Name}', found '{input?.GetType().Name}'");
        }

        /// <summary>
        /// Generate new random key
        /// </summary>
        /// <returns></returns>
        public static Ed25519VerificationKey2018 Generate(string id = "#key-1")
        {
            var edKey = Chaos.NaCl.Ed25519KeyPair.Generate();

            return new Ed25519VerificationKey2018
            {
                Id = id,
                PublicKeyBase58 = Multibase.Base58.Encode(edKey.PublicKey.Array),
                PrivateKeyBase58 = Multibase.Base58.Encode(edKey.PrivateKey.Value.Array),
            };
        }
    }
}