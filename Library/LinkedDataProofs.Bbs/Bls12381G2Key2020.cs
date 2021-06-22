using System;
using BbsSignatures;
using Multiformats.Base;
using Newtonsoft.Json.Linq;
using W3C.CCG.DidCore;

namespace LinkedDataProofs.Bbs
{
    public class Bls12381G2Key2020 : VerificationMethod
    {
        public const string Name = "Bls12381G2Key2020";
        private readonly IBbsSignatureService Service = new BbsSignatureService();

        public Bls12381G2Key2020()
        {
            TypeName = Name;
        }

        public Bls12381G2Key2020(JObject obj) : base(obj)
        {
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
        /// Gets the public data for this method
        /// </summary>
        /// <returns></returns>
        public override VerificationMethod GetPublicNode()
        {
            var clone = DeepClone();
            clone.Remove("privateKeyBase58");

            return new Bls12381G2Key2020(clone as JObject);
        }

        public BlsKeyPair ToBlsKeyPair()
        {
            if (PublicKeyBase58 == null)
            {
                throw new ArgumentNullException(nameof(PublicKeyBase58), "Public key not found");
            }
            return new BlsKeyPair(
                publicKey: Multibase.Base58.Decode(PublicKeyBase58),
                secretKey: PrivateKeyBase58 != null ? Multibase.Base58.Decode(PrivateKeyBase58) : null);
        }
    }
}
