using Newtonsoft.Json.Linq;

namespace LinkedDataProofs.Suites
{
    public class Ed25519Signature2018 : JwsLinkedDataSignature
    {
        public const string Name = "Ed25519Signature2018";

        public Ed25519Signature2018() : base(Name)
        {
        }

        public override string Algorithm => "EdDSA";

        /// <summary>
        /// Returns a typed instance capable of signing and verifying
        /// </summary>
        /// <param name="jToken"></param>
        /// <param name="verificationMethod"></param>
        /// <returns></returns>
        protected override ISigner GetSigner(JToken verificationMethod)
        {
            return new Ed25519VerificationKey2018(verificationMethod as JObject);
        }
    }
}