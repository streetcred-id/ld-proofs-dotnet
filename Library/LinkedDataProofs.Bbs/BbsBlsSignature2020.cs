using BbsSignatures;
using Multiformats.Base;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Threading.Tasks;
using W3C.CCG.SecurityVocabulary;

namespace LinkedDataProofs.Bbs
{
    public class BbsBlsSignature2020 : LinkedDataSignature
    {
        public const string Name = "sec:BbsBlsSignature2020";

        public IBbsSignatureService SignatureService { get; }
        public BlsKeyPair KeyPair { get; set; }

        public BbsBlsSignature2020() : base(Name)
        {
            SignatureService = new BbsSignatureService();
            InitialProof = new JObject
            {
                { "@context", Constants.SECURITY_CONTEXT_V3_URL },
                { "type", "BbsBlsSignature2020" }
            };
        }

        protected override Task<JObject> SignAsync(IVerifyData payload, JObject proof, ProofOptions options)
        {
            var verifyData = payload as StringArray ?? throw new ArgumentException("Invalid data type");

            if (KeyPair?.SecretKey == null)
            {
                throw new Exception("Private key not found.");
            }
            
            var proofValue = SignatureService.Sign(new SignRequest(KeyPair, verifyData.Data));
            proof["proofValue"] = Convert.ToBase64String(proofValue);
            proof["type"] = "BbsBlsSignature2020";

            return Task.FromResult(proof);
        }

        protected override Task VerifyAsync(IVerifyData payload, JToken proof, JToken verificationMethod, ProofOptions options)
        {
            var verifyData = payload as StringArray ?? throw new ArgumentException("Invalid data type");

            var blsVerificationMethod = new Bls12381G2Key2020(verificationMethod as JObject);

            var key = new BlsKeyPair(Multibase.Base58.Decode(blsVerificationMethod.PublicKeyBase58));
            var signature = Helpers.FromBase64String(proof["proofValue"]?.ToString() ?? throw new Exception("Proof value not found"));

            var valid = SignatureService.Verify(new VerifyRequest(key, signature, verifyData.Data));
            if (!valid)
            {
                throw new Exception("Invalid signature");
            }
            return Task.CompletedTask;
        }

        protected override IVerifyData CreateVerifyData(JObject proof, ProofOptions options)
        {
            var processorOptions = options.GetProcessorOptions();

            var c14nProofOptions = Helpers.CanonizeProofStatements(proof, processorOptions);
            var c14nDocument = Helpers.CanonizeStatements(options.Input, processorOptions);

            return (StringArray)c14nProofOptions.Concat(c14nDocument).ToArray();
        }
    }
}
