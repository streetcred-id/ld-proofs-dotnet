using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using VDS.RDF.JsonLd;
using W3C.CCG.DidCore;
using LinkedDataProofs.Purposes;
using W3C.CCG.SecurityVocabulary;

namespace LinkedDataProofs
{
    public abstract class LinkedDataSignature : LinkedDataProof
    {
        public LinkedDataSignature(string typeName) : base(typeName)
        {
        }

        /// <summary>
        /// Gets or sets the initial proof object to use.
        /// Can be null.
        /// </summary>
        public JObject InitialProof { get; set; }

        /// <summary>
        /// Gets or sets the verification method to use for this proof
        /// </summary>
        public string VerificationMethod { get; set; }

        /// <summary>
        /// Gets or sets the 'created' date to use in this proof
        /// </summary>
        public DateTime? Date { get; set; }

        /// <summary>
        /// Create proof
        /// </summary>
        /// <param name="options"></param>
        /// <returns></returns>
        public override async Task<ProofResult> CreateProofAsync(ProofOptions options)
        {
            if (VerificationMethod == null) throw new ArgumentNullException(nameof(VerificationMethod), "VerificationMethod must be specified.");
            if (TypeName == null) throw new ArgumentNullException(nameof(TypeName), "TypeName must be specified.");

            var proof = InitialProof != null
                ? JsonLdProcessor.Compact(InitialProof, Constants.SECURITY_CONTEXT_V2_URL, options.GetProcessorOptions())
                : new JObject { { "@context", Constants.SECURITY_CONTEXT_V2_URL } };

            proof["type"] = TypeName;
            proof["created"] = Date.HasValue ? Date.Value.ToString("s") : DateTime.Now.ToString("s");
            proof["verificationMethod"] = VerificationMethod;

            // allow purpose to update the proof; the `proof` is in the
            // SECURITY_CONTEXT_URL `@context` -- therefore the `purpose` must
            // ensure any added fields are also represented in that same `@context`
            proof = await options.Purpose.UpdateAsync(proof, options);

            // create data to sign
            var verifyData = CreateVerifyData(proof, options);

            // sign data
            proof = await SignAsync(verifyData, proof, options);
            return new ProofResult { Proof = proof };
        }

        public override async Task<ValidationResult> VerifyProofAsync(JToken proof, ProofOptions options)
        {
            var verifyData = CreateVerifyData(proof as JObject, options);
            var verificationMethod = GetVerificationMethod(proof as JObject, options);

            await VerifyAsync(verifyData, proof, verificationMethod, options);

            // Validate proof purpose
            options.Purpose.Options.VerificationMethod = new VerificationMethod(verificationMethod);
            return await options.Purpose.ValidateAsync(proof, options);
        }

        /// <summary>
        /// Signs the verification data for the current proof
        /// </summary>
        /// <param name="verifyData"></param>
        /// <param name="proof"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        protected abstract Task<JObject> SignAsync(IVerifyData verifyData, JObject proof, ProofOptions options);

        /// <summary>
        /// Verifies the verification data for the current proof
        /// </summary>
        /// <param name="verifyData"></param>
        /// <param name="proof"></param>
        /// <param name="verificationMethod"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        protected abstract Task VerifyAsync(IVerifyData verifyData, JToken proof, JToken verificationMethod, ProofOptions options);

        #region Private methods

        protected VerificationMethod GetVerificationMethod(JObject proof, ProofOptions options)
        {
            var verificationMethod = proof["verificationMethod"] ?? throw new Exception("No 'verificationMethod' found in proof.");

            var verificationMethodId = verificationMethod.Type switch
            {
                JTokenType.String => verificationMethod.ToString(),
                JTokenType.Object => verificationMethod["id"]?.ToString() ?? throw new Exception("Verification Method found, but it's 'id' property was empty"),
                _ => throw new Exception($"Invalid verification method type: {verificationMethod.Type}")
            };
            var processorOptions = options.GetProcessorOptions();
            processorOptions.ExpandContext = Constants.SECURITY_CONTEXT_V2_URL;

            var result = JsonLdProcessor.Frame(
                verificationMethodId,
                new JObject
                {
                    { "@context", Constants.SECURITY_CONTEXT_V2_URL },
                    { "@embed", "@always" },
                    { "id", verificationMethod }
                },
                processorOptions);

            if (result == null || result["id"] == null)
            {
                throw new Exception($"Verification method {verificationMethod} not found.");
            }

            if (result["revoked"] != null)
            {
                throw new Exception("The verification method has been revoked.");
            }

            return new VerificationMethod(result);
        }

        protected virtual IVerifyData CreateVerifyData(JObject proof, ProofOptions options)
        {
            var processorOptions = options.GetProcessorOptions();

            var c14nProofOptions = Helpers.CanonizeProof(proof, processorOptions);
            var c14nDocument = Helpers.Canonize(options.Input, processorOptions);

            var sha256 = SHA256.Create();

            return (ByteArray)sha256.ComputeHash(Encoding.UTF8.GetBytes(c14nProofOptions))
                .Concat(sha256.ComputeHash(Encoding.UTF8.GetBytes(c14nDocument)))
                .ToArray();
        }

        #endregion
    }
}
