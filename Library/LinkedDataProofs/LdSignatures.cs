using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using VDS.RDF.JsonLd;
using LinkedDataProofs.Purposes;
using W3C.CCG.SecurityVocabulary;
using W3C.CCG.DidCore;
using System.Linq;

namespace LinkedDataProofs
{
    public class LdSignatures
    {
        /// <summary>
        /// Cryptographically signs the provided document by adding a `proof` section,
        /// based on the provided suite and proof purpose.
        /// </summary>
        /// <param name="document"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public static async Task<JToken> SignAsync(JToken document, ProofOptions options)
        {
            if (options.Purpose is null) throw new Exception("Proof purpose is required.");
            if (options.Suite is null) throw new Exception("Suite is required.");

            options.AdditonalData["originalDocument"] = document;
            var documentCopy = document.DeepClone();

            documentCopy = options.CompactProof
                ? JsonLdProcessor.Compact(documentCopy, Constants.SECURITY_CONTEXT_V2_URL, options.GetProcessorOptions())
                : document.DeepClone();
            documentCopy.Remove("proof");

            // create the new proof (suites MUST output a proof using the security-v2
            // `@context`)
            options.Input = documentCopy;
            var proof = await options.Suite.CreateProofAsync(options);

            // TODO: Check compaction again
            proof.Proof.Remove("@context");

            var result = proof.UpdatedDocument ?? document.DeepClone();
            result["proof"] = proof.Proof;
            return result;
        }

        /// <summary>
        /// Verifies the linked data signature on the provided document.
        /// </summary>
        /// <param name="document"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public static async Task<ValidationResult> VerifyAsync(JToken document, ProofOptions options)
        {
            if (options.Purpose is null) throw new Exception("Purpose is required.");
            if (options.Suite is null) throw new Exception("Suite is required.");

            options.AdditonalData["originalDocument"] = document.DeepClone();

            // shallow copy to allow for removal of proof set prior to canonize
            var input = document.Type == JTokenType.String
                ? await options.DocumentLoader.LoadAsync(document.ToString())
                : document.DeepClone();

            var (proof, doc) = GetProof(input, options);

            var result = await options.Suite.VerifyProofAsync(proof, new ProofOptions
            {
                Suite = options.Suite,
                Purpose = options.Purpose,
                CompactProof = options.CompactProof,
                AdditonalData = options.AdditonalData,
                DocumentLoader = options.DocumentLoader,
                Input = doc
            });

            return result;
        }

        /// <summary>
        /// Get a proof from a signed document
        /// </summary>
        /// <param name="document"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public static (JToken proof, JToken document) GetProof(JToken document, ProofOptions options)
        {
            var documentCopy = options.CompactProof
                ? JsonLdProcessor.Compact(
                    input: document,
                    context: Constants.SECURITY_CONTEXT_V2_URL,
                    options: options.GetProcessorOptions())
                : document.DeepClone();

            var proof = documentCopy["proof"].DeepClone();
            document.Remove("proof");

            if (proof == null)
            {
                throw new Exception("No matching proofs found in the given document.");
            }

            proof["@context"] = Constants.SECURITY_CONTEXT_V2_URL;

            return (proof, document);
        }

        /// <summary>
        /// Returns <c>true/c> if the input document contains proof
        /// </summary>
        /// <param name="document"></param>
        /// <returns></returns>
        public static bool HasProof(JToken document) => document["proof"].HasValues;

        public static IEnumerable<VerificationMethod> FindVerificationMethods(DidDocument didDocument, string proofPurpose, IDocumentLoader documentLoader)
        {
            var processorOptions = new JsonLdProcessorOptions { DocumentLoader = documentLoader.Load };
            processorOptions.ExpandContext = Constants.SECURITY_CONTEXT_V2_URL;

            var result = JsonLdProcessor.Frame(
                input: didDocument,
                frame: new JObject
                {
                    { "@context", Constants.SECURITY_CONTEXT_V2_URL },
                    { "@explicit", true },
                    { proofPurpose, new JObject { { "@embed", "@always" } }
                    }
                },
                options: processorOptions);

            if (result[proofPurpose] == null || !(result[proofPurpose] is JArray purposes))
            {
                throw new Exception($"No verification keys found for prupose `{proofPurpose}`");
            }

            return purposes.Select(x => new VerificationMethod(x as JObject)).ToList();
        }
    }
}