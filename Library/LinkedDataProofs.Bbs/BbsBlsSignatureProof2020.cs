using BbsSignatures;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using VDS.RDF.JsonLd;
using W3C.CCG.SecurityVocabulary;
using System.Text;

namespace LinkedDataProofs.Bbs
{
    public class BbsBlsSignatureProof2020 : LinkedDataSignature
    {
        public const string Name = "sec:BbsBlsSignatureProof2020";

        public BbsBlsSignatureProof2020() : base(Name)
        {
            Service = new BbsSignatureService();
        }

        private BbsSignatureService Service { get; }
        public JToken RevealDocument { get; set; }
        public BlsKeyPair KeyPair { get; set; }
        public byte[] Nonce { get; set; }

        public override async Task<ProofResult> CreateProofAsync(ProofOptions options)
        {
            VerificationMethod = options.AdditonalData["originalDocument"]["proof"]["verificationMethod"].ToString();

            var result = await base.CreateProofAsync(options);

            result.UpdatedDocument = options.AdditonalData["revealDocument"] as JObject;
            return result;
        }

        /// <inheritdoc />
        protected override IVerifyData CreateVerifyData(JObject proof, ProofOptions options)
        {
            var originalProof = options.AdditonalData["originalDocument"]["proof"].DeepClone() as JObject;
            originalProof["type"] = "BbsBlsSignature2020";

            var processorOptions = options.GetProcessorOptions();

            var proofStatements = Helpers.CanonizeProofStatements(originalProof, processorOptions, Constants.SECURITY_CONTEXT_V3_URL);
            var documentStatements = Helpers.CanonizeStatements(options.Input, processorOptions);

            var numberOfProofStatements = proofStatements.Count();

            // if RevealDocument is present, this is a proof derivation
            // apply transformation of blank node to urn:bnid format
            if (RevealDocument != null)
            {
                var transformedInputDocumentStatements = documentStatements.Select(TransformBlankNodeToId).ToArray();
                var compactInputDocument = Helpers.FromRdf(transformedInputDocumentStatements);

                var revealDocument = JsonLdProcessor.Frame(compactInputDocument, RevealDocument, processorOptions);
                var revealDocumentStatements = Helpers.CanonizeStatements(revealDocument, processorOptions);

                options.AdditonalData["revealDocument"] = revealDocument;

                var documentRevealIndicies = revealDocumentStatements.Select(x => Array.IndexOf(transformedInputDocumentStatements, x) + numberOfProofStatements).ToArray();

                if (documentRevealIndicies.Count() != revealDocumentStatements.Count())
                {
                    throw new Exception("Some statements in the reveal document not found in original proof");
                }

                var proofRevealIndicies = new int[numberOfProofStatements].Select((_, x) => x).ToArray();
                var revealIndicies = proofRevealIndicies.Concat(documentRevealIndicies);

                options.AdditonalData["revealIndicies"] = new JArray(revealIndicies.ToArray());
            }
            else
            {
                // it's proof verification, apply transform id to blank node
                documentStatements = documentStatements.Select(TransformIdToBlankNode);
            }
            
            var allInputStatements = proofStatements.Concat(documentStatements);

            return (StringArray)allInputStatements.ToArray();
        }

        /// <inheritdoc />
        protected override Task<JObject> SignAsync(IVerifyData verifyData, JObject proof, ProofOptions options)
        {
            var verifyDataArray = verifyData as StringArray ?? throw new Exception("Unsupported verify data type");

            var derivedProof = new JObject { { "@context", Constants.SECURITY_CONTEXT_V3_URL } };
            var originalProof = options.AdditonalData["originalDocument"]["proof"];
            var signature = Convert.FromBase64String(originalProof["proofValue"].ToString());

            var keyPair = new Bls12381G2Key2020(GetVerificationMethod(originalProof as JObject, options));
            var bbsKey = keyPair.ToBlsKeyPair().GetBbsKey((uint)verifyDataArray.Data.Length);
            var nonce = Nonce ?? Encoding.UTF8.GetBytes(Guid.NewGuid().ToString());

            var proofMessages = GetProofMessages(
                allInputStatements: verifyDataArray.Data,
                revealIndicies: options.AdditonalData["revealIndicies"].ToObject<int[]>());

            var outputProof = Service.CreateProof(new CreateProofRequest(
                publicKey: bbsKey,
                messages: proofMessages.ToArray(),
                signature: signature,
                blindingFactor: null,
                nonce: nonce));

            // Set the proof value on the derived proof
            derivedProof["proofValue"] = Convert.ToBase64String(outputProof);
            derivedProof["nonce"] = Convert.ToBase64String(nonce);
            derivedProof["created"] = originalProof["created"];
            derivedProof["proofPurpose"] = originalProof["proofPurpose"];
            derivedProof["verificationMethod"] = originalProof["verificationMethod"];
            derivedProof["type"] = "BbsBlsSignatureProof2020";

            return Task.FromResult(derivedProof);
        }

        /// <inheritdoc />
        protected override Task VerifyAsync(IVerifyData verifyData, JToken proof, JToken verificationMethod, ProofOptions options)
        {
            var stringArray = verifyData as StringArray ?? throw new Exception("Unsupported verify data type");

            var proofData = Helpers.FromBase64String(proof["proofValue"]?.ToString() ?? throw new Exception("Proof value not found"));
            var nonce = Helpers.FromBase64String(proof["nonce"]?.ToString() ?? throw new Exception("Nonce not found"));
            var keyPair = new Bls12381G2Key2020(GetVerificationMethod(proof as JObject, options));

            var messageCount = Service.GetTotalMessageCount(proofData);

            var verifyResult = Service.VerifyProof(new VerifyProofRequest(
                publicKey: keyPair.ToBlsKeyPair().GetBbsKey((uint)messageCount),
                proof: proofData,
                messages: stringArray.Data,
                nonce: nonce));

            if (!verifyResult)
            {
                throw new Exception("Invalid signature proof");
            }
            return Task.CompletedTask;
        }

        #region Private methods

        private IEnumerable<ProofMessage> GetProofMessages(string[] allInputStatements, int[] revealIndicies) => allInputStatements
            .Select((statement, index) => new ProofMessage
            {
                Message = statement,
                ProofType = revealIndicies.Contains(index) ? ProofMessageType.Revealed : ProofMessageType.HiddenProofSpecificBlinding
            });

        private string TransformBlankNodeToId(string element)
        {
            var nodeIdentifier = element.Split(" ").First();
            if (nodeIdentifier.StartsWith("_:c14n"))
            {
                return element.Replace(
                    oldValue: nodeIdentifier,
                    newValue: $"<urn:bnid:{nodeIdentifier}>");
            }
            return element;
        }

        private string TransformIdToBlankNode(string element)
        {
            var prefixString = "<urn:bnid:";
            if (element.Contains("<urn:bnid:_:c14n", StringComparison.OrdinalIgnoreCase))
            {
                var prefixIndex = element.IndexOf(prefixString);
                var closingIndex = element.IndexOf(">", prefixIndex);
                return element.Replace(
                  element.Substring(prefixIndex, closingIndex + 1 - prefixIndex),
                  element.Substring(prefixIndex + prefixString.Length, closingIndex - prefixIndex - prefixString.Length)
                );
            }
            return element;
        }

        #endregion

    }
}
