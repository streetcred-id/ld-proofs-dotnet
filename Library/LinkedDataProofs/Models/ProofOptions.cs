using System.Collections.Generic;
using Newtonsoft.Json.Linq;
using VDS.RDF.JsonLd;
using LinkedDataProofs.Purposes;
using W3C.CCG.SecurityVocabulary;

namespace LinkedDataProofs
{
    public class ProofOptions
    {
        /// <summary>
        /// instructs this call to compact the resulting proof to the same JSON-LD `@context` as the input
        /// document; this is the default behavior. Setting this flag to <c>false</c> can
        /// be used as an optimization to prevent an unnecessary compaction when the
        /// caller knows that all used proof terms have the same definition in the
        /// document's `@context` as the <see cref="Constants.SECURITY_CONTEXT_V2_URL"/> `@context`
        /// </summary>
        public bool CompactProof { get; set; } = true;

        public LinkedDataProof Suite { get; set; }

        public ProofPurpose Purpose { get; set; }

        public JToken Input { get; set; }

        public IDocumentLoader DocumentLoader { get; set; }

        public IDictionary<string, JToken> AdditonalData { get; set; } = new Dictionary<string, JToken>();

        public JsonLdProcessorOptions GetProcessorOptions()
        {
            return new JsonLdProcessorOptions
            {
                CompactToRelative = false,
                DocumentLoader = DocumentLoader == null
                    ? CachingDocumentLoader.Default.Load
                    : DocumentLoader.Load
            };
        }
    }
}
