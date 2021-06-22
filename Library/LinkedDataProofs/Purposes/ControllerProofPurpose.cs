using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using VDS.RDF.JsonLd;
using W3C.CCG.SecurityVocabulary;

namespace LinkedDataProofs.Purposes
{
    public class ControllerPurpose : ProofPurpose
    {
        public ControllerPurpose(string term) : base(term)
        {
        }

        public string Controller { get; set; }

        public override async Task<ValidationResult> ValidateAsync(JToken proof, ProofOptions options)
        {
            var result = await base.ValidateAsync(proof, options);

            var verificationMethodId = Options.VerificationMethod["id"].ToString();
            var controllerId = Controller ?? GetVerificationMethod() ??
                throw new ProofValidationException("Controller or VerificationMethod not found");

            var framed = JsonLdProcessor.Frame(
                controllerId,
                new JObject
                {
                    { "@context", Constants.SECURITY_CONTEXT_V2_URL },
                    { "id", controllerId },
                    { Term, new JObject
                        {
                            { "@embed", "@never" },
                            { "id", verificationMethodId }
                        }
                    }
                },
                options.GetProcessorOptions());

            if (framed[Term] is JArray keys && keys.Any(x => x.ToString() == verificationMethodId))
            {
                result.Controller = framed["id"].ToString();
                return result;
            }

            throw new ProofValidationException($"Verification method '{verificationMethodId}' not authorized " +
                $"by controller for proof purpose '{Term}'.");
        }

        private string GetVerificationMethod()
        {
            if (Options?.VerificationMethod["controller"] != null)
            {
                switch (Options.VerificationMethod["controller"].Type)
                {
                    case JTokenType.String: return Options.VerificationMethod["controller"].ToString();
                    case JTokenType.Object: return Options.VerificationMethod["controller"]["id"]?.ToString();
                    default:
                        break;
                }
            }
            throw new ProofValidationException("Verification Method not found");
        }
    }
}
