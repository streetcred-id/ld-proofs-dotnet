using Newtonsoft.Json.Linq;

namespace LinkedDataProofs.Purposes
{
    public class PurposeOptions
    {
        public string CapabilityAction { get; set; }
        public string ExpectedAction { get; set; }
        public string Capability { get; set; }
        public string ExpectedTarget { get; set; }
        public string ExpectedRootCapability { get; set; }
        public LinkedDataProof Suite { get; set; }
        public JObject VerificationMethod { get; internal set; }
    }
}
