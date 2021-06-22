using System;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using VDS.RDF.JsonLd;
using W3C.CCG.DidCore;
using LinkedDataProofs;
using LinkedDataProofs.Purposes;

namespace W3C.CCG.AuthorizationCapabilities
{
    public class CapabilityInvocation : ControllerPurpose
    {
        public CapabilityInvocation() : base("capabilityInvocation")
        {
        }

        public CapabilityInvocation(PurposeOptions options) : base("capabilityInvocation")
        {
            Options = options;
        }

        public override async Task<LinkedDataProofs.Purposes.ValidationResult> ValidateAsync(JToken proof, ProofOptions options)
        {
            if (proof["capability"] is null)
            {
                throw new Exception("'capability' was not found in the capability invocation proof.");
            }

            if (Options?.ExpectedTarget == null)
            {
                throw new ArgumentNullException("ExpectedTarget is required.");
            }

            // 1. get the capability in the security v2 context
            var result = await Utils.FetchInSecurityContextAsync(proof["capability"], false, new JsonLdProcessorOptions
            {
                CompactToRelative = false,
                DocumentLoader = options.DocumentLoader.Load
            });
            var capability = new CapabilityDelegation(result as JObject);

            // 2. verify the capability delegation chain
            await Utils.VerifyCapabilityChain(capability, Options);

            // 3. verify the invoker...
            // authorized invoker must match the verification method itself OR
            // the controller of the verification method
            if (!capability.HasInvoker(new VerificationMethod(Options.VerificationMethod)))
            {
                throw new Exception("The authorized invoker does not match the " +
                    "verification method or its controller.");
            }

            var validateResult = await base.ValidateAsync(proof, options);

            validateResult.Invoker = validateResult.Controller;
            validateResult.Controller = null;

            return validateResult;
        }

        public override async Task<JObject> UpdateAsync(JObject proof, ProofOptions options)
        {
            if (Options?.Capability == null)
            {
                throw new Exception("'capability' is required.");
            }

            proof = await base.UpdateAsync(proof, options);

            proof["capability"] = Options.Capability;
            if (Options.CapabilityAction != null)
            {
                proof["capabilityAction"] = Options.CapabilityAction;
            }
            return proof;
        }
    }
}
