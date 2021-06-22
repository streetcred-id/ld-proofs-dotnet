using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using VDS.RDF.JsonLd;
using W3C.CCG.DidCore;
using LinkedDataProofs;
using LinkedDataProofs.Purposes;
using W3C.CCG.SecurityVocabulary;

namespace W3C.CCG.AuthorizationCapabilities
{
    public static class Utils
    {
        /// <summary>
        /// Fetches a JSON-LD document from a URL and, if necessary, compacts it to
        /// the security v2 context.
        /// </summary>
        /// <param name="document"></param>
        /// <param name="isRoot"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public static async Task<JObject> FetchInSecurityContextAsync(JToken document, bool isRoot = false, JsonLdProcessorOptions options = null)
        {
            await Task.Yield();

            if (document.Type == JTokenType.Object &&
                document["@context"]?.Value<string>() == Constants.SECURITY_CONTEXT_V2_URL &&
                !isRoot)
            {
                return document as JObject;
            }

            return JsonLdProcessor.Compact(document, Constants.SECURITY_CONTEXT_V2_URL, options);
        }

        /// <summary>
        /// Retrieves the authorized delegators from a capability.
        /// </summary>
        /// <param name="capability">The JSON-LD document for the object capability
        /// compacted to the security context.</param>
        /// <returns>The delegators for the capability (empty for none).</returns>
        public static IEnumerable<string> GetDelegators(this CapabilityDelegation capability)
        {
            // if neither a delegator, controller, nor id is found on the capability then
            // the capability can not be delegated
            if (capability.Delegator is null || capability.Id is null)
            {
                throw new Exception("Delegator not found for capability.");
            }

            return new[] { capability.Delegator ?? capability.Id };
        }

        /// <summary>
        /// Creates a `capabilityChain` for delegating the given capability.
        /// </summary>
        /// <param name="capability"></param>
        /// <param name="processorOptions"></param>
        /// <returns></returns>
        public static Task<IEnumerable<string>> ComputeCapabilityChainAsync(JObject capability, JsonLdProcessorOptions processorOptions)
        {
            if (capability["parentCapability"] == null)
            {
                throw new Exception("Cannot compute capability chain; capability has no 'parentCapability");
            }

            // TODO
            throw new NotImplementedException("Cannot compute capability chain.");
        }

        /// <summary>
        /// Retrieves the authorized invokers from a capability.
        /// </summary>
        /// <param name="capability">The JSON-LD document for the object capability
        /// compacted to the security context.</param>
        /// <returns>The invokers for the capability (empty for none).</returns>
        public static IEnumerable<string> GetInvokers(this CapabilityDelegation capability)
        {
            // if neither a delegator, controller, nor id is found on the capability then
            // the capability can not be delegated
            if (capability.Invoker is null || capability.Id is null)
            {
                throw new Exception("Delegator not found for capability.");
            }

            return new[] { capability.Invoker ?? capability.Id };
        }

        /// <summary>
        /// Returns true if the given verification method is a delegator or is
        /// controlled by a delegator of the given capability.
        /// </summary>
        /// <param name="capability"></param>
        /// <param name="verificationMethod"></param>
        /// <returns></returns>
        public static bool HasDelegator(this CapabilityDelegation capability, VerificationMethod verificationMethod)
        {
            var delegators = capability.GetDelegators();

            return delegators.Count() > 0 &&
              (delegators.Contains(verificationMethod.Id) ||
              (verificationMethod.Controller != null && delegators.Contains(verificationMethod.Controller)));
        }

        /// <summary>
        /// Returns true if the given verification method is a invoker or is
        /// controlled by an invoker of the given capability.
        /// </summary>
        /// <param name="capability"></param>
        /// <param name="verificationMethod"></param>
        /// <returns></returns>
        public static bool HasInvoker(this CapabilityDelegation capability, VerificationMethod verificationMethod)
        {
            var invokers = capability.GetInvokers();

            return invokers.Count() > 0 &&
              (invokers.Contains(verificationMethod.Id) ||
              (verificationMethod.Controller != null && invokers.Contains(verificationMethod.Controller)));
        }

        /// <summary>
        /// Retrieves the target from a capability.
        /// </summary>
        /// <param name="capability"></param>
        /// <returns></returns>
        public static string GetTarget(JToken capability)
        {
            return capability["invocationTarget"]?.Value<string>() ?? capability["id"].Value<string>();
        }

        public static IEnumerable<JToken> GetDelegationProofs(JToken capability)
        {
            var cap = new CapabilityDelegation(capability as JObject);

            // capability is root, it has no relevant delegation proofs
            if (cap.ParentCapability == null)
            {
                return Array.Empty<JToken>();

            }
            return capability.Values("proof").Where(x =>
            {
                if (!(x["proofPurpose"]?.Value<string>() == "capabilityDelegation" &&
                    x["capabilityChain"] is JArray chain &&
                    chain.Any()))
                {
                    return false;
                }

                var last = chain.Last();
                if (last is JProperty lastProp)
                {
                    return lastProp.Value<string>() == cap.ParentCapability;
                }
                return last["id"].Value<string>() == cap.ParentCapability;
            }).ToArray();
        }

        public static IEnumerable<JToken> GetCapabilityChain(JToken capability)
        {
            if (capability["parentCapability"] == null)
            {
                // root capability has no chain
                return Array.Empty<JToken>();
            }

            var result = GetDelegationProofs(capability);

            if (!result.Any())
            {
                throw new Exception("Cannot get capability chain; capability is invalid; it is not the " +
                    "root capability yet it does not have a delegation proof.");
            }

            var chain = result.First();

            if (chain["capabilityChain"] == null)
            {
                throw new Exception("Cannot get capability chain; capability is invalid; it does not have " +
                    "a 'capabilityChain' in its delegation proof.");
            }

            return new[] { chain };
        }

        /// <summary>
        /// Verifies the capability chain, if any, attached to the given capability.
        /// </summary>
        /// <param name="capability"></param>
        /// <returns></returns>
        public static async Task<JToken> VerifyCapabilityChain(JToken capability, PurposeOptions purposeOptions, JsonLdProcessorOptions options = null)
        {
            /* Verification process is:
                1. Fetch capability if only its ID was passed.
                1.1. Ensure `capabilityAction` is allowed.
                2. Get the capability delegation chain for the capability.
                3. Validate the capability delegation chain.
                4. Verify the root capability:
                    4.1. Check the expected target, if one was specified.
                    4.2. Ensure that the caveats are met on the root capability.
                    4.3. Ensure root capability is expected and has no invocation target.
                5. If `excludeGivenCapability` is not true, then we need to verify the
                    capability delegation proof on `capability`, so add it to the chain to
                    get processed below.
                6. For each capability `cap` in the chain, verify the capability delegation
                    proof on `cap`. This will validate everything else for `cap` including
                    that caveats are met.

                Note: We start verifying a capability from its root of trust (the
                beginning or head of the capability chain) as this approach limits an
                attacker's ability to waste our time and effort traversing from the tail
                to the head.
            */

            // 1. Fetch capability if only its ID was passed.
            capability = await FetchInSecurityContextAsync(capability, false, options);
            //capability = new CapabilityDelegation(cap as JObject);

            // TODO: Add allowed action validation

            // 2. Get the capability delegation chain for the capability.
            var capabilityChain = GetCapabilityChain(capability);

            // 3. Validate the capability delegation chain.
            ValidateCapabilityChain(capability, capabilityChain);

            // 4. Verify root capability (note: it must *always* be dereferenced since
            // it does not need to have a delegation proof to vouch for its authenticity
            // ... dereferencing it prevents adversaries from submitting an invalid
            // root capability that is accepted):
            var isRoot = !capabilityChain.Any();
            var rootCapability = isRoot ? capability : capabilityChain.First();
            capabilityChain = capabilityChain.Skip(1).ToArray();

            rootCapability = await Utils.FetchInSecurityContextAsync(rootCapability, isRoot);

            // 4.1. Check the expected target, if one was specified.
            if (purposeOptions.ExpectedTarget != null)
            {
                var target = GetTarget(rootCapability);
                if (target != purposeOptions.ExpectedTarget)
                {
                    throw new Exception($"Expected target ({purposeOptions.ExpectedTarget}) does not match " +
                        $"root capability target({target}).");
                }
            }

            // 4.2. Ensure that the caveats are met on the root capability.
            // TODO: Add caveats

            // 4.3. Ensure root capability is expected and has no invocation target.

            // run root capability checks (note that these will only be run once
            // because the `verifiedParentCapability` parameter stops recursion
            // from happening below)

            // ensure that the invocation target matches the root capability or,
            // if `expectedRootCapability` is present, that it matches that
            if (purposeOptions.ExpectedRootCapability != null)
            {
                if (purposeOptions.ExpectedRootCapability != rootCapability["id"].Value<string>())
                {
                    throw new Exception($"Expected root capability ({purposeOptions.ExpectedRootCapability}) does not " +
                        $"match actual root capability({rootCapability["id"]}).");
                }
            }
            else if (GetTarget(rootCapability) != rootCapability["id"].Value<string>())
            {
                throw new Exception("The root capability must not specify a different " +
                    "invocation target.");
            }

            // root capability now verified
            var verifiedParentCapability = rootCapability;

            // if verifying a delegation proof and we're at the root, exit early
            if (isRoot)
            {
                return verifiedParentCapability;
            }

            // create a document loader that will use properly embedded capabilities
            var documentLoader = new CachingDocumentLoader(Array.Empty<IDocumentResolver>());
            var next = capabilityChain;
            while (next.Any())
            {
                // the only capability that may be embedded (if the zcap is valid) is
                // the last one in the chain, if it is embedded, add it to `dlMap` and
                // recurse into its chain and loop to collect all embedded zcaps
                var cap = next.Last();

                if (!(cap is JObject))
                {
                    break;
                }

                if (cap["@context"] == null)
                {
                    // the capabilities in the chain are already in the security context
                    // if no context has been specified
                    cap["@context"] = Constants.SECURITY_CONTEXT_V2_URL;
                }

                // Transforms the `capability` into the security context (the native
                // context this code uses) so we can process it cleanly and then
                // verifies the capability delegation proof on `capability`. This allows
                // capabilities to be expressed using custom contexts.
                cap = await FetchInSecurityContextAsync(cap, false, options);

                documentLoader.AddCached(cap["id"].Value<string>(), cap as JObject);

                next = GetCapabilityChain(cap);
            }
            options.DocumentLoader = documentLoader.Load;

            // 5. If `excludeGivenCapability` is not true, then we need to verify the
            //  capability delegation proof on `capability`, so add it to the chain to
            //  get processed below. If an `inspectCapabilityChain` handler has been
            //  provided, the verify results are required on all capabilities.
            // TODO: Add support for `excludeGivenCapability`

            // 6. For each capability `cap` in the chain, verify the capability
            //   delegation proof on `cap`. This will validate everything else for
            //   `cap` including that caveats are met.

            // note that `verifiedParentCapability` will prevent repetitive checking
            // of the same segments of the chain (once a parent is verified, its chain
            // is not checked again when checking its children)

            for (int i = 0; i < capabilityChain.Count(); i++)
            {
                var cap = capabilityChain.ElementAt(i);
                cap = await FetchInSecurityContextAsync(cap, false, options);

                var verifyResult = LdSignatures.VerifyAsync(cap, new ProofOptions
                {
                    Suite = purposeOptions.Suite,
                    Purpose = new CapabilityDelegationProofPurpose
                    {
                        Options = new PurposeOptions
                        {
                            ExpectedTarget = purposeOptions.ExpectedTarget,
                            ExpectedRootCapability = purposeOptions.ExpectedRootCapability
                        },
                        VerifiedParentCapability = verifiedParentCapability
                    },
                    DocumentLoader = documentLoader,
                    CompactProof = false
                });
            }

            return null;
        }

        public static void ValidateCapabilityChain(JToken capability, IEnumerable<JToken> capabilityChain, int maxChainLength = 10)
        {
            if (capabilityChain.Count() + 1 > maxChainLength)
            {
                throw new Exception("The capabability chain exceeds the maximum allowed length " +
                    $"of {maxChainLength}.");
            }

            var uniqueSet = new List<string>();

            // ensure there is no cycle in the chain (including `capability` itself; so
            // compare against `capabilityChain.length + 1`)
            uniqueSet.Add(capability["id"].ToString());
            if (uniqueSet.Count != (capabilityChain.Count() + 1))
            {
                throw new Exception("The capabability chain contains a cycle.");
            }
        }
    }
}
