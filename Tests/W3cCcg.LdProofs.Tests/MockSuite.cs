﻿using System;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using W3C.CCG.LinkedDataProofs;

namespace W3cCcg.LdProofs.Tests
{
    public class MockSuite : LinkedDataSignature
    {
        public MockSuite() : base("https://example.com/MockSignature")
        {
        }

        public override Task<VerifyProofResult> VerifyProofAsync(JToken proof, ProofOptions options)
        {
            throw new NotImplementedException();
        }

        protected override Task<JObject> SignAsync(byte[] verifyData, JObject proof, ProofOptions options)
        {
            proof["proofValue"] = Convert.ToBase64String(verifyData);
            return Task.FromResult(proof);
        }

        protected override Task VerifyAsync(byte[] verifyData, JToken proof, JToken verificationMethod, ProofOptions options)
        {
            throw new NotImplementedException();
        }
    }
}
