﻿using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace LinkedDataProofs
{
    public abstract class JwsLinkedDataSignature : LinkedDataSignature
    {
        public ISigner Signer { get; set; }
        public abstract string Algorithm { get; }

        protected JwsLinkedDataSignature(string typeName) : base(typeName)
        {
        }

        /// <inheritdoc />
        protected override Task<JObject> SignAsync(IVerifyData payload, JObject proof, ProofOptions options)
        {
            var verifyData = payload as ByteArray ?? throw new ArgumentException("Invalid data type");

            // JWS header
            var header = new JObject
            {
                { "alg", Algorithm },
                { "b64", false },
                { "crit", JArray.Parse("[\"b64\"]") }
            };

            /*
            +-------+-----------------------------------------------------------+
            | "b64" | JWS Signing Input Formula                                 |
            +-------+-----------------------------------------------------------+
            | true  | ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||     |
            |       | BASE64URL(JWS Payload))                                   |
            |       |                                                           |
            | false | ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.') ||    |
            |       | JWS Payload                                               |
            +-------+-----------------------------------------------------------+
            */

            // create JWS data and sign
            var encodedHeader = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header)));
            var data = (ByteArray)Encoding.ASCII.GetBytes($"{encodedHeader}.")
                .Concat(verifyData.Data)
                .ToArray();
            var signature = Signer.Sign(data);

            // create detached content signature
            var encodedSignature = Convert.ToBase64String(signature);
            proof["jws"] = $"{encodedHeader}..{encodedSignature}";

            return Task.FromResult(proof);
        }

        protected override Task VerifyAsync(IVerifyData payload, JToken proof, JToken verificationMethod, ProofOptions options)
        {
            var verifyData = payload as ByteArray ?? throw new ArgumentException("Invalid data type");

            if (proof["jws"] == null || !proof["jws"].ToString().Contains(".."))
            {
                throw new Exception("The proof does not include a valid 'jws' property.");
            }
            var parts = proof["jws"].ToString().Split("..");
            var (encodedHeader, encodedSignature) = (parts.First(), parts.Last());

            var header = JObject.Parse(Encoding.UTF8.GetString(Helpers.FromBase64String(encodedHeader)));
            if (header["alg"]?.ToString() != Algorithm)
            {
                throw new Exception($"Invalid JWS header parameters for ${TypeName}.");
            }
            var signature = Helpers.FromBase64String(encodedSignature);

            var data = (ByteArray)Encoding.ASCII.GetBytes($"{encodedHeader}.")
                .Concat(verifyData.Data)
                .ToArray();
            var signer = GetSigner(verificationMethod);

            var valid = signer.Verify(signature, data);
            if (!valid)
            {
                throw new Exception("Invalid signature");
            }
            return Task.CompletedTask;
        }

        public string Encode(string input)
        {
            byte[] encbuff = Encoding.UTF8.GetBytes(input ?? "");
            return Convert.ToBase64String(encbuff).Replace("=", ",").Replace("+", "-").Replace("/", "_");
        }

        protected abstract ISigner GetSigner(JToken verificationMethod);
    }
}
