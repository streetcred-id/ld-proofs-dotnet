using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace W3C.CCG.DidCore
{

    public class DidDocument : JObject
    {
        public DidDocument(JObject obj) : base(obj)
        {
        }

        public DidDocument(string json) : this(Parse(json))
        {
        }

        public DidDocument()
        {
            Context = "https://www.w3.org/ns/did/v1";
        }

        public JToken Context
        {
            get => this["@context"];
            set => this["@context"] = value;
        }

        public string Id
        {
            get => this["id"]?.Value<string>();
            set => this["id"] = value;
        }

        public IEnumerable<IVerificationMethod> VerificationMethod
        {
            get => GetVerificationMethods("verificationMethod");
            set => this["verificationMethod"] = new JArray(value);
        }

        public IEnumerable<IVerificationMethod> Authentication
        {
            get => GetVerificationMethods("authentication");
            set => this["authentication"] = new JArray(value);
        }

        public IEnumerable<IVerificationMethod> AssertionMethod
        {
            get => GetVerificationMethods("assertionMethod");
            set => this["assertionMethod"] = new JArray(value);
        }

        public IEnumerable<IVerificationMethod> CapabilityDelegation
        {
            get => GetVerificationMethods("capabilityDelegation");
            set => this["capabilityDelegation"] = new JArray(value);
        }

        public IEnumerable<IVerificationMethod> CapabilityInvocation
        {
            get => GetVerificationMethods("capabilityInvocation");
            set => this["capabilityInvocation"] = new JArray(value);
        }

        public IEnumerable<IVerificationMethod> KeyAgreement
        {
            get => GetVerificationMethods("keyAgreement");
            set => this["keyAgreement"] = new JArray(value);
        }

        public string Controller
        {
            get => this["controller"]?.Value<string>();
            set => this["controller"] = value;
        }

        [JsonProperty("service", NullValueHandling = NullValueHandling.Ignore)]
        public IEnumerable<ServiceEndpoint> Service { get; set; }

        public DateTimeOffset? Created
        {
            get => this["created"]?.Value<DateTimeOffset>();
            set => this["created"] = value;
        }

        public DateTimeOffset? Updated
        {
            get => this["updated"]?.Value<DateTimeOffset>();
            set => this["updated"] = value;
        }

        #region Private methods

        private IEnumerable<IVerificationMethod> GetVerificationMethods(string propertyName)
        {
            if (this[propertyName] is JArray array)
            {
                foreach (var item in array)
                {
                    yield return item switch
                    {
                        JValue property => new VerificationMethodReference(property.Value<string>()),
                        JObject property => new VerificationMethod(property),
                        _ => throw new ArgumentException($"Unrecognized object type: {item.Type}")
                    };
                }
            }
        }

        #endregion
    }
}
