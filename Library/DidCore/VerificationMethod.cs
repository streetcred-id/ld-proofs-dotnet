using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace W3C.CCG.DidCore
{
    [JsonConverter(typeof(VerificationMethodConverter))]
    public interface IVerificationMethod
    {
    }

    public class VerificationMethod : JObject, IVerificationMethod
    {
        #region ctor

        public VerificationMethod()
        {
        }

        public VerificationMethod(JObject obj) : base(obj)
        {
        }

        #endregion

        #region Public properties

        public string Id
        {
            get => this["id"]?.Value<string>();
            set => this["id"] = value;
        }

        public string TypeName
        {
            get => this["type"]?.Value<string>();
            set => this["type"] = value;
        }

        public string Controller
        {
            get => this["controller"]?.Value<string>();
            set => this["controller"] = value;
        }

        #endregion

        #region Public methods

        public virtual VerificationMethod GetPublicNode()
        {
            return new VerificationMethod((JObject)DeepClone());
        }

        #endregion
    }

    public class VerificationMethodReference : JValue, IVerificationMethod
    {
        public VerificationMethodReference(string value) : base(value)
        {
        }

        public VerificationMethodReference(VerificationMethod verificationMethod) : this(verificationMethod.Id)
        {
        }

        public static implicit operator VerificationMethodReference(string value) => new VerificationMethodReference(value);
    }
}
