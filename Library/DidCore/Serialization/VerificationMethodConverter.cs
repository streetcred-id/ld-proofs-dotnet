using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace W3C.CCG.DidCore
{
    internal class VerificationMethodConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType) => true;

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.String)
            {
                return new VerificationMethodReference((string)reader.Value);
            }
            return new VerificationMethod(JObject.Load(reader));
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer) => throw new NotImplementedException();

        public override bool CanWrite => false;
    }
}
