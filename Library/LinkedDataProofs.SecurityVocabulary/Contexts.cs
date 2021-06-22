using System.IO;
using System.Reflection;
using Newtonsoft.Json.Linq;

namespace W3C.CCG.SecurityVocabulary
{
    public class Contexts
    {
        public static JObject SecurityContextV1 = LoadFromResource("LinkedDataProofs.SecurityVocabulary.Data.security-v1.jsonld");

        public static JObject SecurityContextV2 = LoadFromResource("LinkedDataProofs.SecurityVocabulary.Data.security-v2.jsonld");

        public static JObject SecurityContextV3 = LoadFromResource("LinkedDataProofs.SecurityVocabulary.Data.security-v3-unstable.jsonld");

        public static JObject SecurityContextBbsV1 = LoadFromResource("LinkedDataProofs.SecurityVocabulary.Data.security-bbs-v1.jsonld");

        public static JObject DidContextV1 = LoadFromResource("LinkedDataProofs.SecurityVocabulary.Data.did-v1.jsonld");

        private static JObject LoadFromResource(string resourceName)
        {
            var assembly = Assembly.GetExecutingAssembly();

            using var resourceStream = assembly.GetManifestResourceStream(resourceName);
            using var reader = new StreamReader(resourceStream);

            return JObject.Parse(reader.ReadToEnd());
        }
    }
}
