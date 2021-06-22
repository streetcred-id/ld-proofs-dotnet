
using System;
using System.Collections.Generic;
using System.Linq;
using VDS.RDF.JsonLd;
using W3C.CCG.SecurityVocabulary;

namespace Microsoft.Extensions.DependencyInjection
{
    //public static class ServiceCollectionExtensions
    //{
    //    public static IServiceCollection AddLinkedDataProofs(this IServiceCollection services, Action<ILinkedDataProofsBuilder> configure = null)
    //    {
    //        var builder = new DefaultLinkedDataProofsBuilder(services);

    //        configure?.Invoke(builder);

    //        services.TryAddSingleton<ISuiteFactory, DefaultSuiteFactory>();
    //        services.TryAddSingleton<ILinkedDataProofService, DefaultLinkedDataProofService>();
    //        services.TryAddSingleton<IDocumentLoader, CustomDocumentLoader>();

    //        return services;
    //    }
    //}

    //public interface ILinkedDataProofsBuilder
    //{
    //    IServiceCollection Services { get; }
    //}

    //internal class DefaultLinkedDataProofsBuilder : ILinkedDataProofsBuilder
    //{
    //    public DefaultLinkedDataProofsBuilder(IServiceCollection services)
    //    {
    //        Services = services;
    //    }

    //    public IServiceCollection Services { get; }
    //}
}

namespace Newtonsoft.Json.Linq
{
    public static class JTokenExtensions
    {
        public static (JToken, IEnumerable<JObject>) GetProofs(this JToken document, JsonLdProcessorOptions options, bool compactProof = true, string proofPropertyName = "proof")
        {
            if (compactProof)
            {
                document = JsonLdProcessor.Compact(document, Constants.SECURITY_CONTEXT_V2_URL, options);
            }
            var proofs = document[proofPropertyName];
            (document as JObject).Remove(proofPropertyName);

            return (document, proofs switch
            {
                JObject _ => new[] { proofs as JObject },
                JArray _ => proofs.Select(x => x as JObject),
                _ => throw new Exception("Unexpected proof type")
            });
        }

        /// <summary>
        /// Cast a <see cref="JToken"/> to <see cref="JObject"/> and remove the property name
        /// </summary>
        /// <param name="token"></param>
        /// <param name="propertyName"></param>
        public static void Remove(this JToken token, string propertyName) => (token as JObject).Remove(propertyName);
    }
}