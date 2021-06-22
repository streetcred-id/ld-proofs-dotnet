using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace W3C.CCG.DidCore
{
    public interface IDocumentResolver
    {
        /// <summary>
        /// Returns <c>true</c> if this implementation can resolve the supplied <paramref name="uri"/>
        /// </summary>
        /// <param name="uri">The document uri to resolve</param>
        /// <returns><c>true</c> if the uri can be resolved; otherwise <c>false</c></returns>
        bool CanResolve(string uri);

        /// <summary>
        /// Resolves the input <paramref name="uri"/> to a JSON document asynchronously
        /// </summary>
        /// <param name="uri">The document uri</param>
        /// <returns>The resolved document as JSON</returns>
        Task<JObject> ResolveAsync(string uri);
    }
}
