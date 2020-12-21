﻿using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using VDS.RDF.JsonLd;
using W3C.CCG.DidCore;

namespace W3C.CCG.LinkedDataProofs
{
    internal class CustomDocumentLoader : IDocumentLoader
    {
        public Dictionary<Uri, RemoteDocument> Documents = new Dictionary<Uri, RemoteDocument>();
        private readonly IEnumerable<IDidDriver> didDrivers;

        public CustomDocumentLoader(IEnumerable<IDidDriver> didDrivers)
        {
            this.didDrivers = didDrivers;
        }

        public IDocumentLoader AddCached(string uri, JObject document)
        {
            Documents.Add(new Uri(uri), new RemoteDocument { Document = document });

            return this;
        }

        public RemoteDocument Load(Uri uri, JsonLdLoaderOptions options)
        {
            foreach (var item in didDrivers)
            {
                if (item.CanResolve(uri))
                {
                    var didDocument = item.Resolve(uri);
                    return new RemoteDocument { Document = didDocument };
                }
            }
            if (Documents.TryGetValue(uri, out var document))
            {
                return document;
            }
            var doc = DefaultDocumentLoader.LoadJson(uri, options);
            Documents.TryAdd(uri, doc);
            return doc;
        }

        public Task<JObject> LoadAsync(string documentUri)
        {
            throw new NotImplementedException();
        }
    }

    public interface IDocumentLoader
    {
        IDocumentLoader AddCached(string uri, JObject document);

        Task<JObject> LoadAsync(string documentUri);

        RemoteDocument Load(Uri uri, JsonLdLoaderOptions options);
    }
}
