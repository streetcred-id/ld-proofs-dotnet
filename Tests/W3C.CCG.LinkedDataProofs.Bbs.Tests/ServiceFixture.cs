﻿using System;
using Microsoft.Extensions.DependencyInjection;
using W3C.CCG.LinkedDataProofs;
using Xunit;
using W3C.CCG.SecurityVocabulary;

namespace LinkedDataProofs.Bbs.Tests
{
    [CollectionDefinition(CollectionDefinitionName)]
    public class ServiceFixture : ICollectionFixture<ServiceFixture>
    {
        public const string CollectionDefinitionName = "Service Collection";

        public ServiceFixture()
        {
            CachingDocumentLoader.Default.AddCached("https://w3c-ccg.github.io/ldp-bbs2020/contexts/v1", Utilities.LoadJson("Data/ldp-bbs2020.jsonld"));
        }
    }
}
