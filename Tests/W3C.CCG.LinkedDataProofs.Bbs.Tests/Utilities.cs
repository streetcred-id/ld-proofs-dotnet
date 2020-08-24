﻿using System;
using System.IO;
using Newtonsoft.Json.Linq;

namespace LinkedDataProofs.Bbs.Tests
{
    public class Utilities
    {
        public static JObject LoadJson(string filename) => JObject.Parse(File.ReadAllText(filename));
    }
}
