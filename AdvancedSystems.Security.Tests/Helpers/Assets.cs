using System;
using System.IO;

namespace AdvancedSystems.Security.Tests.Helpers;

internal static class Assets
{
    internal static string ProjectRoot
    {
        get
        {
            DirectoryInfo projectRoot = Directory.GetParent(Environment.CurrentDirectory)?.Parent?.Parent?.Parent
                ?? throw new DirectoryNotFoundException("Failed to locate the project root directory.");

            return projectRoot.FullName;
        }
    }
}