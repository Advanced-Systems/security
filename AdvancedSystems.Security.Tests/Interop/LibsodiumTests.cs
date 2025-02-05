using System;

using AdvancedSystems.Security.Cryptography;

using Xunit;

namespace AdvancedSystems.Security.Tests.Interop;

/// <summary>
///     Tests that the interop code from <c>libsodium</c> can be invoked without
///     failure through the <seealso cref="Libsodium"/> class.
/// </summary>
public sealed class LibsodiumTests
{
    #region Tests

    /// <summary>
    ///     Tests that <seealso cref="Libsodium.Version"/> returns the latest stable
    ///     version of the <c>libsodium</c> NuGet package.
    /// </summary>
    [Fact]
    public void TestVersion()
    {
        // Arrange
        var expectedVersion = new Version(1, 0, 20);

        // Act
        Version actualVersion = Libsodium.Version;

        // Assert
        Assert.Equal(expectedVersion, actualVersion);
    }

    /// <summary>
    ///     Tests that <seealso cref="Libsodium.MajorVersion"/> returns the latest
    ///     major version of the underlying <c>libsodium</c> DLL.
    /// </summary>
    [Fact]
    public void TestMajorVersion()
    {
        // Arrange
        int expectedMajorVersion = 26;

        // Act
        int actualMajorVersion = Libsodium.MajorVersion;

        // Assert
        Assert.Equal(expectedMajorVersion, actualMajorVersion);
    }

    /// <summary>
    ///     Tests that <seealso cref="Libsodium.MinorVersion"/> returns the latest
    ///     minor version of the underlying <c>libsodium</c> DLL.
    /// </summary>
    [Fact]
    public void TestMinorVersion()
    {
        // Arrange
        int expectedMinorVersion = 2;

        // Act
        int actualMinorVersion = Libsodium.MinorVersion;

        // Assert
        Assert.Equal(expectedMinorVersion, actualMinorVersion);
    }

    #endregion
}