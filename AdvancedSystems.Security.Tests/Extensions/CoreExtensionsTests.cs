using System.Text;

using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;

using Xunit;

namespace AdvancedSystems.Security.Tests.Extensions;

public sealed class CoreExtensionsTests
{
    #region Tests

    [Theory]
    [InlineData("test")]
    [InlineData("Hello, World!")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    public void TestStringFormatting(string input)
    {
        // Arrange
        byte[] buffer = input.GetBytes(Format.String);

        // Act
        string fromBytes = buffer.ToString(Format.String);
        byte[] @string = fromBytes.GetBytes(Format.String);

        // Assert
        Assert.Equal(buffer, @string);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(69)]
    [InlineData(100)]
    public void TestBase64Formatting(int size)
    {
        // Arrange
        byte[] buffer = CryptoRandomProvider.GetBytes(size).ToArray();

        // Act
        string base64 = buffer.ToString(Format.Base64);
        byte[] fromBytes = base64.GetBytes(Format.Base64);

        // Assert
        Assert.Equal(buffer, fromBytes);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(69)]
    [InlineData(100)]
    public void TestHexFormatting(int size)
    {
        // Arrange
        byte[] buffer = CryptoRandomProvider.GetBytes(size).ToArray();

        // Act
        string hexadecimal = buffer.ToString(Format.Hex);
        byte[] fromBytes = hexadecimal.GetBytes(Format.Hex);

        // Assert
        Assert.Equal(buffer, fromBytes);
    }

    #endregion
}