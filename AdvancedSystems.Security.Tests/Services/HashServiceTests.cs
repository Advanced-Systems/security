using System.Text;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Tests.Fixtures;

using Xunit;

namespace AdvancedSystems.Security.Tests.Services;

public class HashServiceTests : IClassFixture<HashServiceFixture>
{
    private readonly IHashService _sut;

    public HashServiceTests(HashServiceFixture fixture)
    {
        this._sut = fixture.HashService;
    }

    [Fact]
    public void TestMD5Hash()
    {
        // Arrange
        string input = "The quick brown fox jumps over the lazy dog";
        byte[] buffer = Encoding.UTF8.GetBytes(input);

        // Act
#pragma warning disable CS0618 // Type or member is obsolete
        string md5 = this._sut.GetMD5Hash(buffer);
#pragma warning restore CS0618 // Type or member is obsolete

        // Assert
        Assert.Equal("9e107d9d372bb6826bd81d3542a419d6", md5);
    }

    [Fact]
    public void TestSHA1Hash()
    {
        // Arrange
        string input = "The quick brown fox jumps over the lazy dog";
        byte[] buffer = Encoding.UTF8.GetBytes(input);

        // Act
#pragma warning disable CS0618 // Type or member is obsolete
        string sha1 = this._sut.GetSHA1Hash(buffer);
#pragma warning restore CS0618 // Type or member is obsolete

        // Assert
        Assert.Equal("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", sha1);
    }

    [Fact]
    public void TestSHA256Hash()
    {
        // Arrange
        string input = "The quick brown fox jumps over the lazy dog";
        byte[] buffer = Encoding.UTF8.GetBytes(input);

        // Act
        string sha256 = this._sut.GetSHA256Hash(buffer);

        // Assert
        Assert.Equal("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", sha256);
    }

    [Fact]
    public void TestSHA384Hash()
    {
        // Arrange
        string input = "The quick brown fox jumps over the lazy dog";
        byte[] buffer = Encoding.UTF8.GetBytes(input);

        // Act
        string sha384 = this._sut.GetSHA384Hash(buffer);

        // Assert
        Assert.Equal("ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1", sha384);
    }

    [Fact]
    public void TestSHA512Hash()
    {
        // Arrange
        string input = "The quick brown fox jumps over the lazy dog";
        byte[] buffer = Encoding.UTF8.GetBytes(input);

        // Act
        string sha512 = this._sut.GetSHA512Hash(buffer);

        // Assert
        Assert.Equal("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6", sha512);
    }
}
