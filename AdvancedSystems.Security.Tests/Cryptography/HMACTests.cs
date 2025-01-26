using System.Text;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;

using Xunit;

namespace AdvancedSystems.Security.Tests.Cryptography;

/// <summary>
///     Tests the public methods in <seealso cref="HMACProvider"/>.
/// </summary>
public sealed class HMACTests
{
    #region Tests

    [Theory]
    [InlineData("Hello, World!", "006255bea760447cfb4a2a83f8dcd78e", Format.Hex)]
    [InlineData("Hello, World!", "AGJVvqdgRHz7SiqD+NzXjg==", Format.Base64)]
    [InlineData("The quick brown fox jumps over the lazy dog", "39bbfdd604b4ce30df059be91ff1cfdc", Format.Hex)]
    [InlineData("The quick brown fox jumps over the lazy dog", "Obv91gS0zjDfBZvpH/HP3A==", Format.Base64)]
    public void TestMD5HMAC(string input, string expectedHash, Format format)
    {
        // Arrange
        Encoding encoding = Encoding.UTF8;
        byte[] buffer = encoding.GetBytes(input);
        byte[] key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        // Act
        byte[] hash = HMACProvider.Compute(buffer, key, HashFunction.MD5);
        string md5 = hash.ToString(format);

        // Assert
        Assert.Equal(expectedHash, md5);
    }

    [Theory]
    [InlineData("Hello, World!", "74337880adf8df0e331ba348e8a78ff3fbae4504", Format.Hex)]
    [InlineData("Hello, World!", "dDN4gK343w4zG6NI6KeP8/uuRQQ=", Format.Base64)]
    [InlineData("The quick brown fox jumps over the lazy dog", "6e5535b20cfe26e18df61b465029f379320108ff", Format.Hex)]
    [InlineData("The quick brown fox jumps over the lazy dog", "blU1sgz+JuGN9htGUCnzeTIBCP8=", Format.Base64)]
    public void TestSHA1HMAC(string input, string expectedHash, Format format)
    {
        // Arrange
        Encoding encoding = Encoding.UTF8;
        byte[] buffer = encoding.GetBytes(input);
        byte[] key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        // Act
        byte[] hash = HMACProvider.Compute(buffer, key, HashFunction.SHA1);
        string sha1 = hash.ToString(format);

        // Assert
        Assert.Equal(expectedHash, sha1);
    }

    [Theory]
    [InlineData("Hello, World!", "ac453c5917826e9a73ea7681c28b2156727432ac68477b144236b35b8507436c", Format.Hex)]
    //[InlineData("Hello, World!", "8WReCbppz6naBwoshVnJ0MqxoR3sUQjazW4UHQ2w=", Format.Base64)]
    //[InlineData("The quick brown fox jumps over the lazy dog", "b1d5f845047ccaada44062c2ba3d4f9d24572e1fc", Format.Hex)]
    //[InlineData("The quick brown fox jumps over the lazy dog", "Z39ZJXtPfbhRPKsdX4RQR8yq2kQGLCuj1PnSRXLh/", Format.Base64)]
    public void TestSHA256HMAC(string input, string expectedHash, Format format)
    {
        // Arrange
        Encoding encoding = Encoding.UTF8;
        byte[] buffer = encoding.GetBytes(input);
        byte[] key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        // Act
        byte[] hash = HMACProvider.Compute(buffer, key, HashFunction.SHA256);
        string sha256 = hash.ToString(format);

        // Assert
        Assert.Equal(expectedHash, sha256);
    }

    //[Theory]
    //[InlineData("Hello, World!", "88474536c661377c09e2f81dac464b1ad3e4caeb9", Format.Hex)]
    //[InlineData("Hello, World!", "AGJVvqdgRHz7SiqD+NzXjg==", Format.Base64)]
    //[InlineData("The quick brown fox jumps over the lazy dog", "39bbfdd604b4ce30df059be91ff1cfdc", Format.Hex)]
    //[InlineData("The quick brown fox jumps over the lazy dog", "Obv91gS0zjDfBZvpH/HP3A==", Format.Base64)]
    //public void TestSHA384HMAC(string input, string expectedHash, Format format)
    //{
    //    // Arrange
    //    Encoding encoding = Encoding.UTF8;
    //    byte[] buffer = encoding.GetBytes(input);
    //    byte[] key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    //    // Act
    //    byte[] hash = HMACProvider.Compute(buffer, key, HashFunction.SHA384);
    //    string sha384 = hash.ToString(format);

    //    // Assert
    //    Assert.Equal(expectedHash, sha384);
    //}

    //[Theory]
    //[InlineData("Hello, World!", "c752bac8d1bcb622dddfded281b3cf2acf2c988c8", Format.Hex)]
    //[InlineData("Hello, World!", "AGJVvqdgRHz7SiqD+NzXjg==", Format.Base64)]
    //[InlineData("The quick brown fox jumps over the lazy dog", "39bbfdd604b4ce30df059be91ff1cfdc", Format.Hex)]
    //[InlineData("The quick brown fox jumps over the lazy dog", "Obv91gS0zjDfBZvpH/HP3A==", Format.Base64)]
    //public void TestSHA512HMAC(string input, string expectedHash, Format format)
    //{
    //    // Arrange
    //    Encoding encoding = Encoding.UTF8;
    //    byte[] buffer = encoding.GetBytes(input);
    //    byte[] key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    //    // Act
    //    byte[] hash = HMACProvider.Compute(buffer, key, HashFunction.SHA512);
    //    string sha512 = hash.ToString(format);

    //    // Assert
    //    Assert.Equal(expectedHash, sha512);
    //}

    #endregion
}