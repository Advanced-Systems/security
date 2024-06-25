using AdvancedSystems.Security.Common;
using AdvancedSystems.Security.Cryptography;

using System.Security.Cryptography;
using System.Text;

namespace AdvancedSystems.Security.Tests.Cryptography;

[TestFixture]
public class HashTests
{
    #region Compute(string input)

    [TestCase("Hello, World!", "65a8e27d8879283831b664bd8b7f0ad4", Format.Hex)]
    [TestCase("Hello, World!", "ZajifYh5KDgxtmS9i38K1A==", Format.Base64)]
    [TestCase("The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6", Format.Hex)]
    [TestCase("The quick brown fox jumps over the lazy dog", "nhB9nTcrtoJr2B01QqQZ1g==", Format.Base64)]
    public void TestMd5Hash(string input, string expected, Format format)
    {
        // Arrange
        Encoding encoding = Encoding.UTF8;

        // Act
        byte[] hash = Hash.Compute(input, HashAlgorithmName.MD5, encoding);
        string md5 = hash.ToString(format);

        Assert.That(md5, Is.EqualTo(expected));
    }

    [Theory]
    [TestCase("Hello, World!", "0a0a9f2a6772942557ab5355d76af442f8f65e01", Format.Hex)]
    [TestCase("Hello, World!", "CgqfKmdylCVXq1NV12r0Qvj2XgE=", Format.Base64)]
    [TestCase("The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", Format.Hex)]
    [TestCase("The quick brown fox jumps over the lazy dog", "L9ThxnotKPzthJ7hu3bnORuT6xI=", Format.Base64)]
    public void TestSHA1Hash(string input, string expected, Format format)
    {
        // Arrange
        Encoding encoding = Encoding.UTF8;

        // Act
        byte[] hash = Hash.Compute(input, HashAlgorithmName.SHA1, encoding);
        string sha1 = hash.ToString(format);

        // Assert
        Assert.That(sha1, Is.EqualTo(expected));
    }

    [TestCase("Hello, World!", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f", Format.Hex)]
    [TestCase("Hello, World!", "3/1gIbsr1bCvZ2KQgJ7DpTGR3YHH9wpLKGiKNiGCmG8=", Format.Base64)]
    [TestCase("The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", Format.Hex)]
    [TestCase("The quick brown fox jumps over the lazy dog", "16j7swfXgJRpypq8sAguT41WUeRtPNt2LQLQvzfJ5ZI=", Format.Base64)]
    public void TestSHA256Hash(string input, string expected, Format format)
    {
        // Arrange
        Encoding encoding = Encoding.UTF8;

        // Act
        byte[] hash = Hash.Compute(input, HashAlgorithmName.SHA256, encoding);
        string sha256 = hash.ToString(format);

        // Assert
        Assert.That(sha256, Is.EqualTo(expected));
    }

    [TestCase("Hello, World!", "5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515", Format.Hex)]
    [TestCase("Hello, World!", "VIXMmzNltDBd+06DN+ClmKV0+CQr8XKJ4N1sIKPNRKCJ3harSrMI9j5EsRcOtfUV", Format.Base64)]
    [TestCase("The quick brown fox jumps over the lazy dog", "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1", Format.Hex)]
    [TestCase("The quick brown fox jumps over the lazy dog", "ynN/EBSkj0wLbdQ8sXewr9nlFpNnVExJQBHjMX2/mlCcseXcHoWpQbvuPX8q+8mx", Format.Base64)]
    public void TestSHA384Hash(string input, string expected, Format format)
    {
        // Arrange
        Encoding encoding = Encoding.UTF8;

        // Act
        byte[] hash = Hash.Compute(input, HashAlgorithmName.SHA384, encoding);
        string sha384 = hash.ToString(format);

        // Assert
        Assert.That(sha384, Is.EqualTo(expected));
    }

    [TestCase("Hello, World!", "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387", Format.Hex)]
    [TestCase("Hello, World!", "N015SpXNz9izWZMYX++bo2jxYNja9DLQi6nx7R5avmzGkpHg+i/gAGpSVw7xjBne9OYXwzzlLvCm5fvjGMsDhw==", Format.Base64)]
    [TestCase("The quick brown fox jumps over the lazy dog", "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6", Format.Hex)]
    [TestCase("The quick brown fox jumps over the lazy dog", "B+VH2VhvanP3P7rAQ17XaVEhj7fQyNeIownXhUNru2Quk6JSqVTyORJUfR6KO17W4b/XCXghIz+gU489uFT+5g==", Format.Base64)]
    public void TestSHA512Hash(string input, string expected, Format format)
    {
        // Arrange
        Encoding encoding = Encoding.UTF8;

        // Act
        byte[] hash = Hash.Compute(input, HashAlgorithmName.SHA512, encoding);
        string sha512 = hash.ToString(format);

        // Assert
        Assert.That(sha512, Is.EqualTo(expected));
    }

    #endregion

    #region Compute(object input)

    // TODO

    #endregion

    #region Compute<T>(T input)

    // TODO

    #endregion
}
