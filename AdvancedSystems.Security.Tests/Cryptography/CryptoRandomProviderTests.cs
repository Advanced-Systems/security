using System;
using System.Linq;

using AdvancedSystems.Security.Cryptography;

using Xunit;

namespace AdvancedSystems.Security.Tests.Cryptography;

public class CryptoRandomProviderTests
{
    #region Tests

    [Fact]
    public void TestGetBytes()
    {
        // Arrange
        int length = 64;

        // Act
        Span<byte> buffer = CryptoRandomProvider.GetBytes(length);

        // Assert
        Assert.Equal(length, buffer.Length);
        Assert.All(buffer.ToArray(), b => Assert.InRange(b, byte.MinValue, byte.MaxValue));
    }

    [Fact]
    public void TestGetInt32()
    {
        // Arrange
        int rounds = 10_000;
        int[] randomNumbers = new int[rounds];

        // Act
        for (int i = 0; i < rounds; i++)
        {
            randomNumbers[i] = CryptoRandomProvider.GetInt32();
        }

        // Assert
        Assert.All(randomNumbers, x => Assert.InRange(x, int.MinValue, int.MaxValue));
    }

    [Fact]
    public void TestGetInt32_MinMax()
    {
        // Arrange
        int min = 1;
        int max = 10;
        int rounds = 10_000;
        int[] randomNumbers = new int[rounds];

        // Act
        for (int i = 0; i < rounds; i++)
        {
            randomNumbers[i] = CryptoRandomProvider.GetInt32(min, max);
        }

        // Assert
        Assert.All(randomNumbers, x => Assert.InRange(x, min, max - 1));
    }

    [Fact]
    public void TestShuffle()
    {
        // Arrange
        int[] array1 = Enumerable.Range(1, 100).ToArray();
        int[] array2 = Enumerable.Range(1, 100).ToArray();

        // Act
        CryptoRandomProvider.Shuffle<int>(array1);

        // Assert
        Assert.NotEqual(array1, array2);
    }

    [Fact]
    public void TestChoice()
    {
        // Arrange
        int rounds = 10_000;
        int[] randomNumbers = new int[rounds];
        int[] array = Enumerable.Range(1, 100).ToArray();

        // Act
        for (int i = 0; i < rounds; i++)
        {
            randomNumbers[i] = CryptoRandomProvider.Choice<int>(array);
        }

        // Assert
        Assert.All(randomNumbers, x => Assert.Contains(x, array));
    }

    #endregion
}