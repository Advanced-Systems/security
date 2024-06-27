using System;
using System.Security.Cryptography;

namespace AdvancedSystems.Security.Cryptography;

public static class CryptoRandom
{
    /// <summary>
    ///     Creates an array of bytes filled with a cryptographically strong random sequence of values.
    /// </summary>
    /// <param name="length"></param>
    /// <returns></returns>
    public static Span<byte> GetBytes(int length)
    {
        Span<byte> buffer = new byte[length];
        RandomNumberGenerator.Fill(buffer);
        return buffer;
    }

    /// <summary>
    ///      Returns a cryptographically secure random integer.
    /// </summary>
    /// <returns>A 32-bit signed integer</returns>
    public static int GetInt32()
    {
        Span<byte> buffer = CryptoRandom.GetBytes(4);
        int random = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);
        return random;
    }

    /// <summary>
    ///     Generates a random integer between a specified inclusive lower bound and a specified exclusive upper bound using
    ///     a cryptographically strong random number generator.
    /// </summary>
    /// <param name="minValue">The inclusive lower bound of the random range.</param>
    /// <param name="maxValue">The exclusive upper bound of the random range.</param>
    /// <returns>
    ///     A random integer between <paramref name="minValue"/> (inclusive) and <paramref name="maxValue"/> (exclusive).
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    ///     The <paramref name="maxValue"/> parameter is less than or equal to the <paramref name="minValue"/> parameter.
    /// </exception>
    public static int GetInt32(int minValue, int maxValue)
    {
        return RandomNumberGenerator.GetInt32(minValue, maxValue);
    }
}
