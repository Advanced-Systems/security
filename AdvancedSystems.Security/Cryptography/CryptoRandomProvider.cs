using System;
using System.Security.Cryptography;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Internals;

namespace AdvancedSystems.Security.Cryptography;

/// <summary>
///     Represents a class for performing cryptographically secure numerical operations.
/// </summary>
public static class CryptoRandomProvider
{
    /// <inheritdoc cref="ICryptoRandomService.GetBytes(int)" />
    public static Span<byte> GetBytes(int length)
    {
        Span<byte> buffer = Hazmat.GetUninitializedArray<byte>(length);
        RandomNumberGenerator.Fill(buffer);
        return buffer;
    }

    /// <inheritdoc cref="ICryptoRandomService.GetInt32()" />
    public static int GetInt32()
    {
        Span<byte> buffer = CryptoRandomProvider.GetBytes(4);
        int random = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);
        return random;
    }

    /// <inheritdoc cref="ICryptoRandomService.GetInt32(int, int)" />
    public static int GetInt32(int minValue, int maxValue)
    {
        return RandomNumberGenerator.GetInt32(minValue, maxValue);
    }

    /// <inheritdoc cref="ICryptoRandomService.Shuffle{T}(Span{T})" />
    public static void Shuffle<T>(Span<T> values)
    {
        RandomNumberGenerator.Shuffle(values);
    }

    /// <inheritdoc cref="ICryptoRandomService.Choice{T}(Span{T})" />
    public static T Choice<T>(Span<T> values)
    {
        int index = CryptoRandomProvider.GetInt32(0, values.Length);
        return values[index];
    }
}