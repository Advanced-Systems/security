using System;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;

namespace AdvancedSystems.Security.Services;

/// <inheritdoc cref="ICryptoRandomService" />
public sealed class CryptoRandomService : ICryptoRandomService
{
    public CryptoRandomService()
    {

    }

    #region Methods

    /// <inheritdoc />
    public Span<byte> GetBytes(int length)
    {
        return CryptoRandomProvider.GetBytes(length);
    }

    /// <inheritdoc />
    public int GetInt32()
    {
        return CryptoRandomProvider.GetInt32();
    }

    /// <inheritdoc />
    public int GetInt32(int minValue, int maxValue)
    {
        return CryptoRandomProvider.GetInt32(minValue, maxValue);
    }

    /// <inheritdoc />
    public void Shuffle<T>(Span<T> values)
    {
        CryptoRandomProvider.Shuffle(values);
    }

    /// <inheritdoc />
    public T Choice<T>(Span<T> values)
    {
        return CryptoRandomProvider.Choice(values);
    }

    #endregion
}