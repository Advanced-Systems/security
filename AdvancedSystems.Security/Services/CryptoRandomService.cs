using System;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Cryptography;

namespace AdvancedSystems.Security.Services;

public sealed class CryptoRandomService : ICryptoRandomService
{
    public CryptoRandomService()
    {

    }

    #region Methods

    public Span<byte> GetBytes(int length)
    {
        return CryptoRandomProvider.GetBytes(length);
    }

    public int GetInt32()
    {
        return CryptoRandomProvider.GetInt32();
    }

    public int GetInt32(int minValue, int maxValue)
    {
        return CryptoRandomProvider.GetInt32(minValue, maxValue);
    }

    public void Shuffle<T>(Span<T> values)
    {
        CryptoRandomProvider.Shuffle(values);
    }

    public T Choice<T>(Span<T> values)
    {
        return CryptoRandomProvider.Choice(values);
    }

    #endregion
}
