using System;

namespace AdvancedSystems.Security.Abstractions;

public interface ICryptoRandomService
{
    #region Methods

    /// <summary>
    ///     Creates an array of bytes filled with a cryptographically strong random sequence of values.
    /// </summary>
    /// <param name="length">
    ///     The length of the span to return.
    /// </param>
    /// <returns>
    ///     A span filled with cryptographically strong random numbers.
    /// </returns>
    Span<byte> GetBytes(int length);

    /// <summary>
    ///      Returns a cryptographically secure random integer.
    /// </summary>
    /// <returns>
    ///     A 32-bit signed integer.
    /// </returns>
    int GetInt32();

    /// <summary>
    ///     Generates a random integer between a specified inclusive lower bound and a specified
    ///     exclusive upper bound using a cryptographically strong random number generator.
    /// </summary>
    /// <param name="minValue">
    ///     The inclusive lower bound of the random range.
    /// </param>
    /// <param name="maxValue">
    ///     The exclusive upper bound of the random range.
    /// </param>
    /// <returns>
    ///     A random integer between <paramref name="minValue"/> (inclusive) and
    ///     <paramref name="maxValue"/> (exclusive).
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    ///     The <paramref name="maxValue"/> parameter is less than or equal to the
    ///     <paramref name="minValue"/> parameter.
    /// </exception>
    int GetInt32(int minValue, int maxValue);

    /// <summary>
    ///     Performs an in-place shuffle of a span using cryptographically random number generation.
    /// </summary>
    /// <typeparam name="T">
    ///     The type of span.
    /// </typeparam>
    /// <param name="values">
    ///     The span to shuffle.
    /// </param>
    void Shuffle<T>(Span<T> values);

    /// <summary>
    ///     Selects a random element from the provided span of values.
    /// </summary>
    /// <typeparam name="T">
    ///     The type of span.
    /// </typeparam>
    /// <param name="values">
    ///     The span to select a random element from.
    /// </param>
    /// <returns>
    ///     A randomly selected element from the span.
    /// </returns>
    T Choice<T>(Span<T> values);

    #endregion
}