using System;
using System.Numerics;
using System.Text;

namespace AdvancedSystems.Security.Common
{
    /// <summary>
    ///     Implements various utility methods for manipulating byte arrays and spans in cryptographic operations.
    /// </summary>
    public static class Bytes
    {
        public static string ToString(this byte[] array, Format format) => format switch
        {
            Format.Hex => BitConverter.ToString(array).Replace("-", string.Empty).ToLower(),
            Format.Base64 => Convert.ToBase64String(array),
            Format.String => Encoding.UTF8.GetString(array),
            _ => throw new NotSupportedException($"String formatting is not implemted for {format}.")
        };

        public static byte[] GetBytes<T>(T value) where T : INumber<T> => value switch
        {
            bool boolValue => BitConverter.GetBytes(boolValue),
            char charValue => BitConverter.GetBytes(charValue),
            double doubleValue => BitConverter.GetBytes(doubleValue),
            Half halfValue => BitConverter.GetBytes(halfValue),
            short shortValue => BitConverter.GetBytes(shortValue),
            int intValue => BitConverter.GetBytes(intValue),
            long longValue => BitConverter.GetBytes(longValue),
            float floatValue => BitConverter.GetBytes(floatValue),
            ushort ushortValue => BitConverter.GetBytes(ushortValue),
            uint uintValue => BitConverter.GetBytes(uintValue),
            ulong ulongValue => BitConverter.GetBytes(ulongValue),
            _ => throw new ArgumentException("Failed to convert T to an array of bytes.", nameof(value))
        };
    }
}
