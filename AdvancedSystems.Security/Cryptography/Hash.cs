using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;

using AdvancedSystems.Security.Common;

namespace AdvancedSystems.Security.Cryptography
{
    public static class Hash
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static HashAlgorithm Create(HashAlgorithmName hashAlgorithmName) => hashAlgorithmName.Name switch
        {
            nameof(HashAlgorithmName.MD5) => MD5.Create(),
            nameof(HashAlgorithmName.SHA1) => SHA1.Create(),
            nameof(HashAlgorithmName.SHA256) => SHA256.Create(),
            nameof(HashAlgorithmName.SHA384) => SHA384.Create(),
            nameof(HashAlgorithmName.SHA512) => SHA512.Create(),
            nameof(HashAlgorithmName.SHA3_256) => SHA3_256.Create(),
            nameof(HashAlgorithmName.SHA3_384) => SHA3_384.Create(),
            nameof(HashAlgorithmName.SHA3_512) => SHA3_512.Create(),
            _ => throw new NotImplementedException()
        };

        public static byte[] Compute(string input, HashAlgorithmName hashAlgorithmName, Encoding? encoding = null)
        {
            encoding ??= Encoding.UTF8;
            byte[] bytes = encoding.GetBytes(input);

            using var hashAlgorithm = Hash.Create(hashAlgorithmName);
            return hashAlgorithm.ComputeHash(bytes);
        }

        public static byte[] Compute(object input, HashAlgorithmName hashAlgorithmName)
        {
            var serializer = new DataContractSerializer(input.GetType());

            using var memoryStream = new MemoryStream();
            serializer.WriteObject(memoryStream, input);

            using var hashAlgorithm = Hash.Create(hashAlgorithmName);
            return hashAlgorithm.ComputeHash(memoryStream.ToArray());
        }

        public static byte[] Compute<T>(T input, HashAlgorithmName hashAlgorithmName) where T : class, new()
        {
            ReadOnlySpan<byte> bytes = ObjectSerializer.Serialize(input);

            using var hashAlgorithm = Hash.Create(hashAlgorithmName);
            return hashAlgorithm.ComputeHash(bytes.ToArray());
        }
    }
}
