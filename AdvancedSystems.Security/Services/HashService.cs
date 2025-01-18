﻿using System.Security.Cryptography;

using AdvancedSystems.Security.Abstractions;
using AdvancedSystems.Security.Common;
using AdvancedSystems.Security.Cryptography;
using AdvancedSystems.Security.Extensions;

using Microsoft.Extensions.Logging;

namespace AdvancedSystems.Security.Services;

/// <inheritdoc cref="IHashService" />
public sealed class HashService : IHashService
{
    private readonly ILogger<HashService> _logger;

    public HashService(ILogger<HashService> logger)
    {
        this._logger = logger;
    }

    #region Methods

    /// <inheritdoc />
    public string GetMD5Hash(byte[] buffer)
    {
        this._logger.LogWarning("Computing hash with a cryptographically insecure hash algorithm (MD5).");

        byte[] md5 = Hash.Compute(buffer, HashAlgorithmName.MD5);
        return md5.ToString(Format.Hex);
    }

    /// <inheritdoc />
    public string GetSHA1Hash(byte[] buffer)
    {
        this._logger.LogWarning("Computing hash with a cryptographically insecure hash algorithm (SHA1).");

        byte[] sha1 = Hash.Compute(buffer, HashAlgorithmName.SHA1);
        return sha1.ToString(Format.Hex);
    }

    /// <inheritdoc />
    public string GetSHA256Hash(byte[] buffer)
    {
        byte[] sha256 = Hash.Compute(buffer, HashAlgorithmName.SHA256);
        return sha256.ToString(Format.Hex);
    }

    /// <inheritdoc />
    public string GetSHA384Hash(byte[] buffer)
    {
        byte[] sha384 = Hash.Compute(buffer, HashAlgorithmName.SHA384);
        return sha384.ToString(Format.Hex);
    }

    /// <inheritdoc />
    public string GetSHA512Hash(byte[] buffer)
    {
        byte[] sha512 = Hash.Compute(buffer, HashAlgorithmName.SHA512);
        return sha512.ToString(Format.Hex);
    }

    /// <inheritdoc />
    public string GetSecureSHA1Hash(byte[] buffer, byte[] salt, int iterations = 1000)
    {
        var hashAlgorithmName = HashAlgorithmName.SHA1;
        using var hashAlgorithm = Hash.Create(hashAlgorithmName);
        bool isSuccessful = Hash.TryComputeSecure(buffer, salt, hashAlgorithm.HashSize, iterations, hashAlgorithmName, out byte[] sha1);
        return isSuccessful ? sha1.ToString(Format.Hex) : string.Empty;
    }

    /// <inheritdoc />
    public string GetSecureSHA256Hash(byte[] buffer, byte[] salt, int iterations = 1000)
    {
        var hashAlgorithmName = HashAlgorithmName.SHA256;
        using var hashAlgorithm = Hash.Create(hashAlgorithmName);
        bool isSuccessful = Hash.TryComputeSecure(buffer, salt, hashAlgorithm.HashSize, iterations, hashAlgorithmName, out byte[] sha256);
        return isSuccessful ? sha256.ToString(Format.Hex) : string.Empty;
    }

    /// <inheritdoc />
    public string GetSecureSHA384Hash(byte[] buffer, byte[] salt, int iterations = 1000)
    {
        var hashAlgorithmName = HashAlgorithmName.SHA384;
        using var hashAlgorithm = Hash.Create(hashAlgorithmName);
        bool isSuccessful = Hash.TryComputeSecure(buffer, salt, hashAlgorithm.HashSize, iterations, hashAlgorithmName, out byte[] sha384);
        return isSuccessful ? sha384.ToString(Format.Hex) : string.Empty;
    }

    /// <inheritdoc />
    public string GetSecureSHA512Hash(byte[] buffer, byte[] salt, int iterations = 1000)
    {
        var hashAlgorithmName = HashAlgorithmName.SHA512;
        using var hashAlgorithm = Hash.Create(hashAlgorithmName);
        bool isSuccessful = Hash.TryComputeSecure(buffer, salt, hashAlgorithm.HashSize, iterations, hashAlgorithmName, out byte[] sha512);
        return isSuccessful ? sha512.ToString(Format.Hex) : string.Empty;
    }

    #endregion
}