namespace AdvancedSystems.Security.Abstractions;

/// <summary>
///     Identifies a mathematical function that maps a string of arbitrary length
///     (up to a pre-determined maximum size) to a fixed-length string.
/// </summary>
public enum HashFunction
{
    MD5 = 0,
    SHA1 = 1,
    SHA256 = 2,
    SHA384 = 3,
    SHA512 = 4,
    SHA3_256 = 5,
    SHA3_384 = 6,
    SHA3_512 = 7,
}