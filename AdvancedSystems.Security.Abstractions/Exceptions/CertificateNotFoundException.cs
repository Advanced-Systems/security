using System;

namespace AdvancedSystems.Security.Abstractions.Exceptions;

/// <summary>
///     Represents errors that occur because a specified certificate could not be located.
/// </summary>
/// <remarks>
///     This exception is typically thrown when an attempt to retrieve a certificate by its
///     identifier, such as a thumbprint or subject name, fails. It indicates that the required
///     certificate is not present in the specified certificate store or location.
/// </remarks>
public class CertificateNotFoundException : Exception
{
    /// <summary>
    ///     Initializes a new instance of the <seealso cref="CertificateNotFoundException"/> class.
    /// </summary>
    public CertificateNotFoundException()
    {

    }

    /// <summary>
    ///     Initializes a new instance of the <seealso cref="CertificateNotFoundException"/> class with a specified error <paramref name="message"/>.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    public CertificateNotFoundException(string message) : base(message)
    {

    }

    /// <summary>
    ///     Initializes a new instance of the <seealso cref="CertificateNotFoundException"/> class with a specified error
    ///     <paramref name="message"/> a reference to the <paramref name="inner"/> exception that is the cause of this exception.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    /// <param name="inner">The exception that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
    public CertificateNotFoundException(string message, Exception inner) : base(message, inner)
    {

    }
}
