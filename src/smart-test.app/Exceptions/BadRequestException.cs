using System.Net;

namespace SmartTest.App.Exceptions;

/// <summary>
/// Thrown when a request contains invalid data or violates a business rule (HTTP 400).
/// </summary>
public class BadRequestException : AppException
{
    public BadRequestException(string message)
        : base(message, HttpStatusCode.BadRequest)
    {
    }
}
