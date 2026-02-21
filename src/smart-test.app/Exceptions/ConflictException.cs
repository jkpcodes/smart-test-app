using System.Net;

namespace SmartTest.App.Exceptions;

/// <summary>
/// Thrown when a resource already exists or a conflict occurs (HTTP 409).
/// </summary>
public class ConflictException : AppException
{
    public ConflictException(string message)
        : base(message, HttpStatusCode.Conflict)
    {
    }
}
