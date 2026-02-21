using System.Net;

namespace SmartTest.App.Exceptions;

/// <summary>
/// Thrown when a requested resource is not found (HTTP 404).
/// </summary>
public class NotFoundException : AppException
{
    public NotFoundException(string message)
        : base(message, HttpStatusCode.NotFound)
    {
    }
}
