using System.Net;

namespace SmartTest.App.Exceptions;

/// <summary>
/// Thrown when authentication fails (HTTP 401).
/// </summary>
public class UnauthorizedException : AppException
{
    public UnauthorizedException(string message)
        : base(message, HttpStatusCode.Unauthorized)
    {
    }
}
