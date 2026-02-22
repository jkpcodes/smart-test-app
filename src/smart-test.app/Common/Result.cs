using System.Net;

namespace SmartTest.App.Common;

public class Result<T>
{
    public bool IsSuccess { get; }
    public T? Value { get; }
    public string? Error { get; }
    public int StatusCode { get; }

    private Result(T data)
    {
        IsSuccess = true;
        Value = data;
        StatusCode = (int)HttpStatusCode.OK;
    }

    private Result(string error, HttpStatusCode statusCode)
    {
        IsSuccess = false;
        Error = error;
        StatusCode = (int)statusCode;
    }

    public static Result<T> Success(T value) => new(value);
    public static Result<T> Failure(string error, HttpStatusCode statusCode = HttpStatusCode.BadRequest) => new(error, statusCode);
}

public class Result
{
    public bool IsSuccess { get; }
    public string? Error { get; }
    public int StatusCode { get; }

    private Result()
    {
        IsSuccess = true;
        StatusCode = (int)HttpStatusCode.OK;
    }

    private Result(string error, HttpStatusCode statusCode)
    {
        IsSuccess = false;
        Error = error;
        StatusCode = (int)statusCode;
    }

    public static Result Success() => new();
    public static Result Failure(string error, HttpStatusCode statusCode = HttpStatusCode.BadRequest) => new(error, statusCode);
}
