using SmartTest.App.Common;
using SmartTest.App.DTOs.Auth;

namespace SmartTest.App.Services;

public interface IAuthService
{
    Task<Result<AuthResponse>> RegisterAsync(RegisterRequest request);
    Task<Result<AuthResponse>> LoginAsync(LoginRequest request);
    Task<Result<AuthResponse>> RefreshTokenAsync(RefreshTokenRequest request);
    Task<Result> SetAdminAsync(string userId);
    Task<Result> LogoutAsync(string userId);
}
