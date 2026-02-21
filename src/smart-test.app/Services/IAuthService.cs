using SmartTest.App.DTOs.Auth;

namespace SmartTest.App.Services;

public interface IAuthService
{
    Task<AuthResponse> RegisterAsync(RegisterRequest request);
    Task<AuthResponse> LoginAsync(LoginRequest request);
    Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request);
    Task SetAdminAsync(string userId);
    Task LogoutAsync(string userId);
}
