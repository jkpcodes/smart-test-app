using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SmartTest.App.Common;
using SmartTest.App.Constants;
using SmartTest.App.Constants.ErrorMessages;
using SmartTest.App.DTOs.Auth;
using SmartTest.App.Services;
using SmartTest.Domain.Settings;
using SmartTest.Infrastructure.Identity.Models;

namespace SmartTest.Infrastructure.Identity.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        SignInManager<ApplicationUser> signInManager,
        IOptions<JwtSettings> jwtSettings,
        ILogger<AuthService> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _signInManager = signInManager;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;
    }

    public async Task<Result<AuthResponse>> RegisterAsync(RegisterRequest request)
    {
        // Check if user already exists
        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser is not null)
        {
            return Result<AuthResponse>.Failure(AuthErrorMessages.EmailAlreadyExists(request.Email), HttpStatusCode.Conflict);
        }

        var user = new ApplicationUser
        {
            FirstName = request.FirstName,
            LastName = request.LastName,
            Email = request.Email,
            UserName = request.Email,
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };

        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            return Result<AuthResponse>.Failure(AuthErrorMessages.RegistrationFailed(errors), HttpStatusCode.InternalServerError);
        }

        try
        {
            // Always assign "User" role on registration
            var roleResult = await _userManager.AddToRoleAsync(user, AppRoles.User);
            if (!roleResult.Succeeded)
                throw new Exception(string.Join(", ", roleResult.Errors.Select(e => e.Description)));

            var roles = await _userManager.GetRolesAsync(user);
            var accessToken = GenerateJwtToken(user, roles);
            var refreshToken = GenerateRefreshToken();
            var refreshTokenExpiry = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationInDays);

            // Store refresh token
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = refreshTokenExpiry;

            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
                throw new Exception(string.Join(", ", updateResult.Errors.Select(e => e.Description)));

            return Result<AuthResponse>.Success(new AuthResponse
            {
                UserId = user.Id,
                Email = user.Email!,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Roles = roles.ToList(),
                Token = accessToken,
                TokenExpiration = DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpirationInMinutes),
                RefreshToken = refreshToken,
                RefreshTokenExpiration = refreshTokenExpiry
            });
        }
        catch (Exception ex)
        {
            // If role assignment fails, delete the created user to avoid orphaned accounts
            _logger.LogError("Registration rollback triggered for email {Email}", request.Email);
            await _userManager.DeleteAsync(user);
            return Result<AuthResponse>.Failure(ex.Message, HttpStatusCode.InternalServerError);
        }
    }

    public async Task<Result<AuthResponse>> LoginAsync(LoginRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            return Result<AuthResponse>.Failure(AuthErrorMessages.InvalidCredentials, HttpStatusCode.Unauthorized);
        }

        // Check if account is active
        if (!user.IsActive)
        {
            return Result<AuthResponse>.Failure(AuthErrorMessages.AccountDeactivated, HttpStatusCode.BadRequest);
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

        if (!result.Succeeded)
        {
            if (result.IsLockedOut)
            {
                _logger.LogWarning("Account locked out for email {Email}", request.Email);
                return Result<AuthResponse>.Failure(AuthErrorMessages.AccountLockedOut, HttpStatusCode.Unauthorized);
            }

            _logger.LogWarning("Failed login attempt for email {Email}", request.Email);
            return Result<AuthResponse>.Failure(AuthErrorMessages.InvalidCredentials, HttpStatusCode.Unauthorized);
        }

        var roles = await _userManager.GetRolesAsync(user);
        var accessToken = GenerateJwtToken(user, roles);
        var refreshToken = GenerateRefreshToken();
        var refreshTokenExpiry = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationInDays);

        // Update user: last login time + refresh token
        user.LastLoginAt = DateTime.UtcNow;
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = refreshTokenExpiry;
        await _userManager.UpdateAsync(user);

        return Result<AuthResponse>.Success(new AuthResponse
        {
            UserId = user.Id,
            Email = user.Email!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Roles = roles.ToList(),
            Token = accessToken,
            TokenExpiration = DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpirationInMinutes),
            RefreshToken = refreshToken,
            RefreshTokenExpiration = refreshTokenExpiry
        });
    }

    public async Task<Result<AuthResponse>> RefreshTokenAsync(RefreshTokenRequest request)
    {
        // Validate the expired access token to extract claims
        var principalResult = GetPrincipalFromExpiredToken(request.AccessToken);

        if (!principalResult.IsSuccess)
        {
            return Result<AuthResponse>.Failure(principalResult.Error!, (HttpStatusCode)principalResult.StatusCode);
        }

        // principalResult.Value is guaranteed to be non-null here because GetPrincipalFromExpiredToken
        // returns Failure if it fails
        var principal = principalResult.Value!;

        var userId = principal.FindFirstValue(JwtRegisteredClaimNames.Sub)
            ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId is null)
        {
            return Result<AuthResponse>.Failure(AuthErrorMessages.InvalidAccessToken, HttpStatusCode.Unauthorized);
        }

        var user = await _userManager.FindByIdAsync(userId);

        if (user is null || !user.IsActive)
        {
            return Result<AuthResponse>.Failure(AuthErrorMessages.InvalidAccessToken, HttpStatusCode.Unauthorized);
        }

        // In RefreshTokenAsync — if refresh token doesn't match, revoke ALL tokens
        if (user.RefreshToken != request.RefreshToken)
        {
            // Possible token theft — revoke everything
            _logger.LogWarning("Refresh token reuse detected for user {UserId}. Revoking all tokens.", user.Id);
            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;
            await _userManager.UpdateAsync(user);
            return Result<AuthResponse>.Failure(
                AuthErrorMessages.RefreshTokenExpired, HttpStatusCode.Unauthorized);
        }

        if (user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            return Result<AuthResponse>.Failure(
                AuthErrorMessages.RefreshTokenExpired, HttpStatusCode.Unauthorized);
        }

        // Rotate: issue new access + refresh tokens
        var roles = await _userManager.GetRolesAsync(user);
        var newAccessToken = GenerateJwtToken(user, roles);
        var newRefreshToken = GenerateRefreshToken();
        var refreshTokenExpiry = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationInDays);

        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = refreshTokenExpiry;
        await _userManager.UpdateAsync(user);

        return Result<AuthResponse>.Success(new AuthResponse
        {
            UserId = user.Id,
            Email = user.Email!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Roles = roles.ToList(),
            Token = newAccessToken,
            TokenExpiration = DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpirationInMinutes),
            RefreshToken = newRefreshToken,
            RefreshTokenExpiration = refreshTokenExpiry
        });
    }

    public async Task<Result> SetAdminAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);

        if (user is null)
        {
            return Result.Failure(AuthErrorMessages.UserNotFound(userId), HttpStatusCode.NotFound);
        }

        if (!user.IsActive)
        {
            return Result.Failure(AuthErrorMessages.CannotModifyDeactivatedRoles, HttpStatusCode.BadRequest);
        }

        var isAlreadyAdmin = await _userManager.IsInRoleAsync(user, AppRoles.Admin);
        if (isAlreadyAdmin)
        {
            return Result.Failure(AuthErrorMessages.AlreadyAdmin, HttpStatusCode.Conflict);
        }

        var result = await _userManager.AddToRoleAsync(user, AppRoles.Admin);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            return Result.Failure(AuthErrorMessages.AdminRoleFailed(errors), HttpStatusCode.BadRequest);
        }

        _logger.LogInformation("Admin role assigned to user {UserId}", userId);
        return Result.Success();
    }

    public async Task<Result> LogoutAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);

        if (user is not null)
        {
            // Revoke the refresh token so it can't be reused
            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;
            await _userManager.UpdateAsync(user);
        }

        await _signInManager.SignOutAsync();

        _logger.LogInformation("User {UserId} logged out", userId);
        return Result.Success();
    }

    private string GenerateJwtToken(ApplicationUser user, IList<string> roles)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // Add role claims
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpirationInMinutes),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateRefreshToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    private Result<ClaimsPrincipal> GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = false, // Allow expired tokens
            ValidIssuer = _jwtSettings.Issuer,
            ValidAudience = _jwtSettings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_jwtSettings.Secret))
        };

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                return Result<ClaimsPrincipal>.Failure(AuthErrorMessages.InvalidAccessToken, HttpStatusCode.Unauthorized);
            }

            return Result<ClaimsPrincipal>.Success(principal);
        }
        catch (Exception)
        {
            return Result<ClaimsPrincipal>.Failure(AuthErrorMessages.InvalidAccessToken, HttpStatusCode.Unauthorized);
        }
    }
}
