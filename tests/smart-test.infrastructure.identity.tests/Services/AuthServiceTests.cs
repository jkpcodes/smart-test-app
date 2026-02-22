using Moq;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity;
using SmartTest.Infrastructure.Identity.Models;
using SmartTest.Domain.Settings;
using SmartTest.Infrastructure.Identity.Services;
using smart_test.infrastructure.identity.tests.Helpers;
using SmartTest.App.Constants;
using FluentAssertions;
using SmartTest.App.DTOs.Auth;
using SmartTest.App.Constants.ErrorMessages;
using System.Net;
using Microsoft.Extensions.Logging;

namespace smart_test.infrastructure.identity.tests.Services;

public class AuthServiceTests
{
    private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
    private readonly Mock<RoleManager<IdentityRole>> _roleManagerMock;
    private readonly Mock<SignInManager<ApplicationUser>> _signInManagerMock;
    private readonly IOptions<JwtSettings> _jwtSettings;
    private readonly AuthService _authService;
    private readonly Mock<ILogger<AuthService>> _logger;

    public AuthServiceTests()
    {
        _userManagerMock = MockUserManagerHelper.CreateMockUserManager();
        _roleManagerMock = MockUserManagerHelper.CreateMockRoleManager();
        _signInManagerMock = MockUserManagerHelper.CreateMockSignInManager(_userManagerMock);
        _logger = new Mock<ILogger<AuthService>>();

        _jwtSettings = Options.Create(new JwtSettings
        {
            Secret = "test-secret-key-which-is-long-enough",
            Issuer = "test-issuer",
            Audience = "test-audience",
            TokenExpirationInMinutes = 60,
            RefreshTokenExpirationInDays = 7
        });

        _authService = new AuthService(
            _userManagerMock.Object,
            _roleManagerMock.Object,
            _signInManagerMock.Object,
            _jwtSettings,
            _logger.Object);
    }

    #region RegisterAsync

    [Fact]
    public async Task RegisterAsync_WithNewEmail_ReturnsSuccess()
    {
        var request = new RegisterRequest
        {
            FirstName = "John",
            LastName = "Doe",
            Email = "john@example.com",
            Password = "P@ssword123"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync((ApplicationUser?)null);

        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
            .ReturnsAsync(IdentityResult.Success);

        _userManagerMock
            .Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), AppRoles.User))
            .ReturnsAsync(IdentityResult.Success);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { AppRoles.User });

        _userManagerMock
            .Setup(x => x.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);

        var result = await _authService.RegisterAsync(request);

        result.IsSuccess.Should().BeTrue();

        result.Value.Should().NotBeNull();
        result.Value.Email.Should().Be(request.Email);
        result.Value.FirstName.Should().Be(request.FirstName);
        result.Value.LastName.Should().Be(request.LastName);
        result.Value.Token.Should().NotBeNullOrEmpty();
        result.Value.RefreshToken.Should().NotBeNullOrEmpty();
        result.Value.Roles.Should().Contain(AppRoles.User);

        // Verify all expected operations were called
        _userManagerMock.Verify(x => x.CreateAsync(It.IsAny<ApplicationUser>(), request.Password), Times.Once);
        _userManagerMock.Verify(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), AppRoles.User), Times.Once);
        _userManagerMock.Verify(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()), Times.Once);
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<ApplicationUser>()), Times.Once);
        _userManagerMock.Verify(x => x.DeleteAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task RegisterAsync_WithExistingEmail_ReturnsError()
    {
        // Arrange
        var request = new RegisterRequest
        {
            FirstName = "John",
            LastName = "Doe",
            Email = "existing@example.com",
            Password = "P@ssword123"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync(new ApplicationUser { Email = request.Email });

        // Act
        var result = await _authService.RegisterAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.Conflict);
        result.Error.Should().Be(AuthErrorMessages.EmailAlreadyExists(request.Email));

        // Verify no further operations were performed
        _userManagerMock.Verify(x => x.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Never);
        _userManagerMock.Verify(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Never);
        _userManagerMock.Verify(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _userManagerMock.Verify(x => x.DeleteAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task RegisterAsync_WhenCreateFailsWeakPassword_ReturnsFailure()
    {
        // Arrange
        var request = new RegisterRequest
        {
            FirstName = "John",
            LastName = "Doe",
            Email = "john@example.com",
            Password = "weak"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync((ApplicationUser?)null);

        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
            .ReturnsAsync(IdentityResult.Failed(
                new IdentityError { Description = "Password too weak" }));

        // Act
        var result = await _authService.RegisterAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.InternalServerError);
        result.Error.Should().Contain("Password too weak");

        // Verify no further operations were performed
        _userManagerMock.Verify(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Never);
        _userManagerMock.Verify(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _userManagerMock.Verify(x => x.DeleteAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task RegisterAsync_WhenAddToRoleFails_RollsBackAndReturnsFailure()
    {
        // Arrange
        var request = new RegisterRequest
        {
            FirstName = "John",
            LastName = "Doe",
            Email = "john@example.com",
            Password = "P@ssword123"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync((ApplicationUser?)null);

        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
            .ReturnsAsync(IdentityResult.Success);

        _userManagerMock
            .Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), AppRoles.User))
            .ReturnsAsync(IdentityResult.Failed(
                new IdentityError { Description = "Role assignment failed" }));

        _userManagerMock
            .Setup(x => x.DeleteAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _authService.RegisterAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.InternalServerError);
        result.Error.Should().Contain("Role assignment failed");

        // Verify rollback occurred
        _userManagerMock.Verify(x => x.DeleteAsync(It.IsAny<ApplicationUser>()), Times.Once);

        // Verify no further operations after role failure
        _userManagerMock.Verify(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task RegisterAsync_WhenUpdateFails_RollsBackAndReturnsFailure()
    {
        // Arrange
        var request = new RegisterRequest
        {
            FirstName = "John",
            LastName = "Doe",
            Email = "john@example.com",
            Password = "P@ssword123"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync((ApplicationUser?)null);

        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
            .ReturnsAsync(IdentityResult.Success);

        _userManagerMock
            .Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), AppRoles.User))
            .ReturnsAsync(IdentityResult.Success);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(new List<string> { AppRoles.User });

        _userManagerMock
            .Setup(x => x.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Failed(
                new IdentityError { Description = "Update failed" }));

        _userManagerMock
            .Setup(x => x.DeleteAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _authService.RegisterAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.InternalServerError);
        result.Error.Should().Contain("Update failed");

        // Verify rollback occurred
        _userManagerMock.Verify(x => x.DeleteAsync(It.IsAny<ApplicationUser>()), Times.Once);
    }

    [Fact]
    public async Task RegisterAsync_WhenUnexpectedExceptionThrown_RollsBackAndReturnsFailure()
    {
        // Arrange
        var request = new RegisterRequest
        {
            FirstName = "John",
            LastName = "Doe",
            Email = "john@example.com",
            Password = "P@ssword123"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync((ApplicationUser?)null);

        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
            .ReturnsAsync(IdentityResult.Success);

        _userManagerMock
            .Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), AppRoles.User))
            .ThrowsAsync(new Exception("Unexpected database error"));

        _userManagerMock
            .Setup(x => x.DeleteAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _authService.RegisterAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.InternalServerError);
        result.Error.Should().Contain("Unexpected database error");

        // Verify rollback occurred
        _userManagerMock.Verify(x => x.DeleteAsync(It.IsAny<ApplicationUser>()), Times.Once);
    }

// ...existing code...

    #endregion

    #region LoginAsync Tests

    [Fact]
    public async Task LoginAsync_WithValidCredentials_ReturnsSuccess()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            Email = "john@example.com",
            FirstName = "John",
            LastName = "Doe",
            IsActive = true
        };

        var request = new LoginRequest
        {
            Email = "john@example.com",
            Password = "P@ssword123"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync(user);

        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, request.Password, true))
            .ReturnsAsync(SignInResult.Success);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { AppRoles.User });

        _userManagerMock
            .Setup(x => x.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _authService.LoginAsync(request);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.Should().NotBeNull();
        result.Value.Email.Should().Be(request.Email);
        result.Value.FirstName.Should().Be("John");
        result.Value.LastName.Should().Be("Doe");
        result.Value.Token.Should().NotBeNullOrEmpty();
        result.Value.RefreshToken.Should().NotBeNullOrEmpty();
        result.Value.Roles.Should().Contain(AppRoles.User);

        // Verify operations were called
        _userManagerMock.Verify(x => x.GetRolesAsync(user), Times.Once);
        _userManagerMock.Verify(x => x.UpdateAsync(user), Times.Once);
    }

    [Fact]
    public async Task LoginAsync_WithInvalidEmail_ReturnsFailure()
    {
        // Arrange
        var request = new LoginRequest
        {
            Email = "nonexistent@example.com",
            Password = "P@ssword123"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _authService.LoginAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.Unauthorized);
        result.Error.Should().Be(AuthErrorMessages.InvalidCredentials);

        // Verify no further operations were attempted
        _signInManagerMock.Verify(
            x => x.CheckPasswordSignInAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<bool>()), Times.Never);
        _userManagerMock.Verify(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task LoginAsync_WithDeactivatedAccount_ReturnsFailure()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            Email = "john@example.com",
            IsActive = false
        };

        var request = new LoginRequest
        {
            Email = "john@example.com",
            Password = "P@ssword123"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync(user);

        // Act
        var result = await _authService.LoginAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.BadRequest);
        result.Error.Should().Be(AuthErrorMessages.AccountDeactivated);

        // Verify sign-in was never attempted
        _signInManagerMock.Verify(
            x => x.CheckPasswordSignInAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>(), It.IsAny<bool>()), Times.Never);
        _userManagerMock.Verify(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task LoginAsync_WithWrongPassword_ReturnsFailure()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            Email = "john@example.com",
            IsActive = true
        };

        var request = new LoginRequest
        {
            Email = "john@example.com",
            Password = "WrongPassword"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync(user);

        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, request.Password, true))
            .ReturnsAsync(SignInResult.Failed);

        // Act
        var result = await _authService.LoginAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.Unauthorized);
        result.Error.Should().Be(AuthErrorMessages.InvalidCredentials);

        // Verify no token generation or update
        _userManagerMock.Verify(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task LoginAsync_WhenLockedOut_ReturnsFailure()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            Email = "john@example.com",
            IsActive = true
        };

        var request = new LoginRequest
        {
            Email = "john@example.com",
            Password = "P@ssword123"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync(user);

        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, request.Password, true))
            .ReturnsAsync(SignInResult.LockedOut);

        // Act
        var result = await _authService.LoginAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.Unauthorized);
        result.Error.Should().Be(AuthErrorMessages.AccountLockedOut);

        // Verify no token generation or update
        _userManagerMock.Verify(x => x.GetRolesAsync(It.IsAny<ApplicationUser>()), Times.Never);
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task LoginAsync_UpdatesLastLoginAndRefreshToken()
    {
        var lastLogin = DateTime.UtcNow.AddDays(-1);
        var refreshTokenExpiry = DateTime.UtcNow.AddDays(-1);
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            Email = "john@example.com",
            FirstName = "John",
            LastName = "Doe",
            IsActive = true,
            LastLoginAt = lastLogin,
            RefreshToken = "old-refresh-token",
            RefreshTokenExpiryTime = refreshTokenExpiry
        };

        var request = new LoginRequest
        {
            Email = "john@example.com",
            Password = "P@ssword123"
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync(request.Email))
            .ReturnsAsync(user);

        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, request.Password, true))
            .ReturnsAsync(SignInResult.Success);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { AppRoles.User });

        _userManagerMock
            .Setup(x => x.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        await _authService.LoginAsync(request);

        // Assert
        user.LastLoginAt.Should().BeAfter(lastLogin);
        user.RefreshToken.Should().NotBeNullOrEmpty();
        user.RefreshTokenExpiryTime.Should().BeAfter(refreshTokenExpiry);
    }

    #endregion

    #region RefreshTokenAsync Tests

    [Fact]
    public async Task RefreshTokenAsync_WithValidTokens_ReturnsSuccess()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            Email = "john@example.com",
            FirstName = "John",
            LastName = "Doe",
            IsActive = true,
            RefreshToken = "valid-refresh-token",
            RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7)
        };

        // Generate a real JWT so GetPrincipalFromExpiredToken can parse it
        _userManagerMock
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { AppRoles.User });

        _userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        // First login to get a real access token
        _userManagerMock
            .Setup(x => x.FindByEmailAsync("john@example.com"))
            .ReturnsAsync(user);

        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, "P@ssword123", true))
            .ReturnsAsync(SignInResult.Success);

        var loginResult = await _authService.LoginAsync(new LoginRequest
        {
            Email = "john@example.com",
            Password = "P@ssword123"
        });

        // Update user's refresh token to match what login generated
        var currentRefreshToken = loginResult.Value.RefreshToken;
        user.RefreshToken = currentRefreshToken;

        var request = new RefreshTokenRequest
        {
            AccessToken = loginResult.Value.Token,
            RefreshToken = currentRefreshToken
        };

        // Act
        var result = await _authService.RefreshTokenAsync(request);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.Should().NotBeNull();
        result.Value.Token.Should().NotBeNullOrEmpty();
        result.Value.RefreshToken.Should().NotBeNullOrEmpty();
        result.Value.Token.Should().NotBe(loginResult.Value.Token);
        result.Value.RefreshToken.Should().NotBe(currentRefreshToken);
    }

    [Fact]
    public async Task RefreshTokenAsync_WithInvalidAccessToken_ReturnsFailure()
    {
        // Arrange
        var request = new RefreshTokenRequest
        {
            AccessToken = "invalid-jwt-token",
            RefreshToken = "some-refresh-token"
        };

        // Act
        var result = await _authService.RefreshTokenAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.Unauthorized);
        result.Error.Should().Be(AuthErrorMessages.InvalidAccessToken);

        // Verify no user lookup was attempted
        _userManagerMock.Verify(x => x.FindByIdAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task RefreshTokenAsync_WithNonExistentUser_ReturnsFailure()
    {
        // Arrange — login first to get a real token
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            Email = "john@example.com",
            FirstName = "John",
            LastName = "Doe",
            IsActive = true,
            RefreshToken = "refresh-token",
            RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7)
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync("john@example.com"))
            .ReturnsAsync(user);

        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, "P@ssword123", true))
            .ReturnsAsync(SignInResult.Success);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { AppRoles.User });

        _userManagerMock
            .Setup(x => x.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        var loginResult = await _authService.LoginAsync(new LoginRequest
        {
            Email = "john@example.com",
            Password = "P@ssword123"
        });

        // Now simulate user no longer exists
        _userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync((ApplicationUser?)null);

        var request = new RefreshTokenRequest
        {
            AccessToken = loginResult.Value.Token,
            RefreshToken = "some-refresh-token"
        };

        // Act
        var result = await _authService.RefreshTokenAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.Unauthorized);
        result.Error.Should().Be(AuthErrorMessages.InvalidAccessToken);
    }

    [Fact]
    public async Task RefreshTokenAsync_WithDeactivatedUser_ReturnsFailure()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            Email = "john@example.com",
            FirstName = "John",
            LastName = "Doe",
            IsActive = true,
            RefreshToken = "refresh-token",
            RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7)
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync("john@example.com"))
            .ReturnsAsync(user);

        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, "P@ssword123", true))
            .ReturnsAsync(SignInResult.Success);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { AppRoles.User });

        _userManagerMock
            .Setup(x => x.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        var loginResult = await _authService.LoginAsync(new LoginRequest
        {
            Email = "john@example.com",
            Password = "P@ssword123"
        });

        // Deactivate user after login
        user.IsActive = false;

        _userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        var request = new RefreshTokenRequest
        {
            AccessToken = loginResult.Value.Token,
            RefreshToken = loginResult.Value.RefreshToken
        };

        // Act
        var result = await _authService.RefreshTokenAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.Unauthorized);
        result.Error.Should().Be(AuthErrorMessages.InvalidAccessToken);
    }

    [Fact]
    public async Task RefreshTokenAsync_WithMismatchedRefreshToken_ReturnsFailure()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            Email = "john@example.com",
            FirstName = "John",
            LastName = "Doe",
            IsActive = true,
            RefreshToken = "stored-refresh-token",
            RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7)
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync("john@example.com"))
            .ReturnsAsync(user);

        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, "P@ssword123", true))
            .ReturnsAsync(SignInResult.Success);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { AppRoles.User });

        _userManagerMock
            .Setup(x => x.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        var loginResult = await _authService.LoginAsync(new LoginRequest
        {
            Email = "john@example.com",
            Password = "P@ssword123"
        });

        // Override stored refresh token so it doesn't match
        user.RefreshToken = "different-refresh-token";

        _userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        var request = new RefreshTokenRequest
        {
            AccessToken = loginResult.Value.Token,
            RefreshToken = "wrong-refresh-token"
        };

        // Act
        var result = await _authService.RefreshTokenAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.Unauthorized);
        result.Error.Should().Be(AuthErrorMessages.RefreshTokenExpired);
    }

    [Fact]
    public async Task RefreshTokenAsync_WithExpiredRefreshToken_ReturnsFailure()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            Email = "john@example.com",
            FirstName = "John",
            LastName = "Doe",
            IsActive = true,
            RefreshToken = "refresh-token",
            RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7)
        };

        _userManagerMock
            .Setup(x => x.FindByEmailAsync("john@example.com"))
            .ReturnsAsync(user);

        _signInManagerMock
            .Setup(x => x.CheckPasswordSignInAsync(user, "P@ssword123", true))
            .ReturnsAsync(SignInResult.Success);

        _userManagerMock
            .Setup(x => x.GetRolesAsync(user))
            .ReturnsAsync(new List<string> { AppRoles.User });

        _userManagerMock
            .Setup(x => x.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        var loginResult = await _authService.LoginAsync(new LoginRequest
        {
            Email = "john@example.com",
            Password = "P@ssword123"
        });

        // Set refresh token as expired
        user.RefreshToken = loginResult.Value.RefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(-1);

        _userManagerMock
            .Setup(x => x.FindByIdAsync(user.Id))
            .ReturnsAsync(user);

        var request = new RefreshTokenRequest
        {
            AccessToken = loginResult.Value.Token,
            RefreshToken = loginResult.Value.RefreshToken
        };

        // Act
        var result = await _authService.RefreshTokenAsync(request);

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.Unauthorized);
        result.Error.Should().Be(AuthErrorMessages.RefreshTokenExpired);
    }

    #endregion

    #region SetAdminAsync Tests

    [Fact]
    public async Task SetAdminAsync_WithValidUser_ReturnsSuccess()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            IsActive = true
        };

        _userManagerMock
            .Setup(x => x.FindByIdAsync("user-id-123"))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.IsInRoleAsync(user, AppRoles.Admin))
            .ReturnsAsync(false);

        _userManagerMock
            .Setup(x => x.AddToRoleAsync(user, AppRoles.Admin))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _authService.SetAdminAsync("user-id-123");

        // Assert
        result.IsSuccess.Should().BeTrue();

        // Verify operations
        _userManagerMock.Verify(x => x.FindByIdAsync("user-id-123"), Times.Once);
        _userManagerMock.Verify(x => x.IsInRoleAsync(user, AppRoles.Admin), Times.Once);
        _userManagerMock.Verify(x => x.AddToRoleAsync(user, AppRoles.Admin), Times.Once);
    }

    [Fact]
    public async Task SetAdminAsync_UserNotFound_ReturnsFailure()
    {
        // Arrange
        _userManagerMock
            .Setup(x => x.FindByIdAsync("nonexistent"))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _authService.SetAdminAsync("nonexistent");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.NotFound);
        result.Error.Should().Be(AuthErrorMessages.UserNotFound("nonexistent"));

        // Verify no further operations
        _userManagerMock.Verify(x => x.IsInRoleAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Never);
        _userManagerMock.Verify(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task SetAdminAsync_DeactivatedUser_ReturnsFailure()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            IsActive = false
        };

        _userManagerMock
            .Setup(x => x.FindByIdAsync("user-id-123"))
            .ReturnsAsync(user);

        // Act
        var result = await _authService.SetAdminAsync("user-id-123");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.BadRequest);
        result.Error.Should().Be(AuthErrorMessages.CannotModifyDeactivatedRoles);

        // Verify no role operations
        _userManagerMock.Verify(x => x.IsInRoleAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Never);
        _userManagerMock.Verify(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task SetAdminAsync_AlreadyAdmin_ReturnsFailure()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            IsActive = true
        };

        _userManagerMock
            .Setup(x => x.FindByIdAsync("user-id-123"))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.IsInRoleAsync(user, AppRoles.Admin))
            .ReturnsAsync(true);

        // Act
        var result = await _authService.SetAdminAsync("user-id-123");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.Conflict);
        result.Error.Should().Be(AuthErrorMessages.AlreadyAdmin);

        // Verify AddToRole was never called
        _userManagerMock.Verify(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task SetAdminAsync_WhenAddToRoleFails_ReturnsFailure()
    {
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            IsActive = true
        };

        _userManagerMock
            .Setup(x => x.FindByIdAsync("user-id-123"))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.IsInRoleAsync(user, AppRoles.Admin))
            .ReturnsAsync(false);

        _userManagerMock
            .Setup(x => x.AddToRoleAsync(user, AppRoles.Admin))
            .ReturnsAsync(IdentityResult.Failed(
                new IdentityError { Description = "Role assignment failed" }));

        // Act
        var result = await _authService.SetAdminAsync("user-id-123");

        // Assert
        result.IsSuccess.Should().BeFalse();
        result.StatusCode.Should().Be((int)HttpStatusCode.BadRequest);
        result.Error.Should().Contain("Role assignment failed");
    }

    #endregion

    #region LogoutAsync Tests

    [Fact]
    public async Task LogoutAsync_WithValidUser_ClearsRefreshTokenAndReturnsSuccess()
    {
        var refreshTokenExpiry = DateTime.UtcNow.AddDays(7);
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            RefreshToken = "some-refresh-token",
            RefreshTokenExpiryTime = refreshTokenExpiry
        };

        _userManagerMock
            .Setup(x => x.FindByIdAsync("user-id-123"))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _authService.LogoutAsync("user-id-123");

        // Assert
        result.IsSuccess.Should().BeTrue();
        user.RefreshToken.Should().BeNullOrEmpty();
        user.RefreshTokenExpiryTime.Should().BeNull();

        // Verify update was called
        _userManagerMock.Verify(x => x.UpdateAsync(user), Times.Once);
    }

    [Fact]
    public async Task LogoutAsync_UserNotFound_StillReturnsSuccess()
    {
        // Arrange
        _userManagerMock
            .Setup(x => x.FindByIdAsync("nonexistent"))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _authService.LogoutAsync("nonexistent");

        // Assert
        result.IsSuccess.Should().BeTrue();

        // Verify no update was attempted
        _userManagerMock.Verify(x => x.UpdateAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }

    [Fact]
    public async Task LogoutAsync_WithAlreadyNullRefreshToken_StillReturnsSuccess()
    {
        var refreshTokenExpiry = DateTime.UtcNow.AddDays(7);
        // Arrange
        var user = new ApplicationUser
        {
            Id = "user-id-123",
            RefreshToken = String.Empty,
            RefreshTokenExpiryTime = refreshTokenExpiry
        };

        _userManagerMock
            .Setup(x => x.FindByIdAsync("user-id-123"))
            .ReturnsAsync(user);

        _userManagerMock
            .Setup(x => x.UpdateAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _authService.LogoutAsync("user-id-123");

        // Assert
        result.IsSuccess.Should().BeTrue();
        user.RefreshToken.Should().BeNullOrEmpty();
        user.RefreshTokenExpiryTime.Should().BeNull();
    }

    #endregion
}
