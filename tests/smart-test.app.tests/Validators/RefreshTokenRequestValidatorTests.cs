using FluentValidation.TestHelper;
using SmartTest.App.DTOs.Auth;
using SmartTest.App.Validators.Auth;

namespace SmartTest.App.Tests.Validators;

public class RefreshTokenRequestValidatorTests
{
    private readonly RefreshTokenRequestValidator _validator = new();

    [Fact]
    public void Validate_WithValidRequest_ShouldPass()
    {
        var request = new RefreshTokenRequest
        {
            AccessToken = "valid-refresh-token",
            RefreshToken = "valid-refresh-token"
        };

        var result = _validator.TestValidate(request);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Validate_WithEmptyAccessToken_ShouldFail(string token)
    {
        var request = new RefreshTokenRequest
        {
            AccessToken = token,
            RefreshToken = "valid-refresh-token"
        };

        var result = _validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(r => r.AccessToken);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Validate_WithEmptyRefreshToken_ShouldFail(string token)
    {
        var request = new RefreshTokenRequest
        {
            AccessToken = "valid-access-token",
            RefreshToken = token
        };

        var result = _validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(r => r.RefreshToken);
    }
}
