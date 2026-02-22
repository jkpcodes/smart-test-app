using FluentValidation.TestHelper;
using SmartTest.App.DTOs.Auth;
using SmartTest.App.Validators.Auth;

namespace SmartTest.App.Tests.Validators;

public class LoginRequestValidatorTests
{
    private readonly LoginRequestValidator _validator = new();

    [Fact]
    public void Validate_WithValidRequest_ShouldPass()
    {
        var request = new LoginRequest
        {
            Email = "john@example.com",
            Password = "P@ssword123"
        };

        var result = _validator.TestValidate(request);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("not-an-email")]
    public void Validate_WithInvalidEmail_ShouldFail(string email)
    {
        var request = new LoginRequest
        {
            Email = email,
            Password = "P@ssword123"
        };

        var result = _validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.Email);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Validate_WithEmptyPassword_ShouldFail(string password)
    {
        var request = new LoginRequest
        {
            Email = "john@example.com",
            Password = password
        };

        var result = _validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.Password);
    }
}
