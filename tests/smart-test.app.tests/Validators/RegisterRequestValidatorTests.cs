using FluentValidation.TestHelper;
using SmartTest.App.DTOs.Auth;
using SmartTest.App.Validators.Auth;

namespace SmartTest.App.Tests.Validators;

public class RegisterRequestValidatorTests
{
    private readonly RegisterRequestValidator _validator = new();

    [Fact]
    public void Validate_WithValidRequest_ShouldPass()
    {
        var request = new RegisterRequest
        {
            FirstName = "John",
            LastName = "Doe",
            Email = "john@example.com",
            Password = "P@ssword123",
            ConfirmPassword = "P@ssword123"
        };

        var result = _validator.TestValidate(request);
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Validate_WithEmptyFirstName_ShouldFail(string firstName)
    {
        var request = new RegisterRequest
        {
            FirstName = firstName,
            LastName = "Doe",
            Email = "john@example.com",
            Password = "P@ssword123"
        };

        var result = _validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(r => r.FirstName);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Validate_WithEmptyLastName_ShouldFail(string lastName)
    {
        var request = new RegisterRequest
        {
            FirstName = "John",
            LastName = lastName,
            Email = "john@example.com",
            Password = "P@ssword123"
        };

        var result = _validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(r => r.LastName);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Validate_WithEmptyEmail_ShouldFail(string email)
    {
        var request = new RegisterRequest
        {
            FirstName = "John",
            LastName = "Doe",
            Email = email,
            Password = "P@ssword123",
            ConfirmPassword = "P@ssword123"
        };

        var result = _validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(r => r.Email);
    }

    [Fact]
    public void Validate_WithInvalidEmail_ShouldFail()
    {
        var request = new RegisterRequest
        {
            FirstName = "John",
            LastName = "Doe",
            Email = "invalid-email",
            Password = "P@ssword123",
            ConfirmPassword = "P@ssword123"
        };

        var result = _validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(r => r.Email);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("short")]
    [InlineData("Missingnumber!")]
    [InlineData("missinguppercase1!")]
    [InlineData("MISSINGLOWERCASE1!")]
    [InlineData("MissingSpecial1")]
    public void Validate_WithInvalidPassword_ShouldFail(string? password)
    {
        var request = new RegisterRequest
        {
            FirstName = "John",
            LastName = "Doe",
            Email = "john@example.com",
            Password = password!
        };

        var result = _validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.Password);
    }

    [Fact]
    public void Validate_WithNonMatchingPasswords_ShouldFail()
    {
        var request = new RegisterRequest
        {
            FirstName = "John",
            LastName = "Doe",
            Email = "john@example.com",
            Password = "P@ssword123",
            ConfirmPassword = "DifferentPassword123"
        };

        var result = _validator.TestValidate(request);
        result.ShouldHaveValidationErrorFor(x => x.ConfirmPassword);
    }
}
