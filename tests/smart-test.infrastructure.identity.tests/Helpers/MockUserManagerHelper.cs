using SmartTest.Infrastructure.Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Moq;

namespace smart_test.infrastructure.identity.tests.Helpers;

public class MockUserManagerHelper
{
    public static Mock<UserManager<ApplicationUser>> CreateMockUserManager()
        {
            var store = new Mock<IUserStore<ApplicationUser>>();
            var options = new Mock<IOptions<IdentityOptions>>();
            var passwordHasher = new Mock<IPasswordHasher<ApplicationUser>>();
            var userValidators = new List<IUserValidator<ApplicationUser>>();
            var passwordValidators = new List<IPasswordValidator<ApplicationUser>>();
            var lookupNormalizer = new Mock<ILookupNormalizer>();
            var errorDescriber = new Mock<IdentityErrorDescriber>();
            var services = new Mock<IServiceProvider>();
            var logger = new Mock<ILogger<UserManager<ApplicationUser>>>();

            options.Setup(o => o.Value).Returns(new IdentityOptions());

            return new Mock<UserManager<ApplicationUser>>(
                store.Object,
                options.Object,
                passwordHasher.Object,
                userValidators,
                passwordValidators,
                lookupNormalizer.Object,
                errorDescriber.Object,
                services.Object,
                logger.Object);
        }

    public static Mock<SignInManager<ApplicationUser>> CreateMockSignInManager(
        Mock<UserManager<ApplicationUser>> userManager)
    {
        var contextAccessor = new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
        var claimsFactory = new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>();
        var options = new Mock<IOptions<IdentityOptions>>();
        var logger = new Mock<ILogger<SignInManager<ApplicationUser>>>();
        var schemes = new Mock<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>();
        var confirmation = new Mock<IUserConfirmation<ApplicationUser>>();

        return new Mock<SignInManager<ApplicationUser>>(
            userManager.Object,
            contextAccessor.Object,
            claimsFactory.Object,
            options.Object,
            logger.Object,
            schemes.Object,
            confirmation.Object);
    }

    public static Mock<RoleManager<IdentityRole>> CreateMockRoleManager()
    {
        var store = new Mock<IRoleStore<IdentityRole>>();
        var roleValidators = new List<IRoleValidator<IdentityRole>>();
        var lookupNormalizer = new Mock<ILookupNormalizer>();
        var errorDescriber = new Mock<IdentityErrorDescriber>();
        var logger = new Mock<ILogger<RoleManager<IdentityRole>>>();

        return new Mock<RoleManager<IdentityRole>>(
            store.Object,
            roleValidators,
            lookupNormalizer.Object,
            errorDescriber.Object,
            logger.Object);
    }
}
