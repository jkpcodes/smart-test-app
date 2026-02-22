namespace SmartTest.App.Constants.ErrorMessages;

public static class AuthErrorMessages
{
    public const string InvalidCredentials = "Invalid email or password.";
    public const string AccountDeactivated = "This account has been deactivated. Please contact support.";
    public const string AccountLockedOut = "Account is locked out. Please try again later.";
    public const string InvalidAccessToken = "Invalid access token.";
    public const string RefreshTokenExpired = "Refresh token is invalid or has expired. Please log in again.";

    public const string AccountCreationFailed = "User registration failed. Please try again.";

    public static string EmailAlreadyExists(string email) =>
        $"An account with email '{email}' already exists.";

    public static string RegistrationFailed(string errors) =>
        $"User registration failed: {errors}";

    public static string UserNotFound(string userId) =>
        $"User with ID '{userId}' was not found.";

    public const string CannotModifyDeactivatedRoles = "Cannot modify roles for a deactivated account.";
    public const string AlreadyAdmin = "User already has the Admin role.";

    public static string AdminRoleFailed(string errors) =>
        $"Failed to assign Admin role: {errors}";
}