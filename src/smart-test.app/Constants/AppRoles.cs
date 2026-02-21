namespace SmartTest.App.Constants;

public static class AppRoles
{
    public const string Admin = "Admin";
    public const string User = "User";
}

public static class AppPolicies
{
    public const string AdminOnly = "AdminOnly";
    public const string UserOnly = "UserOnly";
    public const string AdminOrUser = "AdminOrUser";
}
