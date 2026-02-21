using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using SmartTest.App.Services;
using SmartTest.Domain.Settings;
using SmartTest.Infrastructure.Identity.Data;
using SmartTest.Infrastructure.Identity.Models;
using SmartTest.Infrastructure.Identity.Services;

namespace SmartTest.Infrastructure.Identity;

public static class DependencyInjection
{
    public static IServiceCollection AddIdentityInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Bind JWT settings
        var jwtSection = configuration.GetSection("JwtSettings");
        services.Configure<JwtSettings>(jwtSection);
        var jwtSettings = jwtSection.Get<JwtSettings>()!;

        // Register DbContext with PostgreSQL
        services.AddDbContext<AppIdentityDbContext>(options =>
            options.UseNpgsql(configuration.GetConnectionString("AuthConnectionString")));

        // Configure ASP.NET Core Identity
        services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                // Password settings
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequiredLength = 8;

                // Lockout settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;

                // User settings
                options.User.RequireUniqueEmail = true;
            })
            .AddEntityFrameworkStores<AppIdentityDbContext>()
            .AddDefaultTokenProviders();

        // Configure JWT Authentication
        services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings.Issuer,
                    ValidAudience = jwtSettings.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(jwtSettings.Secret)),
                    ClockSkew = TimeSpan.Zero
                };
            });

        // Configure authorization policies
        services.AddAuthorizationBuilder()
            .AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"))
            .AddPolicy("UserOnly", policy => policy.RequireRole("User"))
            .AddPolicy("AdminOrUser", policy => policy.RequireRole("Admin", "User"));

        // Register application services
        services.AddScoped<IAuthService, AuthService>();

        return services;
    }

    /// <summary>
    /// Seeds the Admin and User roles into the database.
    /// Call this after building the app: await app.Services.SeedIdentityRolesAsync();
    /// </summary>
    public static async Task SeedIdentityRolesAsync(this IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        string[] roles = ["Admin", "User"];

        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
            }
        }
    }

    /// <summary>
    /// Seeds the initial admin user from configuration (User Secrets / appsettings).
    /// Call this after seeding roles: await app.Services.SeedAdminUserAsync(configuration);
    /// </summary>
    public static async Task SeedAdminUserAsync(
        this IServiceProvider serviceProvider,
        IConfiguration configuration)
    {
        var adminSettings = configuration.GetSection("AdminUser").Get<AdminUserSettings>();

        if (adminSettings is null
            || string.IsNullOrWhiteSpace(adminSettings.Email)
            || string.IsNullOrWhiteSpace(adminSettings.Password))
        {
            return; // No admin config provided — skip seeding
        }

        using var scope = serviceProvider.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var existingUser = await userManager.FindByEmailAsync(adminSettings.Email);
        if (existingUser is not null)
        {
            return; // Admin already exists — skip
        }

        var adminUser = new ApplicationUser
        {
            Email = adminSettings.Email,
            UserName = adminSettings.Username,
            FirstName = adminSettings.FirstName,
            LastName = adminSettings.LastName,
            EmailConfirmed = true,
            IsActive = true
        };

        var result = await userManager.CreateAsync(adminUser, adminSettings.Password);

        if (result.Succeeded)
        {
            await userManager.AddToRoleAsync(adminUser, "Admin");
        }
        else
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new Exception($"Failed to seed admin user: {errors}");
        }
    }
}
