using FluentValidation;
using FluentValidation.AspNetCore;
using SmartTest.Api.Middlewares;
using SmartTest.App.Validators.Auth;
using SmartTest.Infrastructure.Identity;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Add OpenAPI services
builder.Services.AddOpenApi();

// Register FluentValidation validators from the App assembly
builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddValidatorsFromAssemblyContaining<RegisterRequestValidator>();

// Register Identity infrastructure (DbContext, Identity, JWT, AuthService)
builder.Services.AddIdentityInfrastructure(builder.Configuration);

var app = builder.Build();

// Global exception handling — must be first in the pipeline
app.UseExceptionMiddleware();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi(); // Map the OpenAPI JSON endpoint
    app.MapScalarApiReference();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Seed Identity roles (Admin, User)
await app.Services.SeedIdentityRolesAsync();

// Seed initial admin user from User Secrets / configuration
await app.Services.SeedAdminUserAsync(builder.Configuration);

app.Run();
