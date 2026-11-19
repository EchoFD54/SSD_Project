using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using VulnTracker.Api.Authorization;
using VulnTracker.Api.Data;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    });
    
builder.Services.AddOpenApi();

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.Cookie.Name = "VulnTracker.Auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;

    options.Events.OnRedirectToLogin = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api") &&
            !context.Request.Path.StartsWithSegments("/api/auth/login"))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };

    options.Events.OnRedirectToAccessDenied = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };
})
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.Authority = builder.Configuration["Authentication:Oidc:Authority"];
    options.ClientId = builder.Configuration["Authentication:Oidc:ClientId"];
    options.ClientSecret = builder.Configuration["Authentication:Oidc:ClientSecret"];

    options.ResponseType = OpenIdConnectResponseType.Code;
    options.UsePkce = true;
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.MapInboundClaims = false;
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();

    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");

    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "preferred_username",
        RoleClaimType = "roles"
    };
});

builder.Services.AddVulnTrackerAuthorization();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<IFindingRepository, FindingRepository>();

var app = builder.Build();

static void ApplySecurityHeaders(HttpResponse response)
{
    response.Headers["X-Content-Type-Options"] = "nosniff";
    response.Headers["Cross-Origin-Resource-Policy"] = "same-origin";
    response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
    response.Headers["Pragma"] = "no-cache";
    response.Headers["X-Frame-Options"] = "DENY";
    response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
}

static bool IsIdpUnavailable(Exception? ex)
{
    while (ex is not null)
    {
        if (ex is HttpRequestException ||
            (ex is InvalidOperationException && ex.Message.Contains("IDX20803", StringComparison.Ordinal)))
        {
            return true;
        }
        ex = ex.InnerException;
    }
    return false;
}

app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        ApplySecurityHeaders(context.Response);

        var error = context.Features.Get<IExceptionHandlerFeature>()?.Error;
        if (IsIdpUnavailable(error))
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "Identity provider is temporarily unavailable."
            });
            return;
        }

        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await context.Response.WriteAsJsonAsync(new
        {
            error = "An unexpected error occurred."
        });
    });
});

app.Use(async (context, next) =>
{
    ApplySecurityHeaders(context.Response);
    await next();
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapGet("/health", () => Results.Ok(new { status = "Healthy" }));

app.Run();