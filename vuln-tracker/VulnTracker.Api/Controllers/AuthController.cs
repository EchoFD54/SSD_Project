using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace VulnTracker.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase{
    [HttpGet("login")]
    public IActionResult Login([FromQuery] string? returnUrl = "/"){
        var safeRedirect = Url.IsLocalUrl(returnUrl) ? returnUrl : "/";

        return Challenge(
            new AuthenticationProperties { RedirectUri = safeRedirect },
            OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpPost("logout")]
    public IActionResult Logout(){
        if (User.Identity?.IsAuthenticated != true){
            return Redirect("/");
        }

        return SignOut(
            new AuthenticationProperties { RedirectUri = "/" },
            CookieAuthenticationDefaults.AuthenticationScheme,
            OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpGet("me")]
    public IActionResult Me(){
        if (User.Identity?.IsAuthenticated != true){
            return Ok(new { isAuthenticated = false });
        }

        return Ok(new{
            isAuthenticated = true,
            subject = User.FindFirst("sub")?.Value,
            username = User.FindFirst("preferred_username")?.Value,
            email = User.FindFirst("email")?.Value,
            roles = User.FindAll("roles").Select(c => c.Value).ToArray()
        });
    }
}