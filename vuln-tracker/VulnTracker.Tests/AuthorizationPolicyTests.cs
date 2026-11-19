using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using VulnTracker.Api.Authorization;
using VulnTracker.Api.Models;

namespace VulnTracker.Tests;

public class AuthorizationPolicyTests{
    private readonly IAuthorizationService _authService;

    public AuthorizationPolicyTests(){
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddVulnTrackerAuthorization();
        _authService = services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
    }

    private static ClaimsPrincipal CreateUser(string sub, params string[] roles){
        var claims = new List<Claim> { new("sub", sub) };
        claims.AddRange(roles.Select(r => new Claim("roles", r)));

        var identity = new ClaimsIdentity(claims, authenticationType: "TestOidc", nameType: "preferred_username", roleType: "roles");
        return new ClaimsPrincipal(identity);
    }

    private static ClaimsPrincipal CreateAnonymousUser() => new(new ClaimsIdentity());

    private static Finding CreateFinding(string? assignedToUserId = null) => new(){
        Title = "SQL Injection in Login",
        Description = "Unsanitized input in query",
        AffectedAsset = "auth-service",
        Severity = SeverityLevel.Critical,
        AssignedToUserId = assignedToUserId
    };


    [Theory]
    [InlineData(AppRoles.Pm, AuthPolicies.CanViewFindings, true)]
    [InlineData(AppRoles.Analyst, AuthPolicies.CanViewFindings, true)]
    [InlineData(AppRoles.Developer, AuthPolicies.CanViewFindings, true)]
    [InlineData(AppRoles.Auditor, AuthPolicies.CanViewFindings, true)]
    [InlineData(AppRoles.Pm, AuthPolicies.CanCreateFindings, true)]
    [InlineData(AppRoles.Analyst, AuthPolicies.CanCreateFindings, true)]
    [InlineData(AppRoles.Developer, AuthPolicies.CanCreateFindings, false)]
    [InlineData(AppRoles.Auditor, AuthPolicies.CanCreateFindings, false)]
    [InlineData(AppRoles.Pm, AuthPolicies.CanSetSla, true)]
    [InlineData(AppRoles.Analyst, AuthPolicies.CanSetSla, false)]
    [InlineData(AppRoles.Developer, AuthPolicies.CanSetSla, false)]
    [InlineData(AppRoles.Auditor, AuthPolicies.CanSetSla, false)]
    [InlineData(AppRoles.Pm, AuthPolicies.CanReadAuditLogs, true)]
    [InlineData(AppRoles.Auditor, AuthPolicies.CanReadAuditLogs, true)]
    [InlineData(AppRoles.Analyst, AuthPolicies.CanReadAuditLogs, false)]
    [InlineData(AppRoles.Developer, AuthPolicies.CanReadAuditLogs, false)]
    public async Task RbacPolicies_EnforceRoleMatrix(string role, string policy, bool expectedAllowed){
        var user = CreateUser("user-1", role);

        var result = await _authService.AuthorizeAsync(user, policy);

        Assert.Equal(expectedAllowed, result.Succeeded);
    }

    [Fact]
    public async Task AnonymousUser_IsDenied_AllProtectedPolicies(){
        var anonymous = CreateAnonymousUser();

        var viewResult = await _authService.AuthorizeAsync(anonymous, AuthPolicies.CanViewFindings);
        var createResult = await _authService.AuthorizeAsync(anonymous, AuthPolicies.CanCreateFindings);

        Assert.False(viewResult.Succeeded);
        Assert.False(createResult.Succeeded);
    }


    [Fact]
    public async Task Developer_CanUpdate_FindingAssignedToThemselves(){
        var dev = CreateUser("dev-123", AppRoles.Developer);
        var finding = CreateFinding(assignedToUserId: "dev-123");
        var resource = new FindingUpdateContext(finding, FindingStatus.InProgress);

        var result = await _authService.AuthorizeAsync(dev, resource, AuthPolicies.CanUpdateFinding);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Developer_CannotUpdate_FindingAssignedToAnotherUser(){
        var dev = CreateUser("dev-123", AppRoles.Developer);
        var finding = CreateFinding(assignedToUserId: "dev-999");
        var resource = new FindingUpdateContext(finding, FindingStatus.InProgress);

        var result = await _authService.AuthorizeAsync(dev, resource, AuthPolicies.CanUpdateFinding);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task Developer_CannotMarkAssignedFinding_AsAcceptedRisk(){
        var dev = CreateUser("dev-123", AppRoles.Developer);
        var finding = CreateFinding(assignedToUserId: "dev-123");
        var resource = new FindingUpdateContext(finding, FindingStatus.AcceptedRisk);

        var result = await _authService.AuthorizeAsync(dev, resource, AuthPolicies.CanUpdateFinding);

        Assert.False(result.Succeeded);
    }

    [Theory]
    [InlineData(AppRoles.Pm)]
    [InlineData(AppRoles.Analyst)]
    public async Task PmAndAnalyst_CanUpdateAnyFinding_IncludingAcceptedRisk(string role){
        var user = CreateUser("staff-1", role);
        var finding = CreateFinding(assignedToUserId: "dev-999");
        var resource = new FindingUpdateContext(finding, FindingStatus.AcceptedRisk);

        var result = await _authService.AuthorizeAsync(user, resource, AuthPolicies.CanUpdateFinding);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Auditor_CannotUpdate_AnyFinding(){
        var auditor = CreateUser("auditor-1", AppRoles.Auditor);
        var finding = CreateFinding(assignedToUserId: "auditor-1");
        var resource = new FindingUpdateContext(finding, FindingStatus.InProgress);

        var result = await _authService.AuthorizeAsync(auditor, resource, AuthPolicies.CanUpdateFinding);

        Assert.False(result.Succeeded);
    }
}