using Microsoft.AspNetCore.Authorization;

namespace VulnTracker.Api.Authorization;

public static class AuthorizationExtensions{
    public static IServiceCollection AddVulnTrackerAuthorization(this IServiceCollection services){
        services.AddAuthorization(options =>{
            options.AddPolicy(AuthPolicies.CanViewFindings, policy =>
                policy.RequireAuthenticatedUser()
                      .RequireRole(AppRoles.Pm, AppRoles.Analyst, AppRoles.Developer, AppRoles.Auditor));

            options.AddPolicy(AuthPolicies.CanCreateFindings, policy =>
                policy.RequireAuthenticatedUser()
                      .RequireRole(AppRoles.Pm, AppRoles.Analyst));

            options.AddPolicy(AuthPolicies.CanAssignFindings, policy =>
                policy.RequireAuthenticatedUser()
                      .RequireRole(AppRoles.Pm, AppRoles.Analyst));

            options.AddPolicy(AuthPolicies.CanSetSla, policy =>
                policy.RequireAuthenticatedUser()
                      .RequireRole(AppRoles.Pm));

            options.AddPolicy(AuthPolicies.CanManageUsers, policy =>
                policy.RequireAuthenticatedUser()
                      .RequireRole(AppRoles.Pm));

            options.AddPolicy(AuthPolicies.CanReadAuditLogs, policy =>
                policy.RequireAuthenticatedUser()
                      .RequireRole(AppRoles.Pm, AppRoles.Auditor));

            options.AddPolicy(AuthPolicies.CanUpdateFinding, policy =>
                policy.RequireAuthenticatedUser()
                      .AddRequirements(new FindingUpdateRequirement()));
        });

        services.AddSingleton<IAuthorizationHandler, FindingUpdateAuthorizationHandler>();

        return services;
    }
}