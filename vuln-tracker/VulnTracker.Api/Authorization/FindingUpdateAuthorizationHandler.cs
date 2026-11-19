using Microsoft.AspNetCore.Authorization;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Authorization;

public record FindingUpdateContext(Finding Finding, FindingStatus? RequestedStatus = null);

public class FindingUpdateRequirement : IAuthorizationRequirement;

public class FindingUpdateAuthorizationHandler : AuthorizationHandler<FindingUpdateRequirement, FindingUpdateContext>{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, FindingUpdateRequirement requirement, FindingUpdateContext resource){
        if (context.User.Identity?.IsAuthenticated != true){
            return Task.CompletedTask;
        }

        // RBAC: PMs and Analysts have full update authority across all findings
        if (context.User.IsInRole(AppRoles.Pm) || context.User.IsInRole(AppRoles.Analyst))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        // ReBAC + ABAC: Developers can only update findings assigned to them, and cant unilaterally mark a finding as AcceptedRisk
        if (context.User.IsInRole(AppRoles.Developer)){
            var currentUserId = context.User.FindFirst("sub")?.Value;

            var isAssignedToUser =
                !string.IsNullOrEmpty(currentUserId) &&
                string.Equals(resource.Finding.AssignedToUserId, currentUserId, StringComparison.Ordinal);

            var isDisallowedRiskAcceptance =
                resource.RequestedStatus == FindingStatus.AcceptedRisk;

            if (isAssignedToUser && !isDisallowedRiskAcceptance){
                context.Succeed(requirement);
            }
        }

        // Auditors and any other role fall through to the default of not being authorized to update findings
        return Task.CompletedTask;
    }
}