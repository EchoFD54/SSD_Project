using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulnTracker.Api.Authorization;
using VulnTracker.Api.DTOs;
using VulnTracker.Api.Services;

namespace VulnTracker.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class FindingsController(IFindingService findingService, IAuthorizationService authorizationService) : ControllerBase{
    private AuditActor GetCurrentActor(){
        var sub = User.FindFirst("sub")?.Value ?? "unknown";
        var username = User.FindFirst("preferred_username")?.Value ?? "unknown";
        var roles = string.Join(",", User.FindAll("roles").Select(c => c.Value));
        return new AuditActor(sub, username, string.IsNullOrEmpty(roles) ? "None" : roles);
    }

    [HttpPost("public")]
    [AllowAnonymous]
    public async Task<IActionResult> SubmitPublic([FromBody] PublicFindingSubmissionDto dto){
        var created = await findingService.CreatePublicAsync(dto);

        return Accepted(new
        {
            referenceId = created.Id,
            message = "Thank you. Your vulnerability report has been received for triage."
        });
    }

    [HttpGet]
    [Authorize(Policy = AuthPolicies.CanViewFindings)]
    public async Task<IActionResult> GetAll(){
        var findings = await findingService.GetAllAsync();
        return Ok(findings);
    }

    [HttpPost]
    [Authorize(Policy = AuthPolicies.CanCreateFindings)]
    public async Task<IActionResult> Create([FromBody] CreateFindingDto dto){
        var created = await findingService.CreateInternalAsync(dto, GetCurrentActor());
        return CreatedAtAction(nameof(GetAll), new { id = created.Id }, created);
    }

    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateFindingDto dto){
        var finding = await findingService.GetByIdAsync(id);
        if (finding is null) return NotFound();

        var authContext = new FindingUpdateContext(finding, dto.Status);
        var authResult = await authorizationService.AuthorizeAsync(
            User, authContext, AuthPolicies.CanUpdateFinding);

        if (!authResult.Succeeded)
        {
            return Forbid();
        }

        var updated = await findingService.UpdateAsync(id, dto, GetCurrentActor());
        return updated is null ? NotFound() : Ok(updated);
    }

    [HttpPatch("{id:guid}/assign")]
    [Authorize(Policy = AuthPolicies.CanAssignFindings)]
    public async Task<IActionResult> Assign(Guid id, [FromBody] AssignFindingDto dto){
        var updated = await findingService.AssignAsync(id, dto.AssignedToUserId, GetCurrentActor());
        return updated is null ? NotFound() : Ok(updated);
    }

    [HttpPatch("{id:guid}/sla")]
    [Authorize(Policy = AuthPolicies.CanSetSla)]
    public async Task<IActionResult> SetSla(Guid id, [FromBody] SetSlaDto dto){
        var updated = await findingService.SetSlaAsync(id, dto.SlaDueDate, GetCurrentActor());
        return updated is null ? NotFound() : Ok(updated);
    }
}