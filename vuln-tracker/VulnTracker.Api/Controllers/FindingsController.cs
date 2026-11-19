using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulnTracker.Api.Authorization;
using VulnTracker.Api.Data;
using VulnTracker.Api.DTOs;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize] // Secure by default: deny unauthenticated access unless explicitly opened
public class FindingsController(
    IFindingRepository repository,
    IAuthorizationService authorizationService) : ControllerBase{
    [HttpPost("public")]
    [AllowAnonymous]
    public async Task<IActionResult> SubmitPublic([FromBody] PublicFindingSubmissionDto dto){
        var finding = new Finding
        {
            Title = dto.Title,
            Description = dto.Description,
            AffectedAsset = dto.AffectedAsset,
            ReporterEmail = dto.ReporterEmail,
            Severity = SeverityLevel.Medium, 
            Status = FindingStatus.New
        };

        var created = await repository.CreateAsync(finding);

        return Accepted(new{
            referenceId = created.Id,
            message = "Thank you. Your vulnerability report has been received for triage."
        });
    }

    [HttpGet]
    [Authorize(Policy = AuthPolicies.CanViewFindings)]
    public async Task<IActionResult> GetAll(){
        var findings = await repository.GetAllAsync();
        return Ok(findings);
    }

    [HttpPost]
    [Authorize(Policy = AuthPolicies.CanCreateFindings)]
    public async Task<IActionResult> Create([FromBody] CreateFindingDto dto){
        var finding = new Finding
        {
            Title = dto.Title,
            Description = dto.Description,
            AffectedAsset = dto.AffectedAsset,
            Severity = dto.Severity,
            Status = FindingStatus.New
        };

        var created = await repository.CreateAsync(finding);
        return CreatedAtAction(nameof(GetAll), new { id = created.Id }, created);
    }

    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateFindingDto dto){
        var finding = await repository.GetByIdAsync(id);
        if (finding is null) return NotFound();

        var authContext = new FindingUpdateContext(finding, dto.Status);
        var authResult = await authorizationService.AuthorizeAsync(
            User, authContext, AuthPolicies.CanUpdateFinding);

        if (!authResult.Succeeded){
            return Forbid();
        }

        finding.Title = dto.Title;
        finding.Description = dto.Description;
        finding.Status = dto.Status;

        await repository.UpdateAsync(finding);
        return Ok(finding);
    }

    [HttpPatch("{id:guid}/assign")]
    [Authorize(Policy = AuthPolicies.CanAssignFindings)]
    public async Task<IActionResult> Assign(Guid id, [FromBody] AssignFindingDto dto){
        var finding = await repository.GetByIdAsync(id);
        if (finding is null) return NotFound();

        finding.AssignedToUserId = dto.AssignedToUserId;
        if (finding.Status == FindingStatus.New)
        {
            finding.Status = FindingStatus.Triaged;
        }

        await repository.UpdateAsync(finding);
        return Ok(finding);
    }

    [HttpPatch("{id:guid}/sla")]
    [Authorize(Policy = AuthPolicies.CanSetSla)]
    public async Task<IActionResult> SetSla(Guid id, [FromBody] SetSlaDto dto){
        var finding = await repository.GetByIdAsync(id);
        if (finding is null) return NotFound();

        finding.SlaDueDate = DateTime.SpecifyKind(dto.SlaDueDate, DateTimeKind.Utc);
        await repository.UpdateAsync(finding);
        return Ok(finding);
    }
}