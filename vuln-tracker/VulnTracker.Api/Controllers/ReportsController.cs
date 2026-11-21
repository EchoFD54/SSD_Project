using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulnTracker.Api.Authorization;
using VulnTracker.Api.DTOs;
using VulnTracker.Api.Models;
using VulnTracker.Api.Services;

namespace VulnTracker.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ReportsController(IFindingService findingService, IReportSigningService signingService) : ControllerBase{
    [HttpGet("public-key")]
    [AllowAnonymous]
    public ActionResult<PublicKeyInfoDto> GetPublicKey() =>
        Ok(signingService.GetPublicKeyInfo());

    [HttpGet("export")]
    [Authorize(Policy = AuthPolicies.CanViewFindings)]
    public async Task<ActionResult<SignedReportEnvelopeDto>> Export(
        [FromQuery] string? asset = null,
        [FromQuery] DateTime? from = null,
        [FromQuery] DateTime? to = null){
        var allFindings = await findingService.GetAllAsync();

        var fromUtc = from.HasValue ? DateTime.SpecifyKind(from.Value, DateTimeKind.Utc) : (DateTime?)null;
        var toUtc = to.HasValue ? DateTime.SpecifyKind(to.Value, DateTimeKind.Utc) : (DateTime?)null;

        var filtered = allFindings.Where(f =>
            (string.IsNullOrWhiteSpace(asset) ||
             f.AffectedAsset.Contains(asset.Trim(), StringComparison.OrdinalIgnoreCase)) &&
            (!fromUtc.HasValue || f.DiscoveryDate >= fromUtc.Value) &&
            (!toUtc.HasValue || f.DiscoveryDate <= toUtc.Value))
            .OrderByDescending(f => f.DiscoveryDate)
            .ThenBy(f => f.Id)
            .ToList();

        var now = DateTime.UtcNow;
        var openFindings = filtered.Where(f =>
            f.Status is not (FindingStatus.Remediated or FindingStatus.AcceptedRisk)).ToList();

        var overdueCount = openFindings.Count(f => f.SlaDueDate.HasValue && f.SlaDueDate.Value < now);

        var bySeverity = new SortedDictionary<string, int>(StringComparer.Ordinal);
        foreach (var sev in Enum.GetValues<SeverityLevel>()){
            bySeverity[sev.ToString()] = openFindings.Count(f => f.Severity == sev);
        }

        var byStatus = new SortedDictionary<string, int>(StringComparer.Ordinal);
        foreach (var status in Enum.GetValues<FindingStatus>()){
            byStatus[status.ToString()] = filtered.Count(f => f.Status == status);
        }

        var items = filtered.Select(f => new ReportFindingItemDto(
            Id: f.Id,
            Title: f.Title,
            Description: f.Description,
            AffectedAsset: f.AffectedAsset,
            Severity: f.Severity,
            Status: f.Status,
            DiscoveryDateUtc: f.DiscoveryDate.ToUniversalTime().ToString("O"),
            AssignedToUserId: f.AssignedToUserId,
            SlaDueDateUtc: f.SlaDueDate?.ToUniversalTime().ToString("O"))).ToList();

        var payload = new ReportPayloadDto(
            ReportId: Guid.NewGuid(),
            GeneratedAtUtc: now.ToString("O"),
            GeneratedBy: User.FindFirst("preferred_username")?.Value ?? "unknown",
            Filters: new ReportFiltersDto(
                Asset: string.IsNullOrWhiteSpace(asset) ? null : asset.Trim(),
                FromUtc: fromUtc?.ToString("O"),
                ToUtc: toUtc?.ToString("O")),
            Summary: new ReportSummaryDto(
                TotalFindings: filtered.Count,
                OpenFindings: openFindings.Count,
                OverdueSlaFindings: overdueCount,
                BySeverity: bySeverity,
                ByStatus: byStatus),
            Findings: items);

        var signedReport = signingService.SignReport(payload);
        return Ok(signedReport);
    }

  
    [HttpPost("verify")]
    [Authorize(Policy = AuthPolicies.CanViewFindings)]
    public ActionResult<ReportVerificationResultDto> Verify([FromBody] SignedReportEnvelopeDto envelope){
        var result = signingService.VerifyReport(envelope);
        return Ok(result);
    }
}