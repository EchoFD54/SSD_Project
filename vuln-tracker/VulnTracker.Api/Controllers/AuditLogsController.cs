using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulnTracker.Api.Authorization;
using VulnTracker.Api.DTOs;
using VulnTracker.Api.Models;
using VulnTracker.Api.Services;

namespace VulnTracker.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = AuthPolicies.CanReadAuditLogs)]
public class AuditLogsController(IAuditLogService auditLogService) : ControllerBase{
    [HttpGet]
    public async Task<ActionResult<List<AuditLogEntry>>> GetAll([FromQuery] Guid? findingId = null){
        var logs = await auditLogService.GetLogsAsync(findingId);
        return Ok(logs);
    }

    [HttpGet("verify")]
    public async Task<ActionResult<AuditChainVerificationResultDto>> Verify(){
        var result = await auditLogService.VerifyIntegrityAsync();
        return Ok(result);
    }
}