using VulnTracker.Api.DTOs;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Services;

public interface IAuditLogService{
    Task<AuditLogEntry> RecordAsync(AuditActor actor, string action, Guid findingId, string details);
    Task<List<AuditLogEntry>> GetLogsAsync(Guid? findingId = null);
    Task<AuditChainVerificationResultDto> VerifyIntegrityAsync();
}