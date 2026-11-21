using VulnTracker.Api.Models;

namespace VulnTracker.Api.Data;

public interface IAuditLogRepository{
    Task<AuditLogEntry?> GetLatestAsync();
    Task<List<AuditLogEntry>> GetAllOrderedBySequenceAsync();
    Task<List<AuditLogEntry>> GetByFindingIdAsync(Guid findingId);
    Task<AuditLogEntry> AppendAsync(AuditLogEntry entry);
}