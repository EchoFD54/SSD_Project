using VulnTracker.Api.DTOs;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Services;

public interface IAuditIntegrityService{
    string ActiveKeyId { get; }
    string GenesisHash { get; }
    DateTime NormalizeTimestamp(DateTime utcDateTime);
    string ComputeEntryHash(AuditLogEntry entry);
    AuditChainVerificationResultDto VerifyChain(IReadOnlyList<AuditLogEntry> orderedEntries);
}