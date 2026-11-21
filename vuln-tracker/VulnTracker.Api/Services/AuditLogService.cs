using VulnTracker.Api.Data;
using VulnTracker.Api.DTOs;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Services;

public class AuditLogService(IAuditLogRepository repository, IAuditIntegrityService integrity) : IAuditLogService{
    private static readonly SemaphoreSlim AppendLock = new(1, 1);

    public async Task<AuditLogEntry> RecordAsync(AuditActor actor, string action, Guid findingId, string details){
        await AppendLock.WaitAsync();
        try{
            var latest = await repository.GetLatestAsync();
            var nextSequence = (latest?.SequenceNumber ?? 0) + 1;
            var previousHash = latest?.EntryHash ?? integrity.GenesisHash;

            var entry = new AuditLogEntry{
                Id = Guid.NewGuid(),
                SequenceNumber = nextSequence,
                TimestampUtc = integrity.NormalizeTimestamp(DateTime.UtcNow),
                ActorId = actor.ActorId,
                ActorUsername = actor.ActorUsername,
                ActorRole = actor.ActorRole,
                Action = action,
                FindingId = findingId,
                Details = details,
                KeyId = integrity.ActiveKeyId,
                PreviousHash = previousHash,
                EntryHash = string.Empty
            };

            entry.EntryHash = integrity.ComputeEntryHash(entry);
            return await repository.AppendAsync(entry);
        }
        finally{
            AppendLock.Release();
        }
    }

    public async Task<List<AuditLogEntry>> GetLogsAsync(Guid? findingId = null){
        if (findingId.HasValue)
        {
            return await repository.GetByFindingIdAsync(findingId.Value);
        }

        var entries = await repository.GetAllOrderedBySequenceAsync();
        entries.Reverse(); 
        return entries;
    }

    public async Task<AuditChainVerificationResultDto> VerifyIntegrityAsync(){
        var orderedEntries = await repository.GetAllOrderedBySequenceAsync();
        return integrity.VerifyChain(orderedEntries);
    }
}