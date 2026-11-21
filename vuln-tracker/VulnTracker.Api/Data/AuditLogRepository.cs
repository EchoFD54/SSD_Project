using Microsoft.EntityFrameworkCore;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Data;

public class AuditLogRepository(AppDbContext context) : IAuditLogRepository{
    public async Task<AuditLogEntry?> GetLatestAsync() =>
        await context.AuditLogs
            .AsNoTracking()
            .OrderByDescending(e => e.SequenceNumber)
            .FirstOrDefaultAsync();

    public async Task<List<AuditLogEntry>> GetAllOrderedBySequenceAsync() =>
        await context.AuditLogs
            .AsNoTracking()
            .OrderBy(e => e.SequenceNumber)
            .ToListAsync();

    public async Task<List<AuditLogEntry>> GetByFindingIdAsync(Guid findingId) =>
        await context.AuditLogs
            .AsNoTracking()
            .Where(e => e.FindingId == findingId)
            .OrderByDescending(e => e.SequenceNumber)
            .ToListAsync();

    public async Task<AuditLogEntry> AppendAsync(AuditLogEntry entry){
        context.AuditLogs.Add(entry);
        await context.SaveChangesAsync();
        return entry;
    }
}