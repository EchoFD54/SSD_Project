using VulnTracker.Api.Data;
using VulnTracker.Api.DTOs;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Services;

public class FindingService(IFindingRepository repository, IFieldEncryptionService encryption, IAuditLogService auditLog) : IFindingService {
    private static string BuildAad(Guid findingId, string fieldName) =>
        $"finding:{findingId:N}:{fieldName}";

    public async Task<IEnumerable<Finding>> GetAllAsync(){
        var encryptedFindings = await repository.GetAllAsync();
        return encryptedFindings.Select(ToDecryptedCopy).ToList();
    }

    public async Task<Finding?> GetByIdAsync(Guid id){
        var entity = await repository.GetByIdAsync(id);
        return entity is null ? null : ToDecryptedCopy(entity);
    }

    public async Task<Finding> CreatePublicAsync(PublicFindingSubmissionDto dto){
        var id = Guid.NewGuid();
        var entity = new Finding
        {
            Id = id,
            Title = encryption.Encrypt(dto.Title, BuildAad(id, nameof(Finding.Title))),
            Description = encryption.Encrypt(dto.Description, BuildAad(id, nameof(Finding.Description))),
            AffectedAsset = dto.AffectedAsset,
            ReporterEmail = encryption.Encrypt(dto.ReporterEmail, BuildAad(id, nameof(Finding.ReporterEmail))),
            Severity = SeverityLevel.Medium,
            Status = FindingStatus.New
        };

        var created = await repository.CreateAsync(entity);

        await auditLog.RecordAsync(
            AuditActor.ExternalReporter,
            "FindingSubmittedPublic",
            created.Id,
            $"External report submitted for asset '{created.AffectedAsset}' (Severity: {created.Severity}, Status: {created.Status}).");

        return ToDecryptedCopy(created);
    }

    public async Task<Finding> CreateInternalAsync(CreateFindingDto dto, AuditActor actor){
        var id = Guid.NewGuid();
        var entity = new Finding
        {
            Id = id,
            Title = encryption.Encrypt(dto.Title, BuildAad(id, nameof(Finding.Title))),
            Description = encryption.Encrypt(dto.Description, BuildAad(id, nameof(Finding.Description))),
            AffectedAsset = dto.AffectedAsset,
            Severity = dto.Severity,
            Status = FindingStatus.New
        };

        var created = await repository.CreateAsync(entity);

        await auditLog.RecordAsync(
            actor,
            "FindingCreated",
            created.Id,
            $"Internal finding created for asset '{created.AffectedAsset}' (Severity: {created.Severity}, Status: {created.Status}).");

        return ToDecryptedCopy(created);
    }

    public async Task<Finding?> UpdateAsync(Guid id, UpdateFindingDto dto, AuditActor actor){
        var entity = await repository.GetByIdAsync(id);
        if (entity is null) return null;

        var oldStatus = entity.Status;

        entity.Title = encryption.Encrypt(dto.Title, BuildAad(entity.Id, nameof(Finding.Title)));
        entity.Description = encryption.Encrypt(dto.Description, BuildAad(entity.Id, nameof(Finding.Description)));
        entity.Status = dto.Status;

        await repository.UpdateAsync(entity);

        var statusNote = oldStatus == dto.Status
            ? $"Status unchanged ({dto.Status})"
            : $"Status: {oldStatus} -> {dto.Status}";

        await auditLog.RecordAsync(
            actor,
            "FindingUpdated",
            entity.Id,
            $"{statusNote}; encrypted title/description updated.");

        return ToDecryptedCopy(entity);
    }

    public async Task<Finding?> AssignAsync(Guid id, string assignedToUserId, AuditActor actor){
        var entity = await repository.GetByIdAsync(id);
        if (entity is null) return null;

        var previousOwner = entity.AssignedToUserId ?? "Unassigned";
        var previousStatus = entity.Status;

        entity.AssignedToUserId = assignedToUserId;
        if (entity.Status == FindingStatus.New)
{
            entity.Status = FindingStatus.Triaged;
        }

        await repository.UpdateAsync(entity);

        await auditLog.RecordAsync(
            actor,
            "FindingAssigned",
            entity.Id,
            $"Owner: {previousOwner} -> {assignedToUserId}; Status: {previousStatus} -> {entity.Status}.");

        return ToDecryptedCopy(entity);
    }

    public async Task<Finding?> SetSlaAsync(Guid id, DateTime slaDueDate, AuditActor actor){
        var entity = await repository.GetByIdAsync(id);
        if (entity is null) return null;

        var previousSla = entity.SlaDueDate?.ToString("yyyy-MM-dd") ?? "None";
        var utcDueDate = DateTime.SpecifyKind(slaDueDate, DateTimeKind.Utc);
        entity.SlaDueDate = utcDueDate;

        await repository.UpdateAsync(entity);

        await auditLog.RecordAsync(
            actor,
            "FindingSlaSet",
            entity.Id,
            $"SLA due date: {previousSla} -> {utcDueDate:yyyy-MM-dd}.");

        return ToDecryptedCopy(entity);
    }

    private Finding ToDecryptedCopy(Finding entity) => new(){
        Id = entity.Id,
        Title = encryption.Decrypt(entity.Title, BuildAad(entity.Id, nameof(Finding.Title))),
        Description = encryption.Decrypt(entity.Description, BuildAad(entity.Id, nameof(Finding.Description))),
        AffectedAsset = entity.AffectedAsset,
        Severity = entity.Severity,
        DiscoveryDate = entity.DiscoveryDate,
        Status = entity.Status,
        ReporterEmail = entity.ReporterEmail is null
            ? null
            : encryption.Decrypt(entity.ReporterEmail, BuildAad(entity.Id, nameof(Finding.ReporterEmail))),
        AssignedToUserId = entity.AssignedToUserId,
        SlaDueDate = entity.SlaDueDate
    };
}