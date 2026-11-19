using VulnTracker.Api.Data;
using VulnTracker.Api.DTOs;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Services;

public class FindingService(IFindingRepository repository, IFieldEncryptionService encryption) : IFindingService{
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
        return ToDecryptedCopy(created);
    }

    public async Task<Finding> CreateInternalAsync(CreateFindingDto dto){
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
        return ToDecryptedCopy(created);
    }

    public async Task<Finding?> UpdateAsync(Guid id, UpdateFindingDto dto){
        var entity = await repository.GetByIdAsync(id);
        if (entity is null) return null;

        entity.Title = encryption.Encrypt(dto.Title, BuildAad(entity.Id, nameof(Finding.Title)));
        entity.Description = encryption.Encrypt(dto.Description, BuildAad(entity.Id, nameof(Finding.Description)));
        entity.Status = dto.Status;

        await repository.UpdateAsync(entity);
        return ToDecryptedCopy(entity);
    }

    public async Task<Finding?> AssignAsync(Guid id, string assignedToUserId){
        var entity = await repository.GetByIdAsync(id);
        if (entity is null) return null;

        entity.AssignedToUserId = assignedToUserId;
        if (entity.Status == FindingStatus.New)
        {
            entity.Status = FindingStatus.Triaged;
        }

        await repository.UpdateAsync(entity);
        return ToDecryptedCopy(entity);
    }

    public async Task<Finding?> SetSlaAsync(Guid id, DateTime slaDueDate){
        var entity = await repository.GetByIdAsync(id);
        if (entity is null) return null;

        entity.SlaDueDate = DateTime.SpecifyKind(slaDueDate, DateTimeKind.Utc);
        await repository.UpdateAsync(entity);
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