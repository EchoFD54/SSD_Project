using VulnTracker.Api.DTOs;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Services;

public interface IFindingService{
    Task<IEnumerable<Finding>> GetAllAsync();
    Task<Finding?> GetByIdAsync(Guid id);
    Task<Finding> CreatePublicAsync(PublicFindingSubmissionDto dto);
    Task<Finding> CreateInternalAsync(CreateFindingDto dto);
    Task<Finding?> UpdateAsync(Guid id, UpdateFindingDto dto);
    Task<Finding?> AssignAsync(Guid id, string assignedToUserId);
    Task<Finding?> SetSlaAsync(Guid id, DateTime slaDueDate);
}