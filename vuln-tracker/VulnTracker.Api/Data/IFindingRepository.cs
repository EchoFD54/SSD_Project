using VulnTracker.Api.Models;

namespace VulnTracker.Api.Data;

public interface IFindingRepository{
    Task<IEnumerable<Finding>> GetAllAsync();
    Task<Finding?> GetByIdAsync(Guid id);
    Task<Finding> CreateAsync(Finding finding);
    Task UpdateAsync(Finding finding);
}