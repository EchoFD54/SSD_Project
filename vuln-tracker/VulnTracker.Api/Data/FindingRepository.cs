using Microsoft.EntityFrameworkCore;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Data;

public class FindingRepository(AppDbContext context) : IFindingRepository{
    public async Task<IEnumerable<Finding>> GetAllAsync() =>
        await context.Findings.AsNoTracking().ToListAsync();

    public async Task<Finding?> GetByIdAsync(Guid id) =>
        await context.Findings.FindAsync(id);

    public async Task<Finding> CreateAsync(Finding finding){
        context.Findings.Add(finding);
        await context.SaveChangesAsync();
        return finding;
    }

    public async Task UpdateAsync(Finding finding){
        context.Findings.Update(finding);
        await context.SaveChangesAsync();
    }
}