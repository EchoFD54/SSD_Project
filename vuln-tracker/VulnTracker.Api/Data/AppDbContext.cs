using Microsoft.EntityFrameworkCore;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options){
    public DbSet<Finding> Findings => Set<Finding>();
}