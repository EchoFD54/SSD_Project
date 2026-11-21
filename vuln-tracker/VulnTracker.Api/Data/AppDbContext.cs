using Microsoft.EntityFrameworkCore;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options){
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<AuditLogEntry> AuditLogs => Set<AuditLogEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder){
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<AuditLogEntry>(entity =>
        {
            entity.HasIndex(e => e.SequenceNumber).IsUnique();
            entity.HasIndex(e => e.FindingId);
        });
    }
}