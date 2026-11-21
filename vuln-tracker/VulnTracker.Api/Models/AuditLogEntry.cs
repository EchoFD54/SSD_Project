namespace VulnTracker.Api.Models;

public class AuditLogEntry{
    public Guid Id { get; set; } = Guid.NewGuid();
    public long SequenceNumber { get; set; }

    public DateTime TimestampUtc { get; set; }

    public required string ActorId { get; set; }
    public required string ActorUsername { get; set; }
    public required string ActorRole { get; set; }
    public required string Action { get; set; }
    public Guid FindingId { get; set; }
    public required string Details { get; set; }

    // Integrity & crypto-agility fields
    public required string KeyId { get; set; }
    public required string PreviousHash { get; set; }
    public required string EntryHash { get; set; }
}