namespace VulnTracker.Api.Models;

public enum SeverityLevel { Low, Medium, High, Critical }

public enum FindingStatus { New, Triaged, InProgress, Remediated, AcceptedRisk }

public class Finding{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Title { get; set; }
    public required string Description { get; set; }
    public required string AffectedAsset { get; set; }
    public SeverityLevel Severity { get; set; }
    public DateTime DiscoveryDate { get; set; } = DateTime.UtcNow;
    public FindingStatus Status { get; set; } = FindingStatus.New;
    public string? ReporterEmail { get; set; }
    public string? AssignedToUserId { get; set; }
    public DateTime? SlaDueDate { get; set; }
}
