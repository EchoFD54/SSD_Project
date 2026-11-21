namespace VulnTracker.Api.DTOs;

public record AuditActor(string ActorId, string ActorUsername, string ActorRole){
    public static readonly AuditActor ExternalReporter =
        new("external-anonymous", "External Reporter", "ExternalReporter");
}

public record AuditChainVerificationResultDto(
    bool IsIntact,
    int TotalEntries,
    long? BrokenAtSequenceNumber,
    string Message);