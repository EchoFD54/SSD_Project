using System.Text.Json;
using System.Text.Json.Serialization;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.DTOs;

public static class ReportJson{
    public static readonly JsonSerializerOptions CanonicalOptions = new(){
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() }
    };
}

public record ReportFiltersDto(
    string? Asset,
    string? FromUtc,
    string? ToUtc);

public record ReportSummaryDto(
    int TotalFindings,
    int OpenFindings,
    int OverdueSlaFindings,
    SortedDictionary<string, int> BySeverity,
    SortedDictionary<string, int> ByStatus);

public record ReportFindingItemDto(
    Guid Id,
    string Title,
    string Description,
    string AffectedAsset,
    SeverityLevel Severity,
    FindingStatus Status,
    string DiscoveryDateUtc,
    string? AssignedToUserId,
    string? SlaDueDateUtc);

public record ReportPayloadDto(
    Guid ReportId,
    string GeneratedAtUtc,
    string GeneratedBy,
    ReportFiltersDto Filters,
    ReportSummaryDto Summary,
    List<ReportFindingItemDto> Findings);

public record SignedReportEnvelopeDto(
    string FormatVersion,
    string Algorithm,
    string KeyId,
    string Context,
    string SignedAtUtc,
    string PayloadSha512,
    ReportPayloadDto Payload,
    string Signature);

public record ReportVerificationResultDto(
    bool IsValid,
    string Algorithm,
    string KeyId,
    string Message);

public record PublicKeyInfoDto(
    string KeyId,
    string Algorithm,
    bool IsPostQuantum,
    string PublicKeyPem);