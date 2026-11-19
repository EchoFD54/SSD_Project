using System.ComponentModel.DataAnnotations;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.DTOs;

public record PublicFindingSubmissionDto(
    [Required, StringLength(200)] string Title,
    [Required, StringLength(4000)] string Description,
    [Required, StringLength(200)] string AffectedAsset,
    [Required, EmailAddress] string ReporterEmail);

public record CreateFindingDto(
    [Required, StringLength(200)] string Title,
    [Required, StringLength(4000)] string Description,
    [Required, StringLength(200)] string AffectedAsset,
    SeverityLevel Severity);

public record UpdateFindingDto(
    [Required, StringLength(200)] string Title,
    [Required, StringLength(4000)] string Description,
    FindingStatus Status);

public record AssignFindingDto([Required] string AssignedToUserId);

public record SetSlaDto([Required] DateTime SlaDueDate);