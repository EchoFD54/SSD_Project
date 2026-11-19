using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using VulnTracker.Api.DTOs;
using VulnTracker.Api.Models;
using VulnTracker.Api.Services;

namespace VulnTracker.Tests;

public class ReportSigningTests{
    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment{
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "VulnTracker.Tests";
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private static ReportSigningService CreateService(string keyId = "sig-k1") =>
        new(
            Options.Create(new SigningOptions { KeyId = keyId }),
            new FakeHostEnvironment(Environments.Development),
            NullLogger<ReportSigningService>.Instance);

    private static ReportPayloadDto CreateSamplePayload() => new(
        ReportId: Guid.NewGuid(),
        GeneratedAtUtc: "2026-11-19T12:00:00.0000000Z",
        GeneratedBy: "alice",
        Filters: new ReportFiltersDto("auth-api", null, null),
        Summary: new ReportSummaryDto(
            TotalFindings: 1,
            OpenFindings: 1,
            OverdueSlaFindings: 0,
            BySeverity: new SortedDictionary<string, int>
            {
                ["Critical"] = 1,
                ["High"] = 0,
                ["Low"] = 0,
                ["Medium"] = 0
            },
            ByStatus: new SortedDictionary<string, int>
            {
                ["AcceptedRisk"] = 0,
                ["InProgress"] = 0,
                ["New"] = 1,
                ["Remediated"] = 0,
                ["Triaged"] = 0
            }),
        Findings:
        [
            new ReportFindingItemDto(
                Id: Guid.NewGuid(),
                Title: "SQL Injection in Login",
                Description: "Unsanitized user input in query",
                AffectedAsset: "auth-api",
                Severity: SeverityLevel.Critical,
                Status: FindingStatus.New,
                DiscoveryDateUtc: "2026-11-19T11:00:00.0000000Z",
                AssignedToUserId: "dev-123",
                SlaDueDateUtc: "2026-11-26T00:00:00.0000000Z")
        ]);

    [Fact]
    public void SignAndVerify_UntamperedReport_ReturnsValid(){
        using var sut = CreateService();
        var signed = sut.SignReport(CreateSamplePayload());

        var result = sut.VerifyReport(signed);

        Assert.True(result.IsValid);
        Assert.Equal(sut.GetPublicKeyInfo().Algorithm, result.Algorithm);
    }

    [Fact]
    public void Verify_TamperedFindingSeverity_DetectsTampering(){
        using var sut = CreateService();
        var signed = sut.SignReport(CreateSamplePayload());

        var tamperedFinding = signed.Payload.Findings[0] with { Severity = SeverityLevel.Low };
        var tamperedPayload = signed.Payload with { Findings = [tamperedFinding] };
        var tamperedEnvelope = signed with { Payload = tamperedPayload };

        var result = sut.VerifyReport(tamperedEnvelope);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Verify_TamperedSignatureBytes_DetectsTampering(){
        using var sut = CreateService();
        var signed = sut.SignReport(CreateSamplePayload());

        var sigBytes = Convert.FromBase64String(signed.Signature);
        sigBytes[0] ^= 0xFF;
        var tamperedEnvelope = signed with { Signature = Convert.ToBase64String(sigBytes) };

        var result = sut.VerifyReport(tamperedEnvelope);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Verify_SignedByDifferentKeyPair_RejectsForgedReport(){
        using var legitimateServer = CreateService("sig-k1");
        using var attackerServer = CreateService("sig-k1");

        var forged = attackerServer.SignReport(CreateSamplePayload());

        var result = legitimateServer.VerifyReport(forged);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Verify_AlgorithmDowngradeClaim_IsRejected(){
        using var sut = CreateService();
        var signed = sut.SignReport(CreateSamplePayload());
        var downgraded = signed with { Algorithm = "NONE" };

        var result = sut.VerifyReport(downgraded);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void GetPublicKeyInfo_ExportsPemPublicKeyOnly(){
        using var sut = CreateService();
        var info = sut.GetPublicKeyInfo();

        Assert.Contains("-----BEGIN PUBLIC KEY-----", info.PublicKeyPem);
        Assert.DoesNotContain("PRIVATE KEY", info.PublicKeyPem);
    }
}