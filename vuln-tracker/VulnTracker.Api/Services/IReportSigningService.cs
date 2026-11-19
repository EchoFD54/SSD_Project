using VulnTracker.Api.DTOs;

namespace VulnTracker.Api.Services;

public class SigningOptions{
    public const string SectionName = "Signing";

    public string KeyId { get; set; } = "sig-k1";

    public string? PrivateKeyPem { get; set; } // nullable for now since i sont know/not sure if this is mandatory 
}

public interface IReportSigningService{
    PublicKeyInfoDto GetPublicKeyInfo();
    SignedReportEnvelopeDto SignReport(ReportPayloadDto payload);
    ReportVerificationResultDto VerifyReport(SignedReportEnvelopeDto envelope);
}