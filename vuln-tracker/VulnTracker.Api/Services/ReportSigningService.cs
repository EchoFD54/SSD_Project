using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using VulnTracker.Api.DTOs;

namespace VulnTracker.Api.Services;

#pragma warning disable SYSLIB5006 

public sealed class ReportSigningService : IReportSigningService, IDisposable{
    private const string FormatVersion = "1.0";
    private const string SigningContext = "vulntracker:report:v1";
    private const string MlDsa65Algorithm = "ML-DSA-65";
    private const string EcdsaP384Algorithm = "ECDSA-P384-SHA384";

    private static readonly byte[] ContextBytes = Encoding.UTF8.GetBytes(SigningContext);

    private readonly Lock _keyLock = new();
    private readonly string _keyId;
    private readonly string _algorithm;
    private readonly bool _isPostQuantum;
    private readonly string _publicKeyPem;
    private readonly MLDsa? _mlDsaKey;
    private readonly ECDsa? _ecDsaKey;

    public ReportSigningService(IOptions<SigningOptions> options, IHostEnvironment environment, ILogger<ReportSigningService> logger){
        var cfg = options.Value;
        _keyId = string.IsNullOrWhiteSpace(cfg.KeyId) ? "sig-k1" : cfg.KeyId;

        var configuredPem = string.IsNullOrWhiteSpace(cfg.PrivateKeyPem)
            ? null
            : cfg.PrivateKeyPem.Replace("\\n", "\n");

        if (configuredPem is null && !environment.IsDevelopment()){
            throw new InvalidOperationException(
                "Signing:PrivateKeyPem must be configured outside Development.");
        }

        if (MLDsa.IsSupported){
            _algorithm = MlDsa65Algorithm;
            _isPostQuantum = true;

            if (configuredPem is not null){
                _mlDsaKey = MLDsa.ImportFromPem(configuredPem);
            }
            else{
                _mlDsaKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
                logger.LogWarning(
                    "Generated ephemeral ML-DSA-65 signing key '{KeyId}' for Development.", _keyId);
            }

            _publicKeyPem = _mlDsaKey.ExportSubjectPublicKeyInfoPem();
        }
        else{
            _algorithm = EcdsaP384Algorithm;
            _isPostQuantum = false;

            _ecDsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            if (configuredPem is not null)
            {
                _ecDsaKey.ImportFromPem(configuredPem);
            }
            else
            {
                logger.LogWarning(
                    "OS lacks OpenSSL 3.5+ / CNG PQC support; using crypto-agile fallback {Algorithm} with ephemeral key '{KeyId}'.",
                    _algorithm, _keyId);
            }

            _publicKeyPem = _ecDsaKey.ExportSubjectPublicKeyInfoPem();
        }
    }

    public PublicKeyInfoDto GetPublicKeyInfo() =>
        new(_keyId, _algorithm, _isPostQuantum, _publicKeyPem);

    public SignedReportEnvelopeDto SignReport(ReportPayloadDto payload){
        ArgumentNullException.ThrowIfNull(payload);

        var canonicalBytes = JsonSerializer.SerializeToUtf8Bytes(payload, ReportJson.CanonicalOptions);
        var payloadHash = Convert.ToHexStringLower(SHA512.HashData(canonicalBytes));

        byte[] signatureBytes;
        lock (_keyLock){
            if (_mlDsaKey is not null){
                signatureBytes = _mlDsaKey.SignData(canonicalBytes, ContextBytes);
            }
            else
            {
                var domainSeparated = CombineContextAndData(ContextBytes, canonicalBytes);
                signatureBytes = _ecDsaKey!.SignData(domainSeparated, HashAlgorithmName.SHA384);
            }
        }

        return new SignedReportEnvelopeDto(
            FormatVersion: FormatVersion,
            Algorithm: _algorithm,
            KeyId: _keyId,
            Context: SigningContext,
            SignedAtUtc: DateTime.UtcNow.ToString("O"),
            PayloadSha512: payloadHash,
            Payload: payload,
            Signature: Convert.ToBase64String(signatureBytes));
    }

    public ReportVerificationResultDto VerifyReport(SignedReportEnvelopeDto envelope){
        if (envelope?.Payload is null || string.IsNullOrWhiteSpace(envelope.Signature)){
            return new ReportVerificationResultDto(
                false, envelope?.Algorithm ?? "unknown", envelope?.KeyId ?? "unknown",
                "Report payload or signature is missing.");
        }

        if (!string.Equals(envelope.KeyId, _keyId, StringComparison.Ordinal)){
            return new ReportVerificationResultDto(
                false, envelope.Algorithm, envelope.KeyId,
                $"Unknown signing key ID '{envelope.KeyId}'. Expected '{_keyId}'.");
        }

        if (!string.Equals(envelope.Algorithm, _algorithm, StringComparison.Ordinal)){
            return new ReportVerificationResultDto(
                false, envelope.Algorithm, envelope.KeyId,
                $"Algorithm mismatch: report claims '{envelope.Algorithm}', expected '{_algorithm}'.");
        }

        if (!string.Equals(envelope.Context, SigningContext, StringComparison.Ordinal)){
            return new ReportVerificationResultDto(
                false, envelope.Algorithm, envelope.KeyId,
                "Invalid signing context.");
        }

        byte[] signatureBytes;
        try{
            signatureBytes = Convert.FromBase64String(envelope.Signature);
        }
        catch (FormatException){
            return new ReportVerificationResultDto(
                false, envelope.Algorithm, envelope.KeyId,
                "Signature is not valid Base64.");
        }

        var canonicalBytes = JsonSerializer.SerializeToUtf8Bytes(envelope.Payload, ReportJson.CanonicalOptions);
        var expectedHashBytes = SHA512.HashData(canonicalBytes);

        byte[] claimedHashBytes;
        try{
            claimedHashBytes = Convert.FromHexString(envelope.PayloadSha512 ?? string.Empty);
        }
        catch (FormatException){
            return new ReportVerificationResultDto(
                false, envelope.Algorithm, envelope.KeyId,
                "Payload SHA-512 digest is malformed.");
        }

        var hashMatches =
            claimedHashBytes.Length == expectedHashBytes.Length &&
            CryptographicOperations.FixedTimeEquals(claimedHashBytes, expectedHashBytes);

        bool signatureValid;
        lock (_keyLock){
            if (_mlDsaKey is not null){
                signatureValid = _mlDsaKey.VerifyData(canonicalBytes, signatureBytes, ContextBytes);
            }
            else
            {
                var domainSeparated = CombineContextAndData(ContextBytes, canonicalBytes);
                signatureValid = _ecDsaKey!.VerifyData(
                    domainSeparated, signatureBytes, HashAlgorithmName.SHA384);
            }
        }

        if (!hashMatches || !signatureValid){
            return new ReportVerificationResultDto(
                false, envelope.Algorithm, envelope.KeyId,
                "Tampering detected: cryptographic signature verification failed.");
        }

        return new ReportVerificationResultDto(
            true, envelope.Algorithm, envelope.KeyId,
            $"Signature valid ({envelope.Algorithm}). Report is authentic and untampered.");
    }

    private static byte[] CombineContextAndData(byte[] context, byte[] data){
        var combined = new byte[context.Length + 1 + data.Length];
        context.CopyTo(combined, 0);
        combined[context.Length] = (byte)'|';
        data.CopyTo(combined, context.Length + 1);
        return combined;
    }

    public void Dispose(){
        _mlDsaKey?.Dispose();
        _ecDsaKey?.Dispose();
    }
}

#pragma warning restore SYSLIB5006