using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using VulnTracker.Api.DTOs;
using VulnTracker.Api.Models;

namespace VulnTracker.Api.Services;

public sealed class AuditIntegrityService : IAuditIntegrityService{
    private const int HmacKeySizeBytes = 32;
    private static readonly byte[] HkdfInfo = Encoding.UTF8.GetBytes("vulntracker:audit-log-hmac:v1");

    private readonly string _activeKeyId;
    private readonly Dictionary<string, byte[]> _masterKeys = new(StringComparer.Ordinal);

    public string ActiveKeyId => _activeKeyId;
    public string GenesisHash => "GENESIS";

    public AuditIntegrityService(IOptions<EncryptionOptions> options){
        var cfg = options.Value;
        if (string.IsNullOrWhiteSpace(cfg.ActiveKeyId) || cfg.Keys is null || cfg.Keys.Count == 0){
            throw new InvalidOperationException(
                "Encryption:ActiveKeyId and Encryption:Keys must be configured for audit HMAC derivation.");
        }

        foreach (var (keyId, base64Key) in cfg.Keys){
            var keyBytes = Convert.FromBase64String(base64Key);
            if (keyBytes.Length != HmacKeySizeBytes)
            {
                throw new InvalidOperationException(
                    $"Master key '{keyId}' must be 256 bits for audit HMAC derivation.");
            }
            _masterKeys[keyId] = keyBytes;
        }

        if (!_masterKeys.ContainsKey(cfg.ActiveKeyId)){
            throw new InvalidOperationException(
                $"ActiveKeyId '{cfg.ActiveKeyId}' not found in Encryption:Keys.");
        }

        _activeKeyId = cfg.ActiveKeyId;
    }

    public DateTime NormalizeTimestamp(DateTime utcDateTime) {
        var utc = DateTime.SpecifyKind(utcDateTime, DateTimeKind.Utc);
        return new DateTime(utc.Ticks - (utc.Ticks % TimeSpan.TicksPerMillisecond), DateTimeKind.Utc);
    }

    public string ComputeEntryHash(AuditLogEntry entry){
        if (!_masterKeys.TryGetValue(entry.KeyId, out var masterKey)){
            throw new CryptographicException($"Audit HMAC key '{entry.KeyId}' is not available in keyring.");
        }

        var canonicalPayload = BuildCanonicalString(entry);
        var payloadBytes = Encoding.UTF8.GetBytes(canonicalPayload);

        var hmacKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            masterKey,
            HmacKeySizeBytes,
            salt: null,
            info: HkdfInfo);

        try{
            var hashBytes = HMACSHA256.HashData(hmacKey, payloadBytes);
            return Convert.ToHexStringLower(hashBytes);
        }
        finally{
            CryptographicOperations.ZeroMemory(hmacKey);
        }
    }

    public AuditChainVerificationResultDto VerifyChain(IReadOnlyList<AuditLogEntry> orderedEntries){
        if (orderedEntries.Count == 0){
            return new AuditChainVerificationResultDto(
                IsIntact: true,
                TotalEntries: 0,
                BrokenAtSequenceNumber: null,
                Message: "Audit trail is empty and intact.");
        }

        var expectedSequence = 1L;
        var expectedPreviousHash = GenesisHash;

        foreach (var entry in orderedEntries){
            if (entry.SequenceNumber != expectedSequence){
                return new AuditChainVerificationResultDto(
                    IsIntact: false,
                    TotalEntries: orderedEntries.Count,
                    BrokenAtSequenceNumber: expectedSequence,
                    Message: $"Missing or out-of-order entry: expected sequence #{expectedSequence}, found #{entry.SequenceNumber}.");
            }

            if (!string.Equals(entry.PreviousHash, expectedPreviousHash, StringComparison.Ordinal)){
                return new AuditChainVerificationResultDto(
                    IsIntact: false,
                    TotalEntries: orderedEntries.Count,
                    BrokenAtSequenceNumber: entry.SequenceNumber,
                    Message: $"Broken hash chain at sequence #{entry.SequenceNumber}: previous hash mismatch.");
            }

            string expectedHash;
            try{
                expectedHash = ComputeEntryHash(entry);
            }
            catch (CryptographicException ex){
                return new AuditChainVerificationResultDto(
                    IsIntact: false,
                    TotalEntries: orderedEntries.Count,
                    BrokenAtSequenceNumber: entry.SequenceNumber,
                    Message: $"Verification failed at sequence #{entry.SequenceNumber}: {ex.Message}");
            }

            var actualBytes = Encoding.UTF8.GetBytes(entry.EntryHash ?? string.Empty);
            var expectedBytes = Encoding.UTF8.GetBytes(expectedHash);

            if (actualBytes.Length != expectedBytes.Length || !CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes)){
                return new AuditChainVerificationResultDto(
                    IsIntact: false,
                    TotalEntries: orderedEntries.Count,
                    BrokenAtSequenceNumber: entry.SequenceNumber,
                    Message: $"Tampering detected at sequence #{entry.SequenceNumber}: HMAC-SHA256 mismatch.");
            }

            expectedSequence++;
            expectedPreviousHash = entry.EntryHash;
        }

        return new AuditChainVerificationResultDto(
            IsIntact: true,
            TotalEntries: orderedEntries.Count,
            BrokenAtSequenceNumber: null,
            Message: $"Audit chain intact: all {orderedEntries.Count} HMAC-SHA256 links verified.");
    }

    private string BuildCanonicalString(AuditLogEntry e){
        var normalizedTime = NormalizeTimestamp(e.TimestampUtc).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        return string.Join('\u001f',
            e.SequenceNumber.ToString(),
            e.Id.ToString("N"),
            normalizedTime,
            e.ActorId,
            e.ActorUsername,
            e.ActorRole,
            e.Action,
            e.FindingId.ToString("N"),
            e.Details,
            e.KeyId,
            e.PreviousHash);
    }
}