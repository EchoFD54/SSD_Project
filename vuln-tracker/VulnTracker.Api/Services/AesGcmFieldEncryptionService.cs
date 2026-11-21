using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace VulnTracker.Api.Services;

public sealed class AesGcmFieldEncryptionService : IFieldEncryptionService{
    private const string EnvelopeVersion = "v1";
    private const string AlgorithmId = "AES-256-GCM";
    private const int KeySizeBytes = 32;   
    private const int SaltSizeBytes = 16;  
    private const int NonceSizeBytes = 12; 
    private const int TagSizeBytes = 16;   

    private readonly string _activeKeyId;
    private readonly Dictionary<string, byte[]> _masterKeys = new(StringComparer.Ordinal);

    public AesGcmFieldEncryptionService(IOptions<EncryptionOptions> options){
        var cfg = options.Value;

        if (string.IsNullOrWhiteSpace(cfg.ActiveKeyId) || cfg.ActiveKeyId.Contains(':')){
            throw new InvalidOperationException(
                "Encryption:ActiveKeyId must be configured and cannot contain ':'.");
        }

        if (cfg.Keys is null || cfg.Keys.Count == 0){
            throw new InvalidOperationException(
                "At least one 256-bit master key must be configured under Encryption:Keys.");
        }

        foreach (var (keyId, base64Key) in cfg.Keys){
            if (string.IsNullOrWhiteSpace(keyId) || keyId.Contains(':')){
                throw new InvalidOperationException($"Invalid encryption key ID: '{keyId}'.");
            }

            byte[] keyBytes;
            try{
                keyBytes = Convert.FromBase64String(base64Key);
            }
            catch (FormatException ex){
                throw new InvalidOperationException(
                    $"Encryption key '{keyId}' is not valid Base64.", ex);
            }

            if (keyBytes.Length != KeySizeBytes){
                throw new InvalidOperationException(
                    $"Encryption key '{keyId}' must be exactly {KeySizeBytes} bytes (256 bits).");
            }

            _masterKeys[keyId] = keyBytes;
        }

        if (!_masterKeys.ContainsKey(cfg.ActiveKeyId)){
            throw new InvalidOperationException(
                $"Encryption:ActiveKeyId '{cfg.ActiveKeyId}' was not found in Encryption:Keys.");
        }

        _activeKeyId = cfg.ActiveKeyId;
    }

    public string Encrypt(string plaintext, string associatedData){
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentException.ThrowIfNullOrWhiteSpace(associatedData);

        var masterKey = _masterKeys[_activeKeyId];
        var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var aadBytes = Encoding.UTF8.GetBytes(associatedData);
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSizeBytes];

        var derivedKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            masterKey,
            KeySizeBytes,
            salt,
            aadBytes);

        try{
            using var aesGcm = new AesGcm(derivedKey, TagSizeBytes);
            aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag, aadBytes);
        }
        finally{
            CryptographicOperations.ZeroMemory(derivedKey);
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }

        return string.Join(':',
            EnvelopeVersion,
            _activeKeyId,
            AlgorithmId,
            Convert.ToBase64String(salt),
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(tag),
            Convert.ToBase64String(ciphertext));
    }

    public string Decrypt(string encryptedPayload, string associatedData){
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptedPayload);
        ArgumentException.ThrowIfNullOrWhiteSpace(associatedData);

        var parts = encryptedPayload.Split(':');
        if (parts.Length != 7 || parts[0] != EnvelopeVersion || parts[2] != AlgorithmId){
            throw new CryptographicException("Invalid or unsupported ciphertext envelope format.");
        }

        var keyId = parts[1];
        if (!_masterKeys.TryGetValue(keyId, out var masterKey)){
            throw new CryptographicException($"Decryption key '{keyId}' is not available in keyring.");
        }

        byte[] salt, nonce, tag, ciphertext;
        try{
            salt = Convert.FromBase64String(parts[3]);
            nonce = Convert.FromBase64String(parts[4]);
            tag = Convert.FromBase64String(parts[5]);
            ciphertext = Convert.FromBase64String(parts[6]);
        }
        catch (FormatException ex){
            throw new CryptographicException("Corrupted Base64 encoding in ciphertext envelope.", ex);
        }

        if (salt.Length != SaltSizeBytes || nonce.Length != NonceSizeBytes || tag.Length != TagSizeBytes){
            throw new CryptographicException("Invalid cryptographic parameter lengths.");
        }

        var aadBytes = Encoding.UTF8.GetBytes(associatedData);
        var plaintextBytes = new byte[ciphertext.Length];

        var derivedKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            masterKey,
            KeySizeBytes,
            salt,
            aadBytes);

        try{
            using var aesGcm = new AesGcm(derivedKey, TagSizeBytes);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintextBytes, aadBytes);
            return Encoding.UTF8.GetString(plaintextBytes);
        }
        finally{
            CryptographicOperations.ZeroMemory(derivedKey);
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }
    }
}