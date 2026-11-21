using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using VulnTracker.Api.Services;

namespace VulnTracker.Tests;

public class FieldEncryptionTests{
    private static string GenerateKeyBase64() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static AesGcmFieldEncryptionService CreateService(string activeKeyId, Dictionary<string, string> keys){
        var options = Options.Create(new EncryptionOptions{
            ActiveKeyId = activeKeyId,
            Keys = keys
        });
        return new AesGcmFieldEncryptionService(options);
    }

    [Fact]
    public void EncryptThenDecrypt_RoundTripsPlaintext_AndHidesOriginalText(){
        var sut = CreateService("k1", new() { ["k1"] = GenerateKeyBase64() });
        const string secret = "SQL injection via /api/login username parameter";
        const string aad = "finding:12345:Description";

        var envelope = sut.Encrypt(secret, aad);
        var decrypted = sut.Decrypt(envelope, aad);

        Assert.StartsWith("v1:k1:AES-256-GCM:", envelope);
        Assert.DoesNotContain("SQL injection", envelope);
        Assert.Equal(secret, decrypted);
    }

    [Fact]
    public void Encrypt_SamePlaintextTwice_ProducesDifferentCiphertexts(){
        var sut = CreateService("k1", new() { ["k1"] = GenerateKeyBase64() });
        const string secret = "Identical vulnerability description";
        const string aad = "finding:12345:Description";

        var first = sut.Encrypt(secret, aad);
        var second = sut.Encrypt(secret, aad);

        Assert.NotEqual(first, second);
        Assert.Equal(secret, sut.Decrypt(first, aad));
        Assert.Equal(secret, sut.Decrypt(second, aad));
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_ThrowsAuthenticationTagMismatch(){
        var sut = CreateService("k1", new() { ["k1"] = GenerateKeyBase64() });
        const string aad = "finding:12345:Description";

        var parts = sut.Encrypt("Critical RCE details", aad).Split(':');
        var rawCiphertext = Convert.FromBase64String(parts[6]);
        rawCiphertext[0] ^= 0xFF; 
        parts[6] = Convert.ToBase64String(rawCiphertext);
        var tampered = string.Join(':', parts);

        Assert.Throws<AuthenticationTagMismatchException>(() => sut.Decrypt(tampered, aad));
    }

    [Fact]
    public void Decrypt_WithWrongAad_PreventsCiphertextSwappingAcrossFindings(){
        var sut = CreateService("k1", new() { ["k1"] = GenerateKeyBase64() });

        var findingACiphertext = sut.Encrypt("Secret from Finding A", "finding:AAA:Description");

       
        Assert.Throws<AuthenticationTagMismatchException>(
            () => sut.Decrypt(findingACiphertext, "finding:BBB:Description"));
    }

    [Fact]
    public void KeyRotation_NewActiveKey_DecryptsOldAndNewRecords(){
        var k1 = GenerateKeyBase64();
        var k2 = GenerateKeyBase64();
        const string aad = "finding:999:Title";

        var oldService = CreateService("k1", new() { ["k1"] = k1 });
        var oldCiphertext = oldService.Encrypt("Legacy Finding", aad);

        var rotatedService = CreateService("k2", new() { ["k1"] = k1, ["k2"] = k2 });
        var newCiphertext = rotatedService.Encrypt("New Finding", aad);

        Assert.StartsWith("v1:k2:AES-256-GCM:", newCiphertext);
        Assert.Equal("Legacy Finding", rotatedService.Decrypt(oldCiphertext, aad));
        Assert.Equal("New Finding", rotatedService.Decrypt(newCiphertext, aad));
    }

    [Fact]
    public void Constructor_InvalidKeyLength_FailsClosed(){
        var shortKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)); // 128-bit rejected

        Assert.Throws<InvalidOperationException>(
            () => CreateService("k1", new() { ["k1"] = shortKey }));
    }
}