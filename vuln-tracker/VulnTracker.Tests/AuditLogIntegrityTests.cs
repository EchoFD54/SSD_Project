using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using VulnTracker.Api.Models;
using VulnTracker.Api.Services;

namespace VulnTracker.Tests;

public class AuditLogIntegrityTests{
    private static string GenerateKeyBase64() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static AuditIntegrityService CreateService(
        string activeKeyId,
        Dictionary<string, string> keys) =>
        new(Options.Create(new EncryptionOptions{
            ActiveKeyId = activeKeyId,
            Keys = keys
        }));

    private static List<AuditLogEntry> BuildValidChain(AuditIntegrityService sut, int count = 3){
        var entries = new List<AuditLogEntry>();
        var prevHash = sut.GenesisHash;
        var findingId = Guid.NewGuid();

        for (var i = 1; i <= count; i++){
            var entry = new AuditLogEntry
            {
                Id = Guid.NewGuid(),
                SequenceNumber = i,
                TimestampUtc = sut.NormalizeTimestamp(DateTime.UtcNow.AddMinutes(i)),
                ActorId = $"user-{i}",
                ActorUsername = $"alice-{i}",
                ActorRole = "PM",
                Action = "FindingUpdated",
                FindingId = findingId,
                Details = $"Change #{i}",
                KeyId = sut.ActiveKeyId,
                PreviousHash = prevHash,
                EntryHash = string.Empty
            };

            entry.EntryHash = sut.ComputeEntryHash(entry);
            entries.Add(entry);
            prevHash = entry.EntryHash;
        }

        return entries;
    }

    [Fact]
    public void VerifyChain_ValidLinkedEntries_ReturnsIntact(){
        var sut = CreateService("k1", new() { ["k1"] = GenerateKeyBase64() });
        var chain = BuildValidChain(sut, 4);

        var result = sut.VerifyChain(chain);

        Assert.True(result.IsIntact);
        Assert.Equal(4, result.TotalEntries);
        Assert.Null(result.BrokenAtSequenceNumber);
    }

    [Fact]
    public void VerifyChain_AlteredEntryDetails_DetectsTamperingAtExactSequence(){
        var sut = CreateService("k1", new() { ["k1"] = GenerateKeyBase64() });
        var chain = BuildValidChain(sut, 3);

        chain[1].Details = "Tampered audit message";

        var result = sut.VerifyChain(chain);

        Assert.False(result.IsIntact);
        Assert.Equal(2, result.BrokenAtSequenceNumber);
    }

    [Fact]
    public void VerifyChain_DeletedMiddleEntry_DetectsSequenceGap(){
        var sut = CreateService("k1", new() { ["k1"] = GenerateKeyBase64() });
        var chain = BuildValidChain(sut, 3);

        chain.RemoveAt(1); 

        var result = sut.VerifyChain(chain);

        Assert.False(result.IsIntact);
        Assert.Equal(2, result.BrokenAtSequenceNumber);
    }

    [Fact]
    public void VerifyChain_DeletedFirstEntry_DetectsMissingGenesisRow(){
        var sut = CreateService("k1", new() { ["k1"] = GenerateKeyBase64() });
        var chain = BuildValidChain(sut, 3);

        chain.RemoveAt(0); // Delete entry #1

        var result = sut.VerifyChain(chain);

        Assert.False(result.IsIntact);
        Assert.Equal(1, result.BrokenAtSequenceNumber);
    }

    [Fact]
    public void VerifyChain_AttackerRehashesWithWrongKey_RejectsForgedChain(){
        var legitimate = CreateService("k1", new() { ["k1"] = GenerateKeyBase64() });
        var attacker = CreateService("k1", new() { ["k1"] = GenerateKeyBase64() });

        var forgedChain = BuildValidChain(attacker, 3);

        var result = legitimate.VerifyChain(forgedChain);

        Assert.False(result.IsIntact);
        Assert.Equal(1, result.BrokenAtSequenceNumber);
    }

    [Fact]
    public void VerifyChain_AcrossKeyRotation_VerifiesOldAndNewEntries(){
        var k1 = GenerateKeyBase64();
        var k2 = GenerateKeyBase64();

        var oldService = CreateService("k1", new() { ["k1"] = k1 });
        var chain = BuildValidChain(oldService, 2);
        
        var rotatedService = CreateService("k2", new() { ["k1"] = k1, ["k2"] = k2 });
        var entry3 = new AuditLogEntry
        {
            Id = Guid.NewGuid(),
            SequenceNumber = 3,
            TimestampUtc = rotatedService.NormalizeTimestamp(DateTime.UtcNow.AddMinutes(5)),
            ActorId = "user-3",
            ActorUsername = "alice",
            ActorRole = "PM",
            Action = "FindingSlaSet",
            FindingId = chain[0].FindingId,
            Details = "SLA set after key rotation",
            KeyId = rotatedService.ActiveKeyId,
            PreviousHash = chain[1].EntryHash,
            EntryHash = string.Empty
        };
        entry3.EntryHash = rotatedService.ComputeEntryHash(entry3);
        chain.Add(entry3);

        var result = rotatedService.VerifyChain(chain);

        Assert.True(result.IsIntact);
        Assert.Equal(3, result.TotalEntries);
    }
}