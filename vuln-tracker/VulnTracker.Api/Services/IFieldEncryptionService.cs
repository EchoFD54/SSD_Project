namespace VulnTracker.Api.Services;

public class EncryptionOptions{
    public const string SectionName = "Encryption";

    public string ActiveKeyId { get; set; } = string.Empty;

    public Dictionary<string, string> Keys { get; set; } = new();
}

public interface IFieldEncryptionService{
    string Encrypt(string plaintext, string associatedData);
    string Decrypt(string encryptedPayload, string associatedData);
}