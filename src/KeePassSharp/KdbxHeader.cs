namespace KeePassSharp;

public enum CompressionAlgorithm : uint {
    NoCompression,
    GZip
}

public enum EncryptionAlgorithm {
    AES256,
    ChaCha20
}

public sealed class KdbxHeader {
    public uint Signature1 { get; internal init; }
    public uint Signature2 { get; internal init; }
    public uint FormatVersion { get; internal init; }
    public EncryptionAlgorithm EncryptionAlgorithm { get; internal init; }
    public CompressionAlgorithm CompressionAlgorithm { get; internal init; }
    public byte[] MasterSaltSeed { get; internal init; }
    public byte[] EncryptionIV { get; internal init; }
}
