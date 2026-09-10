using KeePassSharp;

namespace KeePassSharpTest;

public sealed class HeaderReaderTests {
    [Test]
    public async Task Read_signature1() {
        using KdbxFileReader reader = new("Samples\\Database.kdbx");

        KdbxFile result = reader.Read();

        await Assert.That(result.Header.Signature1)
            .IsEqualTo(0x9AA2D903);
    }

    [Test]
    public async Task Read_signature2() {
        using KdbxFileReader reader = new("Samples\\Database.kdbx");

        KdbxFile result = reader.Read();

        await Assert.That(result.Header.Signature2)
            .IsEqualTo(0xB54BFB67);
    }

    [Test]
    public async Task Read_FormatVersion() {
        using KdbxFileReader reader = new("Samples\\Database.kdbx");

        KdbxFile result = reader.Read();

        await Assert.That(result.Header.FormatVersion)
            .IsEqualTo(0x00040000u);
    }

    [Test]
    public async Task Read_EncryptionAlgorithm() {
        using KdbxFileReader reader = new("Samples\\Database.kdbx");

        KdbxFile result = reader.Read();

        await Assert.That(result.Header.EncryptionAlgorithm)
            .IsEqualTo(EncryptionAlgorithm.AES256);
    }

    [Test]
    public async Task Read_CompressionAlgorithm() {
        using KdbxFileReader reader = new("Samples\\Database.kdbx");

        KdbxFile result = reader.Read();

        await Assert.That(result.Header.CompressionAlgorithm)
            .IsEqualTo(CompressionAlgorithm.GZip);
    }
}
