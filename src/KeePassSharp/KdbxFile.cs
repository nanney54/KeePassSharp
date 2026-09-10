using KeePassSharp.KdbxDocument;

namespace KeePassSharp;

public sealed class KdbxFile {
    public required KdbxHeader Header { get; init; }
    //public required KeePassFile XmlData { get; init; }
}
