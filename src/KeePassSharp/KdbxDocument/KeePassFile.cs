namespace KeePassSharp.KdbxDocument;

public sealed class KeePassFile {
    public required Meta Meta { get; set; }

    public required Root Root { get; set; }
}
