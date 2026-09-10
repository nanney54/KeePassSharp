using System.Drawing;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;

namespace KeePassSharp.KdbxDocument;

public sealed class Root {
    public required Group Group { get; set; }

    public DeletedObjects? DeletedObjects { get; set; }
}

public sealed class Meta {
    public string? Generator { get; set; }

    public byte[]? HeaderHash { get; set; }

    public TDateTime? SettingsChanged { get; set; }

    public string? DatabaseName { get; set; }

    public TDateTime? DatabaseNameChanged { get; set; }

    public string? DatabaseDescription { get; set; }

    public TDateTime? DatabaseDescriptionChanged { get; set; }

    public string? DefaultUserName { get; set; }

    public TDateTime? DefaultUserNameChanged { get; set; }

    public uint? MaintenanceHistoryDays { get; set; }

    public TColor? Color { get; set; }

    public TDateTime? MasterKeyChanged { get; set; }

    public long? MasterKeyChangeRec { get; set; }

    public long? MasterKeyChangeForce { get; set; }

    public TBool? MasterKeyChangeForceOnce { get; set; }

    public MemoryProtectionConfig? MemoryProtection { get; set; }

    public CustomIcons? CustomIcons { get; set; }

    public TBool? RecycleBinEnabled { get; set; }

    public TUUID? RecycleBinUUID { get; set; }

    public TDateTime? RecycleBinChanged { get; set; }

    public TUUID? EntryTemplatesGroup { get; set; }

    public TDateTime? EntryTemplatesGroupChanged { get; set; }

    public int? HistoryMaxItems { get; set; }

    public long? HistoryMaxSize { get; set; }

    public TUUID? LastSelectedGroup { get; set; }

    public TUUID? LastTopVisibleGroup { get; set; }

    public Binaries? Binaries { get; set; }

    public CustomDataWithTimes? CustomData { get; set; }
}

public sealed class Binaries {
    [XmlElement("Binary")]
    public required List<ProtectedBinaryDefinition> Items { get; set; } = [];
}

public sealed class ProtectedBinaryDefinition {
    [XmlAttribute]
    public required int ID {
        get;
        set {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 0);
            field = value;
        }
    }

    [XmlAttribute]
    public required bool Compressed { get; set; }

    [XmlAttribute]
    public bool Protected { get; set; }

    public byte[]? Value { get; set; }
}

public sealed class MemoryProtectionConfig {
    public TBool? ProtectTitle { get; set; }
    public TBool? ProtectUserName { get; set; }
    public TBool? ProtectPassword { get; set; }
    public TBool? ProtectURL { get; set; }
    public TBool? ProtectNotes { get; set; }
}

public sealed class CustomIcons {
    [XmlElement("Icon")]
    public required List<CustomIcon> Items { get; set; } = [];
}

public sealed class CustomIcon {
    public required TUUID UUID { get; set; }

    public required byte[] Data { get; set; } = [];

    public string? Name { get; set; }

    public TDateTime? LastModificationTime { get; set; }
}

public sealed class CustomDataWithTimes {
    [XmlElement("Item")]
    public List<CustomDataItemWithTime> Items { get; set; } = [];
}

public sealed class CustomDataItemWithTime {
    public required string Key { get; set; }
    public required string Value { get; set; }
    public TDateTime? LastModificationTime { get; set; }
}

public sealed class Group {
    public required TUUID UUID { get; set; }
    public string? Name { get; set; }
    public string? Notes { get; set; }
    public TNonNegativeInt? IconID { get; set; }
    public TUUID? CustomIconUUID { get; set; }
    public Times? Times { get; set; }
    public TBool? IsExpanded { get; set; }
    public string? DefaultAutoTypeSequence { get; set; }
    public TNullableBool? EnableAutoType { get; set; }
    public TNullableBool? EnableSearching { get; set; }
    public TUUID? LastTopVisibleEntry { get; set; }
    public TUUID? PreviousParentGroup { get; set; }
    public string? Tags { get; set; }
    public CustomData? CustomData { get; set; }

    [XmlElement("Entry")]
    public List<Entry> Entries { get; set; } = [];

    [XmlElement("Group")]
    public List<Group> Groups { get; set; } = [];
}

public sealed class Entry {
    public required TUUID UUID { get; set; }

    public TNonNegativeInt? IconID { get; set; }

    public TNonNegativeInt? CustomIconUUID { get; set; }

    public TColor? ForegroundColor { get; set; }

    public TColor? BackgroundColor { get; set; }

    public string? OverrideURL { get; set; }

    public TBool? QualityCheck { get; set; }

    public string? Tags { get; set; }

    public TUUID? PreviousParentGroup { get; set; }

    public Times? Times { get; set; }

    [XmlElement("String")]
    public required List<ProtectedString> Strings { get; set; } = [];

    [XmlElement("Binary")]
    public required List<ProtectedBinary> Binaries { get; set; } = [];

    public AutoType? AutoType { get; set; }

    public CustomData? CustomData { get; set; }

    public EntryHistory? History { get; set; }
}

public sealed class ProtectedString {
    public required string Key { get; set; }

    public required ProtectedStringValue Value { get; set; }
}

public sealed class ProtectedStringValue {
    [XmlAttribute]
    public bool Protected { get; set; }

    //[XmlAttribute]
    //public bool? ProtectInMemory { get; set; }

    [XmlText]
    public string? Value { get; set; }
}

public sealed class ProtectedBinary {
    public required string Key { get; set; }
    public required ProtectedBinaryValue Value { get; set; }
}

public sealed class ProtectedBinaryValue {
    [XmlAttribute]
    public required int Ref {
        get;
        set {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 0);
            field = value;
        }
    }

    public byte[]? Value { get; set; }
}

public sealed class EntryHistory {
    [XmlElement("Entry")]
    public required List<Entry> Entries { get; set; } = [];
}

public sealed class AutoType {
    public TBool? Enabled { get; set; }

    public DataTransferObfuscation? DataTransferObfuscation { get; set; }

    public string? DefaultSequence { get; set; }

    [XmlElement("Association")]
    public required List<Association> Associations { get; set; } = [];
}

public sealed class Association {
    public required string Window { get; set; }
    public required string KeystrokeSequence { get; set; }
}

public enum DataTransferObfuscation {
    [XmlEnum("0")]
    NoObfuscation = 0,
    [XmlEnum("1")]
    TwoChannelAutoTypeObfuscation = 1,
}

public sealed class CustomData {
    [XmlElement("Item")]
    public required List<CustomDataItem> Items { get; set; } = [];
}

public sealed class CustomDataItem {
    public required string Key { get; set; }

    public required string Value { get; set; }
}

public sealed class Times {
    public TDateTime? CreationTime { get; set; }

    public TDateTime? LastModificationTime { get; set; }

    public TDateTime? LastAccessTime { get; set; }

    public TDateTime? ExpiryTime { get; set; }

    public TBool? Expires { get; set; }

    public ulong? UsageCount { get; set; }

    public TDateTime? LocationChanged { get; set; }
}

public sealed class DeletedObjects {
    [XmlElement("DeletedObject")]
    public required List<DeletedObject> Items { get; set; } = [];
}

public sealed class DeletedObject {
    public required TUUID UUID { get; set; }

    public required TDateTime DeletionTime { get; set; }
}

public abstract class KdbxValue<TDest> : IXmlSerializable {
    public TDest Value { get; set; }

    public XmlSchema? GetSchema() => null;

    public abstract void ReadXml(XmlReader reader);
    public abstract void WriteXml(XmlWriter writer);
}

public class TUUID : KdbxValue<Guid> {
    public override void ReadXml(XmlReader reader) {
        if (!reader.CanReadBinaryContent) {
            return;
        }

        byte[] buffer = new byte[16];
        int byteRead;
        while ((byteRead = reader.ReadElementContentAsBase64(buffer, 0, buffer.Length)) > 0) {

        }

        this.Value = new Guid(buffer);
    }

    public override void WriteXml(XmlWriter writer) => throw new NotImplementedException();
}

public class TDateTime : KdbxValue<DateTime> {
    public override void ReadXml(XmlReader reader) {
        if (!reader.CanReadBinaryContent) {
            return;
        }

        byte[] buffer = new byte[8];
        int byteRead;
        while ((byteRead = reader.ReadElementContentAsBase64(buffer, 0, buffer.Length)) > 0) {

        }

        long elapsedTime = BitConverter.ToInt64(buffer);
        this.Value = new DateTime(1, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            .AddSeconds(elapsedTime);
    }

    public override void WriteXml(XmlWriter writer) => throw new NotImplementedException();
}

public sealed class TBool : KdbxValue<bool> {
    public override void ReadXml(XmlReader reader) {
        if (!reader.CanReadBinaryContent) {
            return;
        }

        string rawBool = reader.ReadElementContentAsString();

        this.Value = rawBool switch {
            "True" or "true" => true,
            "False" or "false" => false
        };
    }

    public override void WriteXml(XmlWriter writer) => throw new NotImplementedException();
}

public sealed class TNullableBool : KdbxValue<bool?> {
    public override void ReadXml(XmlReader reader) {
        if (!reader.CanReadBinaryContent) {
            return;
        }

        string rawBool = reader.ReadElementContentAsString();

        this.Value = rawBool switch {
            "True" or "true" => true,
            "False" or "false" => false,
            "Null" or "null" => null
        };
    }

    public override void WriteXml(XmlWriter writer) => throw new NotImplementedException();
}

public sealed class TColor : KdbxValue<Color> {
    public override void ReadXml(XmlReader reader) {
        if (!reader.CanReadBinaryContent) {
            return;
        }

        string rawColor = reader.ReadElementContentAsString();

        this.Value = ColorTranslator.FromHtml(rawColor);
    }

    public override void WriteXml(XmlWriter writer) => throw new NotImplementedException();
}

public sealed class TNonNegativeInt : KdbxValue<int> {
    public override void ReadXml(XmlReader reader) {
        if (!reader.CanReadBinaryContent) {
            return;
        }

        int rawInteger = reader.ReadElementContentAsInt();

        if (rawInteger < 0) {
            throw new Exception("Out of bounds");
        }

        this.Value = rawInteger;
    }

    public override void WriteXml(XmlWriter writer) => throw new NotImplementedException();
}

public sealed class KdbxXmlParser : XmlTextReader {
    public KdbxXmlParser(Stream stream) : base(stream) {

    }

    public KdbxXmlParser(TextReader textReader) : base(textReader) {

    }

    public override XmlNodeType MoveToContent() {
        XmlNodeType xmlNodeType = base.MoveToContent();

        this.camelize = (xmlNodeType is XmlNodeType.Element)
            && this.BoolValues.Contains(this.Name);

        return xmlNodeType;
    }

    public override string ReadContentAsString() {
        string value = base.ReadContentAsString();

        if (!this.camelize) {
            return value;
        }

        return Camelize(value);
    }

    private static string Camelize(string value) {
        return string.Create(value.Length, value, (c, state) => {
            int index = 0;
            if (char.IsUpper(state[index])) {
                c[index] = char.ToLower(state[index]);
                index += 1;
            }

            state.AsSpan(index).CopyTo(c.Slice(index));
        });
    }

    public override string Value {
        get {
            return this.NodeType == XmlNodeType.Attribute && this.BoolValues.Contains(this.Name)
                ? Camelize(base.Value)
                : base.Value;
        }
    }

    private readonly string[] BoolValues = [
        "MasterKeyChangeForceOnce",
        "RecycleBinEnabled",
        "ProtectTitle",
        "ProtectUserName",
        "ProtectPassword",
        "ProtectURL",
        "ProtectNotes",
        "Compressed",
        "ProtectInMemory",
        "Protected",
        "Expires",
        "IsExpanded",
        "QualityCheck",
        "Enabled"
    ];

    private bool camelize;
}
