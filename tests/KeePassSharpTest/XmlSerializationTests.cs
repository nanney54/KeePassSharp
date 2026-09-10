using System.Drawing;
using System.Xml;
using System.Xml.Serialization;
using KeePassSharp.KdbxDocument;

namespace KeePassSharpTest;

public sealed class XmlSerializationTests {
    [Test]
    public void Read() {
        XmlNamespaceManager xmlNamespace = new(new NameTable());
        xmlNamespace.AddNamespace("xs", "http://www.w3.org/2001/XMLSchema");

        using FileStream fs = File.OpenRead("Samples\\DatabaseFull.xml");
        KdbxXmlParser reader = new(fs);
        XmlSerializer serializer = new(typeof(KeePassFile),
            new XmlRootAttribute("KeePassFile"));

        KeePassFile g = (KeePassFile)serializer.Deserialize(reader);
    }

    [Test]
    public async Task Read_TUUID() {
        string xml = """<UUID>z6VIG3JI+0Cs9/KX8Ex0CQ==</UUID>""";

        TUUID o = Deserialize<TUUID>(xml, "UUID");

        await Assert.That(o.Value)
            .IsEqualTo(Guid.Parse("1b48a5cf-4872-40fb-acf7-f297f04c7409"));
    }

    [Test]
    public async Task Read_TDateTime() {
        string xml = """<CreationTime>g4hn4A4AAAA=</CreationTime>""";

        TDateTime o = Deserialize<TDateTime>(xml, "CreationTime");

        await Assert.That(o.Value)
            .IsEqualTo(new DateTime(2025, 9, 25, 21, 1, 23)
                .ToUniversalTime());
    }

    [Test]
    public async Task Read_TColor() {
        string xml = """<Color>#FF0000</Color>""";

        TColor o = Deserialize<TColor>(xml, "Color");

        await Assert.That(o.Value)
            .IsEqualTo(Color.FromArgb(255, Color.Red));
    }

    [Test]
    public async Task Read_empty_TColor() {
        string xml = """<Color></Color>""";

        TColor o = Deserialize<TColor>(xml, "Color");

        await Assert.That(o.Value)
            .IsEqualTo(Color.Empty);
    }

    [Test]
    [Arguments("Null", null)]
    [Arguments("null", null)]
    [Arguments("True", true)]
    [Arguments("true", true)]
    [Arguments("False", false)]
    [Arguments("false", false)]
    public async Task Read_TNullableBool(string xmlValue, bool? expected) {
        string xml = $"<EnableAutoType>{xmlValue}</EnableAutoType>";

        TNullableBool o = Deserialize<TNullableBool>(xml, "EnableAutoType");

        await Assert.That(o.Value)
            .IsEqualTo(expected);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1024)]
    [Arguments(int.MaxValue)]
    public async Task Read_TNonNegativeInt(int xmlValue) {
        string xml = $"<IconID>{xmlValue}</IconID>";

        TNonNegativeInt o = Deserialize<TNonNegativeInt>(xml, "IconID");

        await Assert.That(o.Value)
            .IsEqualTo(xmlValue);
    }

    [Test]
    [Arguments(-1)]
    [Arguments(long.MaxValue)]
    public async Task Read_out_of_range_TNonNegativeInt(long xmlValue) {
        string xml = $"<IconID>{xmlValue}</IconID>";

        await Assert.That(() => Deserialize<TNonNegativeInt>(xml, "IconID"))
            .ThrowsException();
    }

    [Test]
    public async Task Read_none_standard_boolean_attribute() {
        string xml = """
            <String>
                <Key>Password</Key>
                <Value Protected="True">wpKi0LH43rf49n4CYcw=</Value>
            </String>
            """;

        ProtectedString protectedString = Deserialize<ProtectedString>(
            xml,
            "String");

        await Assert.That(protectedString)
            .IsEquivalentTo(new ProtectedString() {
                Key = "Password",
                Value = new ProtectedStringValue() {
                    Protected = true,
                    Value = "wpKi0LH43rf49n4CYcw="
                }
            });
    }

    [Test]
    public async Task Read_ProtectedBinary() {
        string xml = """
            <Binary>
                <Key>New.rtf</Key>
                <Value Ref="120" />
            </Binary>
            """;

        ProtectedBinary protectedBinary = Deserialize<ProtectedBinary>(
            xml,
            "Binary");

        await Assert.That(protectedBinary)
            .IsEquivalentTo(new ProtectedBinary() {
                Key = "New.rtf",
                Value = new ProtectedBinaryValue() {
                    Ref = 120
                }
            });
    }

    private static T Deserialize<T>(string xml, string xmlRoot) {
        using TextReader textReader = new StringReader(xml);
        using KdbxXmlParser reader = new(textReader);

        XmlSerializer serializer = new(typeof(T),
            new XmlRootAttribute(xmlRoot));

        return (T)serializer.Deserialize(reader)!;
    }
}
