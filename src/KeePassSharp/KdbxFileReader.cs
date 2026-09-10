using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;
using KeePassSharp.KdbxDocument;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace KeePassSharp;

public enum FieldId : byte {
    EndOfHeader = 0,
    EncryptionAlgorithm = 2,
    CompressionAlgorithm = 3,
    MasterSaltSeed = 4,
    EncryptionIV = 7,
    KDFParameters = 11,
    PublicCustomData = 12,
}

public sealed class KdbxFileReader : IDisposable {
    public KdbxFileReader(Stream stream) {
        this.reader = new(stream, Encoding.UTF8, true);
    }

    public KdbxFileReader(string kdbxFilePath) {
        FileStream fileStream = File.OpenRead(kdbxFilePath);
        this.reader = new BinaryReader(fileStream);
    }

    public KdbxFile Read() {
        var sign1 = this.reader.ReadUInt32();
        var sign2 = this.reader.ReadUInt32();
        var version = this.reader.ReadUInt32();

        Dictionary<FieldId, byte[]> fields = new();
        byte id = this.reader.ReadByte();
        int size = this.reader.ReadInt32();
        byte[] value = this.reader.ReadBytes(size);
        fields.Add((FieldId)id, value);

        while (id != 0) {
            id = this.reader.ReadByte();
            size = this.reader.ReadInt32();
            value = this.reader.ReadBytes(size);
            fields.Add((FieldId)id, value);
        }

        Dictionary<string, byte[]> variantDic = new();

        if (fields.TryGetValue(FieldId.KDFParameters, out byte[] kdf)) {
            using BinaryReader kdfReader = new(new MemoryStream(kdf));

            uint vers = kdfReader.ReadUInt16();
            byte valueType;

            while ((valueType = kdfReader.ReadByte()) != 0) {
                int nameSize = kdfReader.ReadInt32();
                string name = Encoding.UTF8.GetString(kdfReader.ReadBytes(nameSize));
                int valueSize = kdfReader.ReadInt32();
                byte[] val = kdfReader.ReadBytes(valueSize);

                variantDic.Add(name, val);
            }
        }

        byte[] composite = SHA256.HashData(
            SHA256.HashData(Encoding.UTF8.GetBytes("KeePassSharpTest")));

        ulong rounds = BitConverter.ToUInt64(variantDic["R"]);

        //AES-KDF
        byte[] transformed = composite;
        byte[] outBuf = new byte[32];

        using (Aes aes = Aes.Create()) {
            aes.Key = variantDic["S"];
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            using ICryptoTransform encryptor = aes.CreateEncryptor();

            for (ulong i = 0; i < rounds; i++) {
                encryptor.TransformBlock(transformed, 0, 16, outBuf, 0);
                encryptor.TransformBlock(transformed, 16, 16, outBuf, 16);

                Buffer.BlockCopy(outBuf, 0, transformed, 0, 32);
            }
        }

        transformed = SHA256.HashData(transformed);

        byte[] masterKey = SHA256.HashData([
            .. fields[FieldId.MasterSaltSeed],
            .. transformed]);

        int position = (int)this.reader.BaseStream.Position;
        this.reader.BaseStream.Seek(0, SeekOrigin.Begin);
        byte[] headerBytes = this.reader.ReadBytes(position);
        byte[] hashHeader = SHA256.HashData(headerBytes);
        byte[] expectedHashHeader = this.reader.ReadBytes(32);

        if (!CryptographicOperations.FixedTimeEquals(hashHeader, expectedHashHeader)) {
            throw new InvalidDataException("Header HMAC does not match expected value.");
        }

        byte[] hmacBaseKey = SHA512.HashData([
            .. fields[FieldId.MasterSaltSeed],
            .. transformed,
            0x01
        ]);

        byte[] hmacKey = SHA512.HashData([
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            .. hmacBaseKey
        ]);

        byte[] computedHmac = HMACSHA256.HashData(hmacKey, headerBytes);
        byte[] expectedHeaderHmac = this.reader.ReadBytes(32);

        if (!CryptographicOperations.FixedTimeEquals(computedHmac, expectedHeaderHmac)) {
            throw new InvalidDataException("Header HMAC mismatch — master key incorrect or file tampered.");
        }

        ulong blockIndex = 0;
        using MemoryStream payload = new();

        while (true) {
            byte[] storedHmac = this.reader.ReadBytes(32);
            int s = this.reader.ReadInt32();

            if (s == 0) {
                break;
            }

            byte[] m = this.reader.ReadBytes(s);

            byte[] blockHmacKey = SHA512.HashData([
                ..BitConverter.GetBytes(blockIndex),
                ..hmacBaseKey
            ]);

            byte[] message = [
            .. BitConverter.GetBytes(blockIndex),
            .. BitConverter.GetBytes(s),
            .. m
            ];

            byte[] cmpHmac = HMACSHA256.HashData(blockHmacKey, message);

            if (!CryptographicOperations.FixedTimeEquals(cmpHmac, storedHmac)) {
                throw new InvalidDataException("Blcok HMAC mismatch.");
            }

            payload.Write(m);

            blockIndex += 1;
        }

        byte[] cypherText = payload.ToArray();
        byte[] cypherDecrypted = null;

        using (Aes aes = Aes.Create()) {
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.IV = fields[FieldId.EncryptionIV];
            aes.Key = masterKey;

            using (ICryptoTransform decryptor = aes.CreateDecryptor())
            using (MemoryStream input = new(cypherText, writable: false))
            using (CryptoStream cryptoStream = new(input, decryptor, CryptoStreamMode.Read))
            using (MemoryStream output = new()) {
                cryptoStream.CopyTo(output);
                cypherDecrypted = output.ToArray();
            }
        }

        if (cypherDecrypted == null) {
            throw new InvalidDataException("Cypher not well decrypted");
        }

        using MemoryStream ms = new(cypherDecrypted);

        KeePassFile? kdbxFile = null;

        ////0x1f 0x8b
        using (GZipStream gZipStream = new(ms, CompressionMode.Decompress)) {
            using (BinaryReader blockReader = new(gZipStream)) {
                byte[] k = null;

                while (true) {
                    byte t = blockReader.ReadByte();
                    int s = blockReader.ReadInt32();

                    if (t == 0) {
                        break;
                    }

                    byte[] v = blockReader.ReadBytes(s);

                    if (t == 1 && BitConverter.ToInt32(v) == 3) {
                        //chacha20

                    }

                    if (t == 2) {
                        k = v;
                    }
                }

                if (k?.Length > 0) {
                    byte[] h = SHA512.HashData(k);
                    byte[] key = h[..32];
                    byte[] nonce = h[32..44];

                    XDocument xml = XDocument.Load(gZipStream);

                    List<string> values = xml.Descendants("Root")
                        .Elements("Group")
                        .Elements("Entry")
                        .Elements("String")
                        .Elements("Value")
                        .Where(v => v.Attribute("Protected") != null)
                        .Select(x => x.Value)
                        .ToList();

                    ChaCha7539Engine engine = new();
                    engine.Init(false, new ParametersWithIV(
                        parameters: new KeyParameter(key),
                        iv: nonce));

                    foreach (string v in values) {
                        byte[] encryptedBytes = Convert.FromBase64String(v);
                        byte[] decryptedBytes = new byte[encryptedBytes.Length];

                        engine.ProcessBytes(
                            encryptedBytes,
                            0,
                            encryptedBytes.Length,
                            decryptedBytes,
                            0);

                        string password = Encoding.UTF8.GetString(decryptedBytes);
                    }
                }
            }
        }

        return new KdbxFile() {
            Header = new() {
                Signature1 = sign1,
                Signature2 = sign2,
                FormatVersion = version,
                CompressionAlgorithm = (CompressionAlgorithm)BitConverter.ToUInt32(
                    fields[FieldId.CompressionAlgorithm], 0),
                EncryptionAlgorithm = Convert.ToHexString(
                    fields[FieldId.EncryptionAlgorithm]) switch {
                        "31C1F2E6BF714350BE5805216AFC5AFF" => EncryptionAlgorithm.AES256,
                        "D6038A2B8B6F4CB5A524339A31DBB59A" => EncryptionAlgorithm.ChaCha20
                    },
                EncryptionIV = fields[FieldId.EncryptionIV],
                MasterSaltSeed = fields[FieldId.MasterSaltSeed],
            }
        };
    }

    public void Dispose() {
        this.reader.Dispose();
    }

    public async Task Test_Async() {

    }
    private readonly BinaryReader reader;
}
//using MemoryStream m = new ();
//using CryptoStream cs = new (m, decryptor, CryptoStreamMode.Write);
//cs.Write(cipherXml, 0, cipherXml.Length);
//cs.FlushFinalBlock();
//byte[] decrypted = m.ToArray();

//<KeePassFile>
//  <Meta>
//    <Generator>KeePass</Generator>
//    <SettingsChanged>g4hn4A4AAAA=</SettingsChanged>
//    <DatabaseName>KeePassSharpTest</DatabaseName>
//    <DatabaseNameChanged>g4hn4A4AAAA=</DatabaseNameChanged>
//    <DatabaseDescription></DatabaseDescription>
//    <DatabaseDescriptionChanged>X4hn4A4AAAA=</DatabaseDescriptionChanged>
//    <DefaultUserName></DefaultUserName>
//    <DefaultUserNameChanged>X4hn4A4AAAA=</DefaultUserNameChanged>
//    <MaintenanceHistoryDays>365</MaintenanceHistoryDays>
//    <Color></Color>
//    <MasterKeyChanged>X4hn4A4AAAA=</MasterKeyChanged>
//    <MasterKeyChangeRec>-1</MasterKeyChangeRec>
//    <MasterKeyChangeForce>-1</MasterKeyChangeForce>
//    <MemoryProtection>
//      <ProtectTitle>False</ProtectTitle>
//      <ProtectUserName>False</ProtectUserName>
//      <ProtectPassword>True</ProtectPassword>
//      <ProtectURL>False</ProtectURL>
//      <ProtectNotes>False</ProtectNotes>
//    </MemoryProtection>
//    <RecycleBinEnabled>True</RecycleBinEnabled>
//    <RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>
//    <RecycleBinChanged>X4hn4A4AAAA=</RecycleBinChanged>
//    <EntryTemplatesGroup>AAAAAAAAAAAAAAAAAAAAAA==</EntryTemplatesGroup>
//    <EntryTemplatesGroupChanged>X4hn4A4AAAA=</EntryTemplatesGroupChanged>
//    <HistoryMaxItems>10</HistoryMaxItems>
//    <HistoryMaxSize>6291456</HistoryMaxSize>
//    <LastSelectedGroup>7OeoblNlDEWpUX2aXS9MNg==</LastSelectedGroup>
//    <LastTopVisibleGroup>7OeoblNlDEWpUX2aXS9MNg==</LastTopVisibleGroup>
//    <CustomData />
//  </Meta>
//  <Root>
//    <Group>
//      <UUID>7OeoblNlDEWpUX2aXS9MNg==</UUID>
//      <Name>Database</Name>
//      <Notes></Notes>
//      <IconID>49</IconID>
//      <Times>
//        <CreationTime>X4hn4A4AAAA=</CreationTime>
//        <LastModificationTime>X4hn4A4AAAA=</LastModificationTime>
//        <LastAccessTime>X4hn4A4AAAA=</LastAccessTime>
//        <ExpiryTime>wIdn4A4AAAA=</ExpiryTime>
//        <Expires>False</Expires>
//        <UsageCount>0</UsageCount>
//        <LocationChanged>X4hn4A4AAAA=</LocationChanged>
//      </Times>
//      <IsExpanded>True</IsExpanded>
//      <DefaultAutoTypeSequence></DefaultAutoTypeSequence>
//      <EnableAutoType>Null</EnableAutoType>
//      <EnableSearching>Null</EnableSearching>
//      <LastTopVisibleEntry>gpnVNlmYUUqGH79Lr9dxxw==</LastTopVisibleEntry>
//      <Entry>
//        <UUID>gpnVNlmYUUqGH79Lr9dxxw==</UUID>
//        <IconID>0</IconID>
//        <ForegroundColor></ForegroundColor>
//        <BackgroundColor></BackgroundColor>
//        <OverrideURL></OverrideURL>
//        <Tags></Tags>
//        <Times>
//          <CreationTime>g4hn4A4AAAA=</CreationTime>
//          <LastModificationTime>g4hn4A4AAAA=</LastModificationTime>
//          <LastAccessTime>g4hn4A4AAAA=</LastAccessTime>
//          <ExpiryTime>wIdn4A4AAAA=</ExpiryTime>
//          <Expires>False</Expires>
//          <UsageCount>0</UsageCount>
//          <LocationChanged>g4hn4A4AAAA=</LocationChanged>
//        </Times>
//        <String>
//          <Key>Notes</Key>
//          <Value>Notes</Value>
//        </String>
//        <String>
//          <Key>Password</Key>
//          <Value Protected="True">O5r6F6KGBXg=</Value>
//        </String>
//        <String>
//          <Key>Title</Key>
//          <Value>Sample Entry</Value>
//        </String>
//        <String>
//          <Key>URL</Key>
//          <Value>https://keepass.info/</Value>
//        </String>
//        <String>
//          <Key>UserName</Key>
//          <Value>User Name</Value>
//        </String>
//        <AutoType>
//          <Enabled>True</Enabled>
//          <DataTransferObfuscation>0</DataTransferObfuscation>
//          <Association>
//            <Window>Target Window</Window>
//            <KeystrokeSequence>{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}</KeystrokeSequence>
//          </Association>
//        </AutoType>
//        <History />
//      </Entry>
//      <Entry>
//        <UUID>z6VIG3JI+0Cs9/KX8Ex0CQ==</UUID>
//        <IconID>0</IconID>
//        <ForegroundColor></ForegroundColor>
//        <BackgroundColor></BackgroundColor>
//        <OverrideURL></OverrideURL>
//        <Tags></Tags>
//        <Times>
//          <CreationTime>g4hn4A4AAAA=</CreationTime>
//          <LastModificationTime>g4hn4A4AAAA=</LastModificationTime>
//          <LastAccessTime>g4hn4A4AAAA=</LastAccessTime>
//          <ExpiryTime>wIdn4A4AAAA=</ExpiryTime>
//          <Expires>False</Expires>
//          <UsageCount>0</UsageCount>
//          <LocationChanged>g4hn4A4AAAA=</LocationChanged>
//        </Times>
//        <String>
//          <Key>Password</Key>
//          <Value Protected="True">brTp/ls=</Value>
//        </String>
//        <String>
//          <Key>Title</Key>
//          <Value>Sample Entry #2</Value>
//        </String>
//        <String>
//          <Key>URL</Key>
//          <Value>https://keepass.info/help/kb/testform.html</Value>
//        </String>
//        <String>
//          <Key>UserName</Key>
//          <Value>Michael321</Value>
//        </String>
//        <AutoType>
//          <Enabled>True</Enabled>
//          <DataTransferObfuscation>0</DataTransferObfuscation>
//          <Association>
//            <Window>*Test Form - KeePass*</Window>
//            <KeystrokeSequence></KeystrokeSequence>
//          </Association>
//        </AutoType>
//        <History />
//      </Entry>
//      <Group>
//        <UUID>yxrbkCFsUkyIAP1fUKVRSA==</UUID>
//        <Name>General</Name>
//        <Notes></Notes>
//        <IconID>48</IconID>
//        <Times>
//          <CreationTime>g4hn4A4AAAA=</CreationTime>
//          <LastModificationTime>g4hn4A4AAAA=</LastModificationTime>
//          <LastAccessTime>g4hn4A4AAAA=</LastAccessTime>
//          <ExpiryTime>wIdn4A4AAAA=</ExpiryTime>
//          <Expires>False</Expires>
//          <UsageCount>0</UsageCount>
//          <LocationChanged>g4hn4A4AAAA=</LocationChanged>
//        </Times>
//        <IsExpanded>True</IsExpanded>
//        <DefaultAutoTypeSequence></DefaultAutoTypeSequence>
//        <EnableAutoType>Null</EnableAutoType>
//        <EnableSearching>Null</EnableSearching>
//        <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
//      </Group>
//      <Group>
//        <UUID>b8PqQTs3UEO8sGRYm9C33g==</UUID>
//        <Name>Windows</Name>
//        <Notes></Notes>
//        <IconID>38</IconID>
//        <Times>
//          <CreationTime>g4hn4A4AAAA=</CreationTime>
//          <LastModificationTime>g4hn4A4AAAA=</LastModificationTime>
//          <LastAccessTime>g4hn4A4AAAA=</LastAccessTime>
//          <ExpiryTime>wIdn4A4AAAA=</ExpiryTime>
//          <Expires>False</Expires>
//          <UsageCount>0</UsageCount>
//          <LocationChanged>g4hn4A4AAAA=</LocationChanged>
//        </Times>
//        <IsExpanded>True</IsExpanded>
//        <DefaultAutoTypeSequence></DefaultAutoTypeSequence>
//        <EnableAutoType>Null</EnableAutoType>
//        <EnableSearching>Null</EnableSearching>
//        <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
//      </Group>
//      <Group>
//        <UUID>oId/jJBg6EaeAnweiqO7gA==</UUID>
//        <Name>Network</Name>
//        <Notes></Notes>
//        <IconID>3</IconID>
//        <Times>
//          <CreationTime>g4hn4A4AAAA=</CreationTime>
//          <LastModificationTime>g4hn4A4AAAA=</LastModificationTime>
//          <LastAccessTime>g4hn4A4AAAA=</LastAccessTime>
//          <ExpiryTime>wIdn4A4AAAA=</ExpiryTime>
//          <Expires>False</Expires>
//          <UsageCount>0</UsageCount>
//          <LocationChanged>g4hn4A4AAAA=</LocationChanged>
//        </Times>
//        <IsExpanded>True</IsExpanded>
//        <DefaultAutoTypeSequence></DefaultAutoTypeSequence>
//        <EnableAutoType>Null</EnableAutoType>
//        <EnableSearching>Null</EnableSearching>
//        <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
//      </Group>
//      <Group>
//        <UUID>J1zORZtBlEm7dGweSfkqjQ==</UUID>
//        <Name>Internet</Name>
//        <Notes></Notes>
//        <IconID>1</IconID>
//        <Times>
//          <CreationTime>g4hn4A4AAAA=</CreationTime>
//          <LastModificationTime>g4hn4A4AAAA=</LastModificationTime>
//          <LastAccessTime>g4hn4A4AAAA=</LastAccessTime>
//          <ExpiryTime>wIdn4A4AAAA=</ExpiryTime>
//          <Expires>False</Expires>
//          <UsageCount>0</UsageCount>
//          <LocationChanged>g4hn4A4AAAA=</LocationChanged>
//        </Times>
//        <IsExpanded>True</IsExpanded>
//        <DefaultAutoTypeSequence></DefaultAutoTypeSequence>
//        <EnableAutoType>Null</EnableAutoType>
//        <EnableSearching>Null</EnableSearching>
//        <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
//      </Group>
//      <Group>
//        <UUID>m0QERmxG00msWcLuZcNYjQ==</UUID>
//        <Name>eMail</Name>
//        <Notes></Notes>
//        <IconID>19</IconID>
//        <Times>
//          <CreationTime>g4hn4A4AAAA=</CreationTime>
//          <LastModificationTime>g4hn4A4AAAA=</LastModificationTime>
//          <LastAccessTime>g4hn4A4AAAA=</LastAccessTime>
//          <ExpiryTime>wIdn4A4AAAA=</ExpiryTime>
//          <Expires>False</Expires>
//          <UsageCount>0</UsageCount>
//          <LocationChanged>g4hn4A4AAAA=</LocationChanged>
//        </Times>
//        <IsExpanded>True</IsExpanded>
//        <DefaultAutoTypeSequence></DefaultAutoTypeSequence>
//        <EnableAutoType>Null</EnableAutoType>
//        <EnableSearching>Null</EnableSearching>
//        <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
//      </Group>
//      <Group>
//        <UUID>VD0d9O8yKUaKgG1/krUPog==</UUID>
//        <Name>Homebanking</Name>
//        <Notes></Notes>
//        <IconID>37</IconID>
//        <Times>
//          <CreationTime>g4hn4A4AAAA=</CreationTime>
//          <LastModificationTime>g4hn4A4AAAA=</LastModificationTime>
//          <LastAccessTime>g4hn4A4AAAA=</LastAccessTime>
//          <ExpiryTime>wIdn4A4AAAA=</ExpiryTime>
//          <Expires>False</Expires>
//          <UsageCount>0</UsageCount>
//          <LocationChanged>g4hn4A4AAAA=</LocationChanged>
//        </Times>
//        <IsExpanded>True</IsExpanded>
//        <DefaultAutoTypeSequence></DefaultAutoTypeSequence>
//        <EnableAutoType>Null</EnableAutoType>
//        <EnableSearching>Null</EnableSearching>
//        <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>
//      </Group>
//    </Group>
//    <DeletedObjects />
//  </Root>
//</KeePassFile>
