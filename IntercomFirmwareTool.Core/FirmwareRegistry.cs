using System.Security.Cryptography;
using System.Text;

namespace IntercomFirmwareTool.Core
{
    /// <summary>A BTicino product reference this firmware runs on.</summary>
    public sealed record FirmwareModel(
        string Reference,   // catalogue reference, e.g. "344642"
        string Name);       // commercial name, e.g. "Classe 300X13E (light finish)"

    /// <summary>
    /// A known-good original firmware file. Identity is by <b>content</b>
    /// (size + SHA-256), never by name — the same file may be downloaded under
    /// any name. The name, MD5, model metadata and download URL are recorded for
    /// display / future use, not for validation.
    /// </summary>
    public sealed record KnownFirmware(
        string OriginalName,
        long SizeBytes,
        string Sha256,          // uppercase hex — the authoritative validation value
        string Md5,             // uppercase hex — stored, not used for validation
        bool IsFwzContainer,
        string Line,            // product line, e.g. "Classe 300X" / "Classe 100X"
        string Version,         // firmware version, e.g. "1.7.19"
        string? Edition,        // 100X firmware family: "Home + Security" / "Door Entry"; null for 300X
        IReadOnlyList<FirmwareModel> Models,
        string? DownloadUrl = null) // official download URL, where known
    {
        /// <summary>A labelled multi-line description for the Result window.</summary>
        public string Describe()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"  Line     : BTicino {Line}");
            if (!string.IsNullOrEmpty(Edition))
                sb.AppendLine($"  Edition  : {Edition}");
            sb.AppendLine($"  Version  : {Version}");
            if (Models.Count == 1)
            {
                sb.AppendLine($"  Model    : {Models[0].Reference} — {Models[0].Name}");
            }
            else
            {
                sb.AppendLine("  Models   :");
                foreach (var m in Models)
                    sb.AppendLine($"    • {m.Reference} — {m.Name}");
            }
            return sb.ToString().TrimEnd('\r', '\n');
        }
    }

    /// <summary>Outcome of checking a file against the registry.</summary>
    public sealed record FirmwareCheckResult(
        bool Ok,
        KnownFirmware? Match,
        string Message);

    /// <summary>
    /// Whitelist of known-good original firmware images and the gate that
    /// verifies a chosen file against it. Only a file whose <b>size and SHA-256
    /// match a known original</b> may be modified — this prevents building from a
    /// corrupt, incomplete, or wrong download.
    /// </summary>
    public static class FirmwareRegistry
    {
        // ---- Product references (catalogue names confirmed on catalogue.bticino.com) ----
        // Classe 300X13E — same unit, two finishes (light 344642, dark 344643).
        private static readonly FirmwareModel M300X_Light = new("344642", "Classe 300X13E (light finish)");
        private static readonly FirmwareModel M300X_Dark  = new("344643", "Classe 300X13E (dark finish)");
        // Classe 100X16E — one reference, two firmware families (Home+Security / Door Entry).
        private static readonly FirmwareModel M100X        = new("344682", "Classe 100X16E");

        // Recorded from the official Legrand/BTicino downloads (size + SHA-256 +
        // MD5). SHA-256 is the authoritative check; MD5 is kept for future use.
        // Names/models are informational only, never validation inputs.
        // Array.AsReadOnly: hand out a genuine read-only view — the backing array
        // cannot be reached and cast back to KnownFirmware[] to mutate the
        // whitelist at runtime, which would undermine the integrity gate.
        public static readonly IReadOnlyList<KnownFirmware> Known = Array.AsReadOnly(new[]
        {
            // ---- Classe 100X (344682) — Home + Security family ----
            new KnownFirmware("C100X_010501.fwz", 106380638,
                "87A61E4444CF1656FD63EACE6AD0044D53224851321FBABB60B1014E1E285A8F",
                "910CFFF0960EF35C6C9F3F0A68705EEE", true,
                "Classe 100X", "1.5.1", "Home + Security", new[] { M100X },
                "https://www.homesystems-legrandgroup.com/MatrixENG/liferay/bt_mxLiferayCheckout.jsp?fileFormat=generic&fileName=C100X_010501.fwz&fileId=58107.23188.46381.34528"),
            new KnownFirmware("C100XR_020012.fwz", 187381703,
                "7E7CC789A261B85CC1C344E9D2894F5652BE2DC2FBE5644D54BA6C2BEE4FCDE2",
                "50F0FA138198F845873688F6113F918F", true,
                "Classe 100X", "2.0.12", "Home + Security", new[] { M100X },
                "https://www.homesystems-legrandgroup.com/MatrixENG/liferay/bt_mxLiferayCheckout.jsp?fileFormat=generic&fileName=C100XR_020012.fwz&fileId=58107.23188.36439.38772"),
            new KnownFirmware("C100XR_020311.fwz", 184914730,
                "6D199A2FADD08213E37115EA9BF9AA302CD5158E654FD872D1EFF48731588545",
                "43A635AD3BD024690F431776C5641814", true,
                "Classe 100X", "2.3.11", "Home + Security", new[] { M100X },
                "https://assets.legrand.com/pim/AUTRE/C100XR_020311.fwz"),

            // ---- Classe 100X (344682) — Door Entry family ----
            new KnownFirmware("C100X_010505.fwz", 106477062,
                "C2CDCD29887AF2694B04279D652C37507B7BA669AB756FEF0DA6CCAB119CD929",
                "9919D5103B6FE7AA9748EF9AE2E62CF5", true,
                "Classe 100X", "1.5.5", "Door Entry", new[] { M100X },
                "https://www.homesystems-legrandgroup.com/MatrixENG/liferay/bt_mxLiferayCheckout.jsp?fileFormat=generic&fileName=C100X_010505.fwz&fileId=58107.23188.62332.48840"),
            new KnownFirmware("C100X_010507.fwz", 106486815,
                "82436D66519A28B7B407D83810E4F42961F1CC2E99B8AAF561460959F5148F58",
                "EDD09A27037AEA289075C5D86815E13B", true,
                "Classe 100X", "1.5.7", "Door Entry", new[] { M100X },
                "https://www.homesystems-legrandgroup.com/MatrixENG/liferay/bt_mxLiferayCheckout.jsp?fileFormat=generic&fileName=C100X_010507.fwz&fileId=58107.23188.5954.54078"),
            new KnownFirmware("C100X_010508.fwz", 106240356,
                "BCA0DD7E407C2406D6F8C696F0A9E50BC1E795C8E4700C89E83F09FF96C3EFB2",
                "0BDD681AC772B886767B4F5D792DB3D3", true,
                "Classe 100X", "1.5.8", "Door Entry", new[] { M100X },
                "https://assets.legrand.com/pim/AUTRE/C100X_010508.fwz"),

            // ---- Classe 300X13E (344642 light / 344643 dark) ----
            new KnownFirmware("C300X_010717.fwz", 100476940,
                "D0C42410254A9DFA4F18D2F8A94B2CBD7C99A393AC78334463D1EC4D3320F517",
                "FD7FBC5522488A257075CE2792B0D2D4", true,
                "Classe 300X", "1.7.17", null, new[] { M300X_Dark },
                "https://www.homesystems-legrandgroup.com/MatrixENG/liferay/bt_mxLiferayCheckout.jsp?fileFormat=generic&fileName=C300X_010717.fwz&fileId=58107.23188.15908.12349"),
            new KnownFirmware("C300X_010719.fwz", 100510249,
                "8E6FDE2070168704FDD46DF8825FF124F993A0C81AC1EE32EBDCC5821EC2DBA7",
                "70795123E8A6C06E324909862B062522", true,
                "Classe 300X", "1.7.19", null, new[] { M300X_Light, M300X_Dark },
                "https://assets.legrand.com/pim/AUTRE/C300X_010719.fwz"),
        });

        /// <summary>
        /// Verifies a file against the whitelist. Fast path: reject on size
        /// mismatch before hashing. Then compute SHA-256 and require an exact
        /// match. Returns the matched entry (and whether it is a modifiable
        /// .fwz) or a clear reason for rejection.
        /// </summary>
        public static FirmwareCheckResult Verify(string path)
        {
            long size;
            try { size = new FileInfo(path).Length; }
            catch (Exception ex) { return new(false, null, $"Cannot read the file: {ex.Message}"); }

            // Fast pre-filter: no known original has this exact byte size.
            var bySize = Known.Where(k => k.SizeBytes == size).ToList();
            if (bySize.Count == 0)
                return new(false, null,
                    $"Unrecognized firmware: size {size:N0} bytes does not match any known original.");

            string sha;
            try { sha = Sha256Hex(path); }
            catch (Exception ex)
            {
                // Deleted/locked/unreadable after the size check: reject through
                // the normal flow instead of faulting the (uncaught) caller.
                return new(false, null, $"Cannot read the file while hashing: {ex.Message}");
            }
            var match = bySize.FirstOrDefault(
                k => string.Equals(k.Sha256, sha, StringComparison.OrdinalIgnoreCase));
            if (match is null)
                return new(false, null,
                    $"Unrecognized firmware: the SHA-256 does not match any known original.\n" +
                    $"  size   : {size:N0} bytes\n" +
                    $"  sha256 : {sha}");

            if (!match.IsFwzContainer)
                return new(false, match,
                    $"Recognized as {match.OriginalName}, but it is not a .fwz container this tool " +
                    $"can unpack. It cannot be modified here.");

            return new(true, match,
                $"Verified original: {match.OriginalName} — SHA-256 matches, {size:N0} bytes.");
        }

        private static string Sha256Hex(string path)
        {
            using var sha = SHA256.Create();
            // FileShare.Read: tolerate other readers (Explorer preview, AV scan)
            // holding the file open; we only read, so this stays safe.
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return Convert.ToHexString(sha.ComputeHash(fs)); // uppercase hex
        }
    }
}
