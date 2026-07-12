using System.Security.Cryptography;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// A known-good original firmware file. Identity is by <b>content</b>
    /// (size + SHA-256), never by name — the same file may be downloaded under
    /// any name. <see cref="OriginalName"/> and <see cref="Md5"/> are recorded
    /// for display / future use, not for validation.
    /// </summary>
    public sealed record KnownFirmware(
        string OriginalName,
        long SizeBytes,
        string Sha256,      // uppercase hex
        string Md5,         // uppercase hex (stored; not used for validation)
        bool IsFwzContainer // true for .fwz ZIPs this tool can unpack
    );

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
        // Recorded from the official Legrand/BTicino downloads (size + SHA-256 +
        // MD5). Names are informational only. SHA-256 is the authoritative check;
        // MD5 is kept for future use.
        public static readonly IReadOnlyList<KnownFirmware> Known = new[]
        {
            new KnownFirmware("C100X_010501.fwz", 106380638,
                "87A61E4444CF1656FD63EACE6AD0044D53224851321FBABB60B1014E1E285A8F",
                "910CFFF0960EF35C6C9F3F0A68705EEE", true),
            new KnownFirmware("C100X_010505.fwz", 106477062,
                "C2CDCD29887AF2694B04279D652C37507B7BA669AB756FEF0DA6CCAB119CD929",
                "9919D5103B6FE7AA9748EF9AE2E62CF5", true),
            new KnownFirmware("C100X_010507.fwz", 106486815,
                "82436D66519A28B7B407D83810E4F42961F1CC2E99B8AAF561460959F5148F58",
                "EDD09A27037AEA289075C5D86815E13B", true),
            new KnownFirmware("C100X_010508.fwz", 106240356,
                "BCA0DD7E407C2406D6F8C696F0A9E50BC1E795C8E4700C89E83F09FF96C3EFB2",
                "0BDD681AC772B886767B4F5D792DB3D3", true),
            new KnownFirmware("C300X_010717.fwz", 100476940,
                "D0C42410254A9DFA4F18D2F8A94B2CBD7C99A393AC78334463D1EC4D3320F517",
                "FD7FBC5522488A257075CE2792B0D2D4", true),
            new KnownFirmware("C300X_010719.fwz", 100510249,
                "8E6FDE2070168704FDD46DF8825FF124F993A0C81AC1EE32EBDCC5821EC2DBA7",
                "70795123E8A6C06E324909862B062522", true),
        };

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

            string sha = Sha256Hex(path);
            var match = bySize.FirstOrDefault(
                k => string.Equals(k.Sha256, sha, StringComparison.OrdinalIgnoreCase));
            if (match is null)
                return new(false, null,
                    $"Unrecognized firmware: the SHA-256 does not match any known original.\n" +
                    $"  size   : {size:N0} bytes\n" +
                    $"  sha256 : {sha}");

            if (!match.IsFwzContainer)
                return new(false, match,
                    $"Recognized as {match.OriginalName}, but it is a raw .bin image, not a .fwz " +
                    $"container this tool can unpack. It cannot be modified here.");

            return new(true, match,
                $"Verified original: {match.OriginalName} — SHA-256 matches, {size:N0} bytes.");
        }

        private static string Sha256Hex(string path)
        {
            using var sha = SHA256.Create();
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
            return Convert.ToHexString(sha.ComputeHash(fs)); // uppercase hex
        }
    }
}
