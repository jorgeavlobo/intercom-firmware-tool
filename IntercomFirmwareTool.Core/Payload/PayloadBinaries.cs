using System.Security.Cryptography;
using System.Text;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// Metadata for a prebuilt ARM binary that the optional MQTT bridge installs
    /// into the firmware image. (btmqttd is first-party — built from this repo's
    /// source; only its bundled dependency notices are third-party.)
    /// </summary>
    /// <param name="Name">Short tool name, e.g. "btmqttd".</param>
    /// <param name="InstallPath">Absolute path on the device rootfs.</param>
    /// <param name="Length">Expected byte length of the embedded resource.</param>
    /// <param name="Sha256Hex">Lower-case hex SHA-256 of the exact bytes.</param>
    /// <param name="ResourceName">Manifest resource (LogicalName) in this assembly.</param>
    /// <param name="LicenseResourceName">Manifest resource of the primary license text.</param>
    /// <param name="LicenseSpdx">SPDX license expression for the binary as a whole.</param>
    public sealed record ArmBinary(
        string Name,
        string InstallPath,
        int Length,
        string Sha256Hex,
        string ResourceName,
        string LicenseResourceName,
        string LicenseSpdx)
    {
        /// <summary>
        /// Manifest resources of further license texts a statically-linked binary
        /// bundles, beyond <see cref="LicenseResourceName"/>. Unused by the current
        /// single binary (btmqttd aggregates all its dependency notices into one
        /// license file), but kept so the metadata stays general.
        /// Declared as an init-only property (not a positional parameter) so the
        /// record's primary constructor and Deconstruct signature stay stable.
        /// </summary>
        public IReadOnlyList<string>? AdditionalLicenseResourceNames { get; init; }
    }

    /// <summary>
    /// Access to the embedded ARM binary (<c>btmqttd</c>) and its dependency-license
    /// notice, embedded in this assembly, that the MQTT bridge installer writes
    /// into the firmware image. Every <see cref="Read"/> re-verifies the bytes
    /// against their recorded length and SHA-256, so a corrupted or swapped
    /// resource can never be silently installed onto a device.
    ///
    /// This binary is NOT in the factory firmware. It is a single, statically-linked
    /// Rust daemon whose bundled crates are all permissive (MIT / Apache-2.0 / ISC /
    /// BSD-3-Clause / Unicode-3.0 — no copyleft). See
    /// <c>Payload/vendor/THIRD_PARTY.md</c> for provenance and integrity data, and
    /// <c>licenses/btmqttd-THIRD-PARTY-LICENSES.txt</c> (repo-root licenses/ dir) for the
    /// aggregated dependency license texts.
    /// </summary>
    public static class PayloadBinaries
    {
        /// <summary>
        /// musl libc's MIT license notice. BOTH shipped binaries statically link musl libc
        /// objects — <c>btmqttd</c> via the Rust <c>*-musleabihf</c> target, <c>ffmpeg</c>
        /// via <c>zig cc</c> — and musl's exception waives only headers/CRT, so the linked
        /// libc.a objects require the notice. The same upstream license text covers both.
        /// </summary>
        private const string MuslCopyrightResource =
            "IntercomFirmwareTool.Core.licenses.musl-COPYRIGHT.txt";

        /// <summary>
        /// <c>btmqttd</c> — the single-connection MQTT bridge daemon (issue #32),
        /// a statically-linked armv7 hard-float (musl) ELF that REPLACES the entire
        /// shell-orchestrated bridge (StartMqttSend/StartMqttReceive, keypress.sh,
        /// filter.py, ha_discovery.sh, mqtt_common.sh, TcpDump2Mqtt) plus the
        /// vendored <c>jq</c> (native serde_json) and <c>evtest</c> (native evdev).
        /// Static musl means it needs no runtime interpreter or shared libraries.
        /// Installed <c>0775 root:root</c>. Built per <c>native/btmqttd/BUILD.md</c>.
        /// </summary>
        public static readonly ArmBinary Btmqttd = new(
            Name: "btmqttd",
            InstallPath: "/usr/sbin/btmqttd",
            Length: 1_693_992,
            Sha256Hex: "26d744404af5315ac3b2459cb666a9c120b4636c9f0a8fd96d6e70b0838bab86",
            ResourceName: "IntercomFirmwareTool.Core.Payload.vendor.armhf.btmqttd",
            LicenseResourceName:
                "IntercomFirmwareTool.Core.licenses.btmqttd-THIRD-PARTY-LICENSES.txt",
            // The static binary bundles ~65 Rust crates; the mandatory notices span
            // MIT, Apache-2.0, ISC (ring/webpki/untrusted), BSD-3-Clause (subtle) and
            // Unicode-3.0 (unicode-ident). All texts are in the aggregated notice file.
            LicenseSpdx: "MIT AND Apache-2.0 AND ISC AND BSD-3-Clause AND Unicode-3.0")
        {
            // Also statically links musl libc (MIT) — its COPYRIGHT ships alongside the
            // aggregated crate notices. (SPDX already lists MIT, from the crates.)
            AdditionalLicenseResourceNames = new[] { MuslCopyrightResource },
        };

        /// <summary>
        /// The bridge daemon's Semantic Version (issue #114) — the version of the vendored
        /// <see cref="Btmqttd"/> binary this build installs. Surfaced to Home Assistant as the
        /// intercom device's <c>sw_version</c> (see <c>MqttInstaller.GenerateHaDiscovery</c>), so an
        /// operator can see which bridge is running on the panel's device page (regardless of model).
        ///
        /// SINGLE SOURCE OF TRUTH is <c>native/btmqttd/Cargo.toml</c>'s <c>[package] version</c>
        /// (which the daemon also compiles in as <c>CARGO_PKG_VERSION</c>); this constant MIRRORS
        /// it so the installer can bake the value into the discovery JSON without reading the
        /// binary. The two MUST stay equal — <c>btmqttd-provenance.yml</c> fails the build if they
        /// drift (and <c>MqttHaDiscoveryDeviceTests</c> pins this to a valid SemVer). Bump BOTH
        /// together when the daemon's version changes.
        /// </summary>
        public const string BridgeVersion = "0.1.0";

        /// <summary>
        /// <c>ffmpeg</c> — a minimal, LGPL, statically-linked armv7 hard-float (musl) build for the
        /// on-device media server (issue #120): the on-device go2rtc runs it to read the panel's
        /// cleartext RTP via an SDP and <b>copy</b> the H.264 into RTSP — no decode/encode. Unlike
        /// the first-party <see cref="Btmqttd"/>, this is a <b>third-party</b> binary (FFmpeg n7.1.1,
        /// <c>LGPL-2.1-or-later</c>), built per <c>native/ffmpeg/BUILD.md</c> and byte-reproducible
        /// (every input pinned + SHA-verified; <c>ffmpeg-provenance.yml</c> enforces a byte-for-byte
        /// rebuild match, like btmqttd). Embedded here; it is deliberately NOT in <see cref="All"/>
        /// yet — the on-device camera install (which writes it + <see cref="Go2Rtc"/>, gated on the
        /// camera option) lands in Phase 1c-2, so the vendored binary ships with no change to install
        /// behaviour.
        /// </summary>
        public static readonly ArmBinary Ffmpeg = new(
            Name: "ffmpeg",
            InstallPath: "/usr/sbin/ffmpeg",
            Length: 2_996_128,
            Sha256Hex: "c8a6810d4862a37f9501f4870068d300adbfd2a882f088002ad12efff42eb5b4",
            ResourceName: "IntercomFirmwareTool.Core.Payload.vendor.armhf.ffmpeg",
            LicenseResourceName:
                "IntercomFirmwareTool.Core.licenses.ffmpeg-COPYING.LGPLv2.1.txt",
            // FFmpeg core is LGPL-2.1; the static binary also links musl libc (MIT), hence
            // the compound expression and the extra musl notice below.
            LicenseSpdx: "LGPL-2.1-or-later AND MIT")
        {
            AdditionalLicenseResourceNames = new[] { MuslCopyrightResource },
        };

        /// <summary>
        /// <c>go2rtc</c> — the on-device streaming server (issue #120): it reads the panel's
        /// cleartext RTP (fanned to <c>127.0.0.2</c> by <see cref="Btmqttd"/>) via a generated SDP,
        /// runs <see cref="Ffmpeg"/> to <b>copy</b> the H.264 into RTSP, and serves it to Home
        /// Assistant as a native Generic Camera — no go2rtc on the HA side. This is a
        /// <b>third-party, redistributed upstream prebuilt</b> (go2rtc <c>v1.9.14</c>, <c>MIT</c>,
        /// AlexxIT/go2rtc): a statically-linked Go binary with no libc dependency. Unlike the
        /// byte-reproducible <see cref="Ffmpeg"/>/<see cref="Btmqttd"/>, it is <i>not</i> rebuilt
        /// from source here — its exact upstream release is pinned (tag + asset + SHA-256 in
        /// <c>native/go2rtc/pins.env</c>) and <c>go2rtc-provenance.yml</c> re-downloads that pinned
        /// asset and byte-compares it to this committed copy. Embedded here; like <see cref="Ffmpeg"/>
        /// it is deliberately NOT in <see cref="All"/> yet — the gated on-device camera install lands
        /// in Phase 1c-2.
        /// </summary>
        public static readonly ArmBinary Go2Rtc = new(
            Name: "go2rtc",
            InstallPath: "/usr/sbin/go2rtc",
            Length: 4_588_084,
            Sha256Hex: "4d7e1639af5a2722a28e864468fd8099b3c1682565446c798bf9e3b38fde12e4",
            ResourceName: "IntercomFirmwareTool.Core.Payload.vendor.armhf.go2rtc",
            LicenseResourceName:
                "IntercomFirmwareTool.Core.licenses.go2rtc-LICENSE.txt",
            // Statically linked Go: the binary contains the Go runtime (BSD-3-Clause) + ~35 Go
            // modules, so their notices must travel too. go2rtc's own MIT text is the primary
            // resource; the AUDITED aggregate (generated with `go-licenses` against the pinned
            // v1.9.14 linux/arm build) is the additional resource. All permissive — paho.mqtt
            // (EPL-2.0/EDL-1.0 dual) is used under the permissive EDL-1.0 election, no copyleft.
            LicenseSpdx: "Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT AND (EPL-2.0 OR BSD-3-Clause)")
        {
            AdditionalLicenseResourceNames = new[]
            {
                "IntercomFirmwareTool.Core.licenses.go2rtc-THIRD-PARTY-LICENSES.txt",
            },
        };

        /// <summary>The complete third-party notice (Markdown).</summary>
        public const string ThirdPartyNoticeResourceName =
            "IntercomFirmwareTool.Core.Payload.vendor.THIRD_PARTY.md";

        /// <summary>All ARM binaries the MQTT bridge ships, in install order.</summary>
        // Array.AsReadOnly so the exposed IReadOnlyList can't be cast back to
        // ArmBinary[] and mutated (matching FirmwareRegistry.Known's convention).
        public static readonly IReadOnlyList<ArmBinary> All =
            Array.AsReadOnly(new[] { Btmqttd });

        /// <summary>
        /// Return the exact bytes of <paramref name="binary"/>, after verifying
        /// they match its recorded length and SHA-256.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// The resource is missing, or its length or SHA-256 does not match — a
        /// build/packaging error we refuse to write onto a device.
        /// </exception>
        public static byte[] Read(ArmBinary binary)
        {
            ArgumentNullException.ThrowIfNull(binary);

            byte[] bytes = ReadResource(binary.ResourceName);

            if (bytes.Length != binary.Length)
            {
                throw new InvalidOperationException(
                    $"Embedded binary '{binary.Name}' is {bytes.Length} bytes, " +
                    $"expected {binary.Length}. The assembly is corrupt or the " +
                    $"wrong file was embedded.");
            }

            string actual = Convert.ToHexStringLower(SHA256.HashData(bytes));
            if (!string.Equals(actual, binary.Sha256Hex, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Embedded binary '{binary.Name}' SHA-256 {actual} does not " +
                    $"match the expected {binary.Sha256Hex}. Refusing to install " +
                    $"an unverified binary.");
            }

            return bytes;
        }

        /// <summary>The primary license text (UTF-8) for <paramref name="binary"/>.</summary>
        public static string LicenseText(ArmBinary binary)
        {
            ArgumentNullException.ThrowIfNull(binary);
            return Encoding.UTF8.GetString(ReadResource(binary.LicenseResourceName));
        }

        /// <summary>
        /// Every license resource name that applies to <paramref name="binary"/> —
        /// the primary plus any additional licenses a statically-linked binary
        /// declares in <see cref="ArmBinary.AdditionalLicenseResourceNames"/>. Read
        /// each with <see cref="LicenseTextByResource"/>.
        /// </summary>
        public static IReadOnlyList<string> LicenseResourceNames(ArmBinary binary)
        {
            ArgumentNullException.ThrowIfNull(binary);
            var names = new List<string> { binary.LicenseResourceName };
            if (binary.AdditionalLicenseResourceNames is { } extra)
            {
                names.AddRange(extra);
            }
            // AsReadOnly so a caller can't downcast the result to List<string>
            // and mutate this metadata.
            return names.AsReadOnly();
        }

        /// <summary>Read a license text (UTF-8) by its manifest resource name.</summary>
        public static string LicenseTextByResource(string resourceName) =>
            Encoding.UTF8.GetString(ReadResource(resourceName));

        /// <summary>The aggregate third-party notice (Markdown, UTF-8).</summary>
        public static string ThirdPartyNotice() =>
            Encoding.UTF8.GetString(ReadResource(ThirdPartyNoticeResourceName));

        private static byte[] ReadResource(string name)
        {
            var assembly = typeof(PayloadBinaries).Assembly;
            using Stream? stream = assembly.GetManifestResourceStream(name);
            if (stream is null)
            {
                throw new InvalidOperationException(
                    $"Embedded resource '{name}' not found in {assembly.GetName().Name}. " +
                    $"Check the <EmbeddedResource> LogicalName in the .csproj.");
            }

            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);
            return buffer.ToArray();
        }
    }
}
