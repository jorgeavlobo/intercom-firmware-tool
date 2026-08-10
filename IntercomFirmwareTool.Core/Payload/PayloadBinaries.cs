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
    /// <c>Payload/vendor/licenses/btmqttd-THIRD-PARTY-LICENSES.txt</c> for the
    /// aggregated dependency license texts.
    /// </summary>
    public static class PayloadBinaries
    {
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
            Length: 1447_424,
            Sha256Hex: "028220070be3061317565d72363fff922b3bf2ff6df06b92978f3c9ea59f6273",
            ResourceName: "IntercomFirmwareTool.Core.Payload.vendor.armhf.btmqttd",
            LicenseResourceName:
                "IntercomFirmwareTool.Core.Payload.vendor.licenses.btmqttd-THIRD-PARTY-LICENSES.txt",
            // The static binary bundles ~65 Rust crates; the mandatory notices span
            // MIT, Apache-2.0, ISC (ring/webpki/untrusted), BSD-3-Clause (subtle) and
            // Unicode-3.0 (unicode-ident). All texts are in the aggregated notice file.
            LicenseSpdx: "MIT AND Apache-2.0 AND ISC AND BSD-3-Clause AND Unicode-3.0");

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
