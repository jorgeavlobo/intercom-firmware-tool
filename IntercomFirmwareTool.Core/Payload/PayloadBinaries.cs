using System.Security.Cryptography;
using System.Text;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// Metadata for a verbatim third-party ARM binary that the optional MQTT
    /// bridge installs into the firmware image.
    /// </summary>
    /// <param name="Name">Short tool name, e.g. "jq".</param>
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
        /// bundles (e.g. Oniguruma, glibc), beyond <see cref="LicenseResourceName"/>.
        /// Declared as an init-only property (not a positional parameter) so the
        /// record's primary constructor and Deconstruct signature stay stable.
        /// </summary>
        public IReadOnlyList<string>? AdditionalLicenseResourceNames { get; init; }
    }

    /// <summary>
    /// Access to the third-party ARM binaries (jq, evtest) and their license
    /// notices, embedded in this assembly, that the MQTT bridge installer writes
    /// into the firmware image. Every <see cref="Read"/> re-verifies the bytes
    /// against their recorded length and SHA-256, so a corrupted or swapped
    /// resource can never be silently installed onto a device.
    ///
    /// These binaries are NOT in the factory firmware and are shipped under
    /// their own licenses (jq: MIT; evtest: GPL-2.0-or-later). See
    /// <c>Payload/vendor/THIRD_PARTY.md</c> for provenance, integrity data and the
    /// GPL written offer for source.
    /// </summary>
    public static class PayloadBinaries
    {
        /// <summary>
        /// <c>jq</c> 1.8.2 — statically-linked armv7-hardfloat ELF. jq itself is
        /// MIT, but the static binary also bundles Oniguruma (BSD-2-Clause) and
        /// glibc (LGPL-2.1-or-later); see <c>Payload/vendor/THIRD_PARTY.md</c>.
        /// 1.8.2 is a security release (over the reference unit's 1.7): it fixes
        /// the decNumber overflows (CVE-2023-50268 / CVE-2024-53427) plus the jq
        /// 1.8.2 batch — parser memory-corruption and a hash-collision DoS
        /// (CVE-2026-40164) — all reachable via the untrusted JSON parsed in
        /// <c>StartMqttReceive</c>. Also used by <c>keypress.sh</c> (build the
        /// key-press JSON). Installed <c>0775 root:root</c>.
        /// </summary>
        public static readonly ArmBinary Jq = new(
            Name: "jq",
            InstallPath: "/usr/bin/jq",
            Length: 1_340_000,
            Sha256Hex: "78458244fb546469b4042e9e07cf78714ef6848895eb9515df76b4eb0b1dc992",
            ResourceName: "IntercomFirmwareTool.Core.Payload.vendor.armhf.jq",
            LicenseResourceName: "IntercomFirmwareTool.Core.Payload.vendor.licenses.jq-COPYING",
            // Full set carried by the static binary: jq (MIT); its bundled
            // dtoa/g_fmt (David M. Gay's Lucent permissive notice — no standard
            // SPDX id, so LicenseRef-dtoa) and decNumber (ICU), both documented
            // in jq-COPYING; Oniguruma (BSD-2-Clause) and glibc (LGPL-2.1-or-later).
            LicenseSpdx: "MIT AND ICU AND LicenseRef-dtoa AND BSD-2-Clause AND LGPL-2.1-or-later")
        {
            // Array.AsReadOnly so this nested collection can't be cast back to
            // string[] and mutated (completes the immutability of the metadata).
            AdditionalLicenseResourceNames = Array.AsReadOnly(new[]
            {
                "IntercomFirmwareTool.Core.Payload.vendor.licenses.oniguruma-COPYING",
                "IntercomFirmwareTool.Core.Payload.vendor.licenses.glibc-LGPL-2.1.txt",
            }),
        };

        /// <summary>
        /// <c>evtest</c> 1.35 — dynamically-linked armv7-hardfloat ELF
        /// (GPL-2.0-or-later; needs glibc's <c>/lib/ld-linux-armhf.so.3</c>,
        /// present on the C100X/C300X). Used by <c>keypress.sh</c> to read the
        /// front-panel keypad. Installed <c>0775 root:root</c>.
        /// </summary>
        public static readonly ArmBinary Evtest = new(
            Name: "evtest",
            InstallPath: "/usr/bin/evtest",
            Length: 34_264,
            Sha256Hex: "96e3c20fb1742fc57b9b9efbc716cb4c7ae5a1faebe5621a14c1b3053d0d08c0",
            ResourceName: "IntercomFirmwareTool.Core.Payload.vendor.armhf.evtest",
            LicenseResourceName: "IntercomFirmwareTool.Core.Payload.vendor.licenses.evtest-COPYING",
            LicenseSpdx: "GPL-2.0-or-later");

        /// <summary>The complete third-party notice (Markdown).</summary>
        public const string ThirdPartyNoticeResourceName =
            "IntercomFirmwareTool.Core.Payload.vendor.THIRD_PARTY.md";

        /// <summary>All ARM binaries the MQTT bridge ships, in install order.</summary>
        // Array.AsReadOnly so the exposed IReadOnlyList can't be cast back to
        // ArmBinary[] and mutated (matching FirmwareRegistry.Known's convention).
        public static readonly IReadOnlyList<ArmBinary> All =
            Array.AsReadOnly(new[] { Jq, Evtest });

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
        /// the primary plus any licenses a statically-linked binary bundles
        /// (Oniguruma, glibc for the static <c>jq</c>). Read each with
        /// <see cref="LicenseTextByResource"/>.
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
