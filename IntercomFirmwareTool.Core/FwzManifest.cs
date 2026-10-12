using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// Helpers for the firmware service-pack manifest (<c>fwz.xml</c>) carried inside a
    /// <c>.fwz</c> archive. Pure (no I/O) so the transform is unit-tested directly.
    ///
    /// <para>Context — MyHOME Suite "service pack inadequate" (error 1063): for the Classe
    /// 300X13E (ref. 344642/344643, Door Entry, branch 1.7) the catalogue selects the
    /// <c>btesuXP</c> protocol; when <c>fwz.xml</c> omits <c>&lt;req_hw_ver&gt;</c> the library
    /// defaults required hardware to <c>03.00.00</c>. The device is hardware 2.0.0, so the
    /// major-version comparison fails → error 1063. Declaring <c>&lt;req_hw_ver&gt;02.00.00&lt;/req_hw_ver&gt;</c>
    /// in the manifest makes the required-hardware gate pass (02.00.00 ≤ the device's HW), with
    /// MyHOME's own checks left enabled — it is a metadata correction, not a signature bypass,
    /// and lowering the required-HW bar only makes the gate MORE permissive for the same image.</para>
    /// </summary>
    public static class FwzManifest
    {
        /// <summary>The manifest element that declares the minimum required hardware version.</summary>
        internal const string ReqHwVerElement = "req_hw_ver";

        // A hardware version is three dot-separated 2-digit groups, e.g. "02.00.00" — the form
        // MyHOME writes/reads (and the form the device reports via *#13**17## as 2*0*0). Use [0-9],
        // not \d: in .NET \d matches every Unicode decimal digit (e.g. Arabic-Indic "٠٢.٠٠.٠٠"),
        // but the manifest/MyHOME format is strictly ASCII, so only ASCII digits may be accepted.
        // Anchor with \A…\z, not ^…$: in .NET $ also matches just before a trailing '\n', so a
        // "02.00.00\n" would otherwise pass and be injected verbatim. \z pins the absolute end.
        private static readonly Regex HwVerPattern =
            new(@"\A[0-9]{2}\.[0-9]{2}\.[0-9]{2}\z", RegexOptions.CultureInvariant);

        /// <summary>
        /// Returns a copy of the <paramref name="manifestXml"/> bytes with
        /// <c>&lt;req_hw_ver&gt;</c> set to <paramref name="reqHwVer"/>. Idempotent and
        /// conservative:
        /// <list type="bullet">
        /// <item>absent → the element is added as the last child of the root;</item>
        /// <item>present and EQUAL → returned re-serialized but logically unchanged;</item>
        /// <item>present and DIFFERENT → throws (we never silently override a declared
        ///   requirement — the source manifest for the fixed case has none).</item>
        /// </list>
        /// Pure: no I/O. The XML declaration and existing whitespace are preserved. For the UTF-8
        /// manifest these firmwares ship (the only case that occurs), the output carries no BOM; a
        /// non-UTF-8 declaration keeps the BOM its encoding requires (see <see cref="Serialize"/>).
        /// </summary>
        /// <param name="manifestXml">The decrypted <c>fwz.xml</c> bytes.</param>
        /// <param name="reqHwVer">The required-hardware value to declare, e.g. <c>"02.00.00"</c>.</param>
        public static byte[] InjectReqHwVer(byte[] manifestXml, string reqHwVer)
        {
            ArgumentNullException.ThrowIfNull(manifestXml);
            if (!IsValidHwVer(reqHwVer))
                throw new ArgumentException(
                    $"req_hw_ver must be three 2-digit groups 'NN.NN.NN', got '{reqHwVer}'.", nameof(reqHwVer));

            XDocument doc = Parse(manifestXml);
            XElement root = doc.Root
                ?? throw new InvalidDataException("fwz.xml has no root element.");

            // Inspect ALL req_hw_ver children, not just the first: XContainer.Element returns only the
            // first match, so a manifest that declared the element twice with different values could pass
            // as "already correct" by matching the first while a conflicting second one stayed in place
            // (and ReadReqHwVer, also reading the first, would not see the conflict).
            var existing = root.Elements(ReqHwVerElement).ToList();
            if (existing.Count > 1)
                throw new InvalidDataException(
                    $"fwz.xml declares req_hw_ver {existing.Count} times; refusing to rewrite a manifest " +
                    "with duplicate (possibly conflicting) hardware requirements.");

            if (existing.Count == 1)
            {
                string current = (existing[0].Value ?? string.Empty).Trim();
                if (!string.Equals(current, reqHwVer, StringComparison.Ordinal))
                    throw new InvalidDataException(
                        $"fwz.xml already declares req_hw_ver '{current}'; expected it absent or '{reqHwVer}'. " +
                        "Refusing to override a declared hardware requirement.");
                // Already the wanted value — normalize to the exact validated form so the serialized
                // bytes and ReadReqHwVer agree (e.g. drop stray surrounding whitespace that Trim ignored).
                existing[0].Value = reqHwVer;
            }
            else
            {
                root.Add(new XElement(ReqHwVerElement, reqHwVer));
            }

            return Serialize(doc);
        }

        /// <summary>
        /// Reads the <c>&lt;req_hw_ver&gt;</c> value from the manifest, or <c>null</c> when the
        /// element is absent. Used to verify an injection round-tripped through the repacked
        /// <c>.fwz</c>. Pure.
        /// </summary>
        public static string? ReadReqHwVer(byte[] manifestXml)
        {
            ArgumentNullException.ThrowIfNull(manifestXml);
            XElement? el = Parse(manifestXml).Root?.Element(ReqHwVerElement);
            return el is null ? null : (el.Value ?? string.Empty).Trim();
        }

        /// <summary>Whether <paramref name="value"/> is a well-formed <c>NN.NN.NN</c> hardware version.</summary>
        public static bool IsValidHwVer(string? value) =>
            value is not null && HwVerPattern.IsMatch(value);

        private static XDocument Parse(byte[] xml)
        {
            using var ms = new MemoryStream(xml, writable: false);
            // PreserveWhitespace so re-serialization stays as close to the original layout as
            // possible (we only add one element). No DTD processing — the manifest has none,
            // and this avoids any external-entity surprise on untrusted input.
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
            };
            using var reader = XmlReader.Create(ms, settings);
            return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
        }

        private static byte[] Serialize(XDocument doc)
        {
            // Match the original declaration: keep it if present, and honour its encoding
            // (default UTF-8). The BTicino manifest is UTF-8, and ResolveEncoding returns a BOM-less
            // UTF-8 encoder, so the manifest we actually ship carries no BOM (a stray UTF-8 BOM could
            // trip a strict reader). A non-UTF-8 declaration — which these firmwares never use — keeps
            // whatever BOM its encoding requires (a UTF-16/UTF-32 XML entity is REQUIRED to begin with
            // one), so we do not strip it. Do not re-indent (PreserveWhitespace already kept the
            // layout); the one added element sits after the last child.
            Encoding encoding = ResolveEncoding(doc.Declaration?.Encoding);
            var settings = new XmlWriterSettings
            {
                Encoding = encoding,
                Indent = false,
                NewLineHandling = NewLineHandling.None,
                OmitXmlDeclaration = doc.Declaration is null,
            };
            using var ms = new MemoryStream();
            using (var writer = XmlWriter.Create(ms, settings))
                doc.Save(writer);
            return ms.ToArray();
        }

        private static Encoding ResolveEncoding(string? declared)
        {
            // UTF-8 without BOM is the firmware manifest's encoding and a safe default.
            if (string.IsNullOrWhiteSpace(declared))
                return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            try
            {
                Encoding e = Encoding.GetEncoding(declared);
                // Strip a UTF-8 BOM preamble if the resolved encoding would emit one.
                return e is UTF8Encoding
                    ? new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)
                    : e;
            }
            catch (ArgumentException)
            {
                return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            }
        }
    }
}
