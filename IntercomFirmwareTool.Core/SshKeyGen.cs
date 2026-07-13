using System.Security.Cryptography;
using System.Text;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// Generates an SSH RSA key pair using only built-in .NET cryptography (no
    /// external dependency). Writes the private key as a classic PKCS#1 PEM
    /// (<c>-----BEGIN RSA PRIVATE KEY-----</c>, which OpenSSH reads directly) and
    /// the public key in the OpenSSH one-line format (<c>ssh-rsa AAAA… comment</c>)
    /// that dropbear/authorized_keys expects.
    ///
    /// RSA is used (rather than Ed25519) because it is available in the base
    /// class library on every target, and the BTicino firmware's dropbear
    /// accepts it — the same key type as the project's existing keys.
    /// </summary>
    /// <summary>
    /// Type, size and SHA-256 fingerprint of an OpenSSH public key, for display.
    /// </summary>
    public sealed record PublicKeyInfo(string Type, int Bits, string Sha256Fingerprint)
    {
        /// <summary>A short human label, e.g. "RSA 4096" or "Ed25519".</summary>
        public string Label => Type switch
        {
            "ssh-rsa" => Bits > 0 ? $"RSA {Bits}" : "RSA",
            "ssh-ed25519" => "Ed25519",
            "ssh-dss" => "DSA",
            _ when Type.StartsWith("ecdsa-", StringComparison.Ordinal)
                => Bits > 0 ? $"ECDSA {Bits}" : "ECDSA",
            _ => Type,
        };
    }

    public static class SshKeyGen
    {
        /// <summary>
        /// Creates an RSA key pair, writing the private key to
        /// <paramref name="privateKeyPath"/> and the OpenSSH public key to that
        /// path plus ".pub". Returns the public key path.
        /// </summary>
        /// <param name="privateKeyPath">Where to write the private key.</param>
        /// <param name="comment">Trailing comment for the public key line.</param>
        /// <param name="bits">RSA modulus size (default 4096).</param>
        public static string Generate(string privateKeyPath, string comment, int bits = 4096)
        {
            using var rsa = RSA.Create(bits);

            // Private key: PKCS#1 PEM ("RSA PRIVATE KEY"), read natively by OpenSSH.
            string privatePem = rsa.ExportRSAPrivateKeyPem() + "\n";
            // Public key: OpenSSH one-line format.
            string pubPath = privateKeyPath + ".pub";
            string pubText = OpenSshPublicKey(rsa, comment) + "\n";

            // Write both to temp files first, then move them into place. Back up
            // any existing destinations so that if the second move fails we can
            // roll back — never leaving a mismatched private/.pub pair on disk.
            string tmpPriv = privateKeyPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            string tmpPub = pubPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            string? bakPriv = null, bakPub = null;
            try
            {
                File.WriteAllText(tmpPriv, privatePem);
                File.WriteAllText(tmpPub, pubText);

                bakPriv = BackupIfExists(privateKeyPath);
                bakPub = BackupIfExists(pubPath);
                try
                {
                    File.Move(tmpPriv, privateKeyPath, overwrite: true);
                    File.Move(tmpPub, pubPath, overwrite: true);
                }
                catch
                {
                    // Best-effort rollback before rethrowing: restore the original
                    // where we have a backup, otherwise delete the newly created
                    // file so no mismatched (new/old) pair is left on disk.
                    if (bakPriv != null) TryRestore(bakPriv, privateKeyPath); else TryDelete(privateKeyPath);
                    if (bakPub != null) TryRestore(bakPub, pubPath); else TryDelete(pubPath);
                    throw;
                }
                return pubPath;
            }
            finally
            {
                TryDelete(tmpPriv);
                TryDelete(tmpPub);
                if (bakPriv != null) TryDelete(bakPriv);
                if (bakPub != null) TryDelete(bakPub);
            }
        }

        /// <summary>
        /// Heuristic check that <paramref name="text"/> is an OpenSSH public key
        /// line (<c>type base64 [comment]</c>). It verifies the type token is a
        /// known one AND that the base64 blob decodes to a wire-format key whose
        /// embedded type matches — so a non-key file or random text is rejected
        /// before it gets written verbatim into <c>authorized_keys</c>.
        /// </summary>
        public static bool IsLikelyPublicKey(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            string line = text.Trim();
            // Reject multi-line input: the ENTIRE string is written to
            // authorized_keys, so a valid first key with an appended second key
            // must not pass validation and silently authorize both.
            if (line.IndexOfAny(new[] { '\r', '\n' }) >= 0) return false;
            string[] parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return false;

            string type = parts[0];
            string[] allowed =
            {
                "ssh-rsa", "ssh-ed25519", "ssh-dss",
                "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
                "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
            };
            if (Array.IndexOf(allowed, type) < 0) return false;

            try
            {
                byte[] blob = Convert.FromBase64String(parts[1]);

                // Walk every SSH wire field (uint32 length + bytes): each length
                // must fit, and the fields must consume the blob EXACTLY (no
                // truncation, no trailing garbage). The first field must equal
                // the advertised type. This rejects a corrupt/partial .pub whose
                // blob decodes but is missing key material (e.g. ssh-rsa without
                // its exponent/modulus) — which would otherwise be written into
                // authorized_keys and fail login while the round-trip (text-only)
                // check still passes.
                int pos = 0, fields = 0;
                while (pos < blob.Length)
                {
                    if (pos + 4 > blob.Length) return false; // truncated length prefix
                    long fieldLen = ((long)blob[pos] << 24) | ((long)blob[pos + 1] << 16)
                                  | ((long)blob[pos + 2] << 8) | blob[pos + 3];
                    pos += 4;
                    if (fieldLen < 0 || pos + fieldLen > blob.Length) return false; // truncated / overflow
                    if (fields == 0 &&
                        (fieldLen == 0 || Encoding.ASCII.GetString(blob, pos, (int)fieldLen) != type))
                        return false; // first field must be the algorithm name
                    pos += (int)fieldLen;
                    fields++;
                }

                // Exact consumption plus the field count for the type. Enforce
                // the exact count only for the two common, well-defined formats
                // (ssh-rsa: name,e,n = 3; ssh-ed25519: name,key = 2 — the type we
                // generate and the most common one users supply). For any other
                // type require only name + at least one key field, so a valid but
                // less common key (dss/ecdsa/FIDO) is not wrongly rejected.
                int expected = type switch
                {
                    "ssh-rsa" => 3,
                    "ssh-ed25519" => 2,
                    _ => -1,
                };
                return pos == blob.Length && (expected == -1 ? fields >= 2 : fields == expected);
            }
            catch (FormatException)
            {
                return false; // parts[1] was not valid base64
            }
        }

        /// <summary>
        /// Parses an OpenSSH public-key line and returns its type, size (bits) and
        /// SHA-256 fingerprint (the standard <c>SHA256:&lt;base64&gt;</c> form that
        /// <c>ssh-keygen -lf</c> prints), or null if it is not a valid key line.
        /// The bit size is the real key size read from the blob (for RSA, the
        /// modulus bit length), not an assumed value.
        /// </summary>
        public static PublicKeyInfo? DescribePublicKey(string publicKeyLine)
        {
            if (!IsLikelyPublicKey(publicKeyLine)) return null;
            string[] parts = publicKeyLine.Trim()
                .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            string type = parts[0];
            byte[] blob;
            try { blob = Convert.FromBase64String(parts[1]); }
            catch (FormatException) { return null; }

            // OpenSSH fingerprint: base64 of SHA-256 over the raw blob, no padding.
            string fp = "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');
            return new PublicKeyInfo(type, KeyBits(type, blob), fp);
        }

        /// <summary>Splits an SSH blob into its length-prefixed fields, or null if malformed.</summary>
        private static List<byte[]>? ReadFields(byte[] blob)
        {
            var fields = new List<byte[]>();
            int pos = 0;
            while (pos < blob.Length)
            {
                if (pos + 4 > blob.Length) return null;
                long len = ((long)blob[pos] << 24) | ((long)blob[pos + 1] << 16)
                         | ((long)blob[pos + 2] << 8) | blob[pos + 3];
                pos += 4;
                if (len < 0 || pos + len > blob.Length) return null;
                fields.Add(blob[pos..(int)(pos + len)]);
                pos += (int)len;
            }
            return fields;
        }

        /// <summary>Key size in bits: RSA modulus bit length, or the fixed size of the curve.</summary>
        private static int KeyBits(string type, byte[] blob)
        {
            switch (type)
            {
                case "ssh-rsa":
                    // Fields: "ssh-rsa", e, n → the size is the modulus (n) bit length.
                    var f = ReadFields(blob);
                    return f is { Count: >= 3 } ? MpintBitLength(f[2]) : 0;
                case "ssh-ed25519": return 256;
                case "ecdsa-sha2-nistp256": return 256;
                case "ecdsa-sha2-nistp384": return 384;
                case "ecdsa-sha2-nistp521": return 521;
                default: return 0;
            }
        }

        /// <summary>Bit length of a big-endian SSH mpint (leading zero/sign bytes ignored).</summary>
        private static int MpintBitLength(byte[] mpint)
        {
            int i = 0;
            while (i < mpint.Length && mpint[i] == 0) i++;
            if (i >= mpint.Length) return 0;
            int bitsInTop = 0;
            for (int b = mpint[i]; b != 0; b >>= 1) bitsInTop++;
            return (mpint.Length - i - 1) * 8 + bitsInTop;
        }

        /// <summary>Copies a file to a temp ".bak" sibling if it exists; returns the backup path or null.</summary>
        private static string? BackupIfExists(string path)
        {
            if (!File.Exists(path)) return null;
            string bak = path + "." + Guid.NewGuid().ToString("N") + ".bak";
            File.Copy(path, bak, overwrite: true);
            return bak;
        }

        /// <summary>Restores a backup over the destination, ignoring failures (best-effort rollback).</summary>
        private static void TryRestore(string backup, string destination)
        {
            try { File.Copy(backup, destination, overwrite: true); }
            catch { /* best-effort rollback */ }
        }

        /// <summary>Deletes a file if it exists, ignoring failures (best-effort temp cleanup).</summary>
        private static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); }
            catch { /* best-effort cleanup */ }
        }

        /// <summary>Encodes an RSA public key as "ssh-rsa &lt;base64&gt; &lt;comment&gt;".</summary>
        private static string OpenSshPublicKey(RSA rsa, string comment)
        {
            RSAParameters p = rsa.ExportParameters(false);
            using var ms = new MemoryStream();
            WriteLengthPrefixed(ms, Encoding.ASCII.GetBytes("ssh-rsa"));
            WriteMpint(ms, p.Exponent!);
            WriteMpint(ms, p.Modulus!);
            string body = Convert.ToBase64String(ms.ToArray());
            comment = comment.Replace("\r", " ").Replace("\n", " ").Trim();
            return string.IsNullOrEmpty(comment)
                ? $"ssh-rsa {body}"
                : $"ssh-rsa {body} {comment}";
        }

        /// <summary>Writes a 4-byte big-endian length, then the bytes (SSH "string").</summary>
        private static void WriteLengthPrefixed(Stream s, byte[] data)
        {
            s.WriteByte((byte)(data.Length >> 24));
            s.WriteByte((byte)(data.Length >> 16));
            s.WriteByte((byte)(data.Length >> 8));
            s.WriteByte((byte)data.Length);
            s.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Writes an SSH "mpint": a big-endian two's-complement integer, with a
        /// leading 0x00 added when the top bit is set so it stays positive, and
        /// with superfluous leading zero bytes stripped.
        /// </summary>
        private static void WriteMpint(Stream s, byte[] value)
        {
            int start = 0;
            while (start < value.Length - 1 && value[start] == 0) start++;
            byte[] v = value[start..];
            if ((v[0] & 0x80) != 0)
            {
                byte[] padded = new byte[v.Length + 1];
                Array.Copy(v, 0, padded, 1, v.Length);
                v = padded;
            }
            WriteLengthPrefixed(s, v);
        }
    }
}
