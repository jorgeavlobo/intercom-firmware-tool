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
                    // Best-effort rollback to the original pair before rethrowing.
                    if (bakPriv != null) TryRestore(bakPriv, privateKeyPath);
                    if (bakPub != null) TryRestore(bakPub, pubPath);
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
            string line = text.Trim().Split('\n')[0].Trim();
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
                if (blob.Length < 4) return false;
                int len = (blob[0] << 24) | (blob[1] << 16) | (blob[2] << 8) | blob[3];
                if (len <= 0 || 4 + len > blob.Length) return false;
                return Encoding.ASCII.GetString(blob, 4, len) == type;
            }
            catch (FormatException)
            {
                return false; // parts[1] was not valid base64
            }
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
