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
            string privatePem = rsa.ExportRSAPrivateKeyPem();
            File.WriteAllText(privateKeyPath, privatePem + "\n");

            // Public key: OpenSSH one-line format.
            string pub = OpenSshPublicKey(rsa, comment);
            string pubPath = privateKeyPath + ".pub";
            File.WriteAllText(pubPath, pub + "\n");

            return pubPath;
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
