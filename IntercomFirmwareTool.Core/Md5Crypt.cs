using System.Security.Cryptography;
using System.Text;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// MD5-based crypt — the "$1$" scheme, identical to `openssl passwd -1`.
    /// This is what the fquinto installer uses for /etc/shadow entries.
    ///
    /// The algorithm was ported from a reference implementation checked
    /// byte-for-byte against openssl (see <see cref="SelfTest"/>); e.g.
    /// Crypt("pwned123", "root") == "$1$root$0i6hbFPn3JOGMeEF0LgEV1".
    /// </summary>
    public static class Md5Crypt
    {
        private const string ITOA64 =
            "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        /// <summary>
        /// Computes the $1$ MD5-crypt hash of <paramref name="password"/> with
        /// <paramref name="salt"/>. Returns "$1$salt$hash".
        /// <para>
        /// The salt is normalized exactly like crypt(3)/<c>openssl passwd -1</c>:
        /// an optional leading <c>$1$</c> magic is stripped, the salt ends at the
        /// first <c>$</c>, and it is capped at 8 characters. So a full setting
        /// string such as <c>$1$root$…</c> yields the same hash as the bare salt
        /// <c>root</c>.
        /// </para>
        /// </summary>
        public static string Crypt(string password, string salt)
        {
            byte[] pw = Encoding.UTF8.GetBytes(password);

            // Normalize the salt as crypt(3) does: drop the "$1$" magic prefix,
            // stop at the next '$', then cap at 8 chars.
            if (salt.StartsWith("$1$")) salt = salt.Substring(3);
            int dollar = salt.IndexOf('$');
            if (dollar >= 0) salt = salt.Substring(0, dollar);
            string saltStr = salt.Length > 8 ? salt.Substring(0, 8) : salt;
            byte[] saltBytes = Encoding.ASCII.GetBytes(saltStr);

            // alt = md5(pw + salt + pw)
            byte[] alt = Md5(pw, saltBytes, pw);

            // ctx = pw + "$1$" + salt + (alt repeated over pw length) + length bits
            var ctx = new List<byte>();
            ctx.AddRange(pw);
            ctx.AddRange("$1$"u8.ToArray());
            ctx.AddRange(saltBytes);

            for (int i = pw.Length; i > 0; i -= 16)
                ctx.AddRange(alt.AsSpan(0, Math.Min(i, 16)).ToArray());

            // For each bit of the password length: a 0x00 (bit set) or pw[0]
            // (bit clear). The loop never runs for an empty password, so pw[0]
            // is always valid here.
            for (int i = pw.Length; i != 0; i >>= 1)
                ctx.Add((i & 1) != 0 ? (byte)0x00 : pw[0]);

            byte[] final = Md5(ctx.ToArray());

            // 1000 stretching rounds
            for (int i = 0; i < 1000; i++)
            {
                var c = new List<byte>();
                c.AddRange((i & 1) != 0 ? pw : final);
                if (i % 3 != 0) c.AddRange(saltBytes);
                if (i % 7 != 0) c.AddRange(pw);
                c.AddRange((i & 1) != 0 ? final : pw);
                final = Md5(c.ToArray());
            }

            // Custom base64 rearrangement of the 16 digest bytes.
            var sb = new StringBuilder("$1$");
            sb.Append(saltStr).Append('$');
            AppendTo64(sb, (uint)((final[0] << 16) | (final[6] << 8) | final[12]), 4);
            AppendTo64(sb, (uint)((final[1] << 16) | (final[7] << 8) | final[13]), 4);
            AppendTo64(sb, (uint)((final[2] << 16) | (final[8] << 8) | final[14]), 4);
            AppendTo64(sb, (uint)((final[3] << 16) | (final[9] << 8) | final[15]), 4);
            AppendTo64(sb, (uint)((final[4] << 16) | (final[10] << 8) | final[5]), 4);
            AppendTo64(sb, final[11], 2);
            return sb.ToString();
        }

        /// <summary>
        /// Runs the known-good vectors (verified against openssl) and reports
        /// whether the implementation matches them all.
        /// </summary>
        public static (bool AllPass, string Report) SelfTest()
        {
            (string pw, string salt, string expected)[] vectors =
            {
                ("pwned123",             "root",     "$1$root$0i6hbFPn3JOGMeEF0LgEV1"),
                ("",                     "root",     "$1$root$PTgJv3alico0v8lBruv1y."),
                ("password",             "12345678", "$1$12345678$o2n/JiO/h5VviOInWJ4OQ/"),
                ("Bticino_Classe_100_X", "xyz",      "$1$xyz$GyaadV4enfbk3tpI30lSS1"),
                ("hello world",          "aB.7/xQ2", "$1$aB.7/xQ2$RGQ3Krk5B5/wUwoCMC5Md/"),
                // Salt normalization: a full "$1$root$" setting string must
                // yield the same hash as the bare salt "root" (as openssl does).
                ("pwned123",             "$1$root$", "$1$root$0i6hbFPn3JOGMeEF0LgEV1"),
            };

            var sb = new StringBuilder();
            bool all = true;
            foreach (var (pw, salt, expected) in vectors)
            {
                string got = Crypt(pw, salt);
                bool ok = got == expected;
                all &= ok;
                sb.AppendLine($"{(ok ? "PASS" : "FAIL")}  Crypt(\"{pw}\", \"{salt}\")");
                if (!ok)
                {
                    sb.AppendLine($"       got      = {got}");
                    sb.AppendLine($"       expected = {expected}");
                }
            }
            return (all, sb.ToString());
        }

        private static void AppendTo64(StringBuilder sb, uint value, int count)
        {
            for (int i = 0; i < count; i++)
            {
                sb.Append(ITOA64[(int)(value & 0x3f)]);
                value >>= 6;
            }
        }

        private static byte[] Md5(params byte[][] parts)
        {
            var buf = new List<byte>();
            foreach (var p in parts) buf.AddRange(p);
            return MD5.HashData(buf.ToArray());
        }
    }
}
