using SharpExt4;
using System.Text;

namespace IntercomFirmwareTool.Core
{
    /// <summary>Result of the ext4 write-persistence proof of concept.</summary>
    public sealed record Ext4WriteResult(
        bool CanWrite,
        string Before,
        string After,
        bool Persisted);

    /// <summary>
    /// Options for the SSH/root-enable edit (Phase A–D). <b>At least one</b>
    /// credential must be present — a root password and/or an SSH public key:
    /// <list type="bullet">
    ///   <item>password only → key login off, no <c>authorized_keys</c> written;</item>
    ///   <item>key only → password login disabled (shadow field <c>*</c>);</item>
    ///   <item>both → password and key login.</item>
    /// </list>
    /// </summary>
    public sealed record EnableSshOptions(
        string? RootPassword = null,
        string? PublicKey = null)
    {
        /// <summary>True when a non-empty root password is set (else login is key-only).</summary>
        public bool HasPassword => !string.IsNullOrEmpty(RootPassword);
        /// <summary>True when an SSH public key was supplied (so authorized_keys is written).</summary>
        public bool HasKey => !string.IsNullOrWhiteSpace(PublicKey);
    }

    /// <summary>One validation check: a name, pass/fail, and an optional detail.</summary>
    public sealed record Ext4Check(string Name, bool Pass, string Detail);

    /// <summary>
    /// Result of inspecting a firmware image's SSH-enable state WITHOUT the
    /// caller declaring the password or key: <see cref="Findings"/> are
    /// informational lines (password-login mode, installed key fingerprint),
    /// <see cref="Checks"/> are objective structural checks (accounts, perms,
    /// ownership, dropbear autostart), and <see cref="AllPass"/> is true when
    /// every structural check passed.
    /// </summary>
    public sealed record SshInspection(
        IReadOnlyList<string> Findings,
        IReadOnlyList<Ext4Check> Checks,
        bool AllPass);

    public static class Ext4Probe
    {
        private const int SectorSize = 512;
        // Default first-partition offset: 1 MiB = 2048 sectors.
        private const long PartitionStartSector = 2048;
        private const long PartitionOffsetBytes = PartitionStartSector * SectorSize;

        /// <summary>
        /// Opens an ext4 image and reads (read-only) the contents of a file
        /// inside it, returning it as text.
        ///
        /// Accepts both a partitioned disk image (with an MBR) and a "bare" ext4
        /// image (just the filesystem): in the latter case it automatically
        /// wraps it in a temporary MBR disk, because SharpExt4 can only open
        /// partitioned disks.
        /// </summary>
        /// <param name="imagePath">Path to the image on disk.</param>
        /// <param name="fileInsideImage">File inside the image, e.g. "/etc/hostname".</param>
        public static string ReadFile(string imagePath, string fileInsideImage)
        {
            // A partitioned image (valid MBR) is read directly; we only wrap it
            // when there is NO MBR and the content really is a bare ext4. This
            // avoids wrapping an already-partitioned image by mistake.
            if (!HasValidMbr(imagePath) && IsBareExt4(imagePath))
            {
                string wrapped = WrapBareFilesystem(imagePath);
                try
                {
                    return ReadFromDiskImage(wrapped, fileInsideImage);
                }
                finally
                {
                    TryDelete(wrapped);
                }
            }

            return ReadFromDiskImage(imagePath, fileInsideImage);
        }

        /// <summary>
        /// Opens an already-partitioned disk image, enters the first partition
        /// and reads (read-only) the requested file, with a bounded size.
        /// </summary>
        private static string ReadFromDiskImage(string diskImagePath, string fileInsideImage)
        {
            // 'using' releases disk, fs and file (all IDisposable, via the
            // C++/CLI destructor) at the end — on success or on exception —
            // preventing native handle leaks.
            using var disk = ExtDisk.Open(diskImagePath);
            if (disk.Partitions.Count == 0)
                throw new InvalidOperationException(
                    "The image has no recognizable partitions (MBR without valid entries).");

            // The real API is Open(ExtDisk, Partition) — two arguments.
            // (The SharpExt4 README shows only one, but it's wrong.)
            using var fs = ExtFileSystem.Open(disk, disk.Partitions[0]);
            return ReadAllTextFromFs(fs, fileInsideImage);
        }

        /// <summary>
        /// Reads a whole file from an already-open filesystem as text, with a
        /// bounded size so a huge file can't exhaust memory.
        /// </summary>
        private static string ReadAllTextFromFs(ExtFileSystem fs, string fileInsideImage)
        {
            using var file = fs.OpenFile(fileInsideImage, FileMode.Open, FileAccess.Read);

            const long maxBytes = 64L * 1024 * 1024; // 64 MiB: plenty for text/config
            long length = file.Length;
            if (length > maxBytes)
                throw new NotSupportedException(
                    $"File too large for this test: {length} bytes (limit {maxBytes} bytes).");

            int len = (int)length;
            var buf = new byte[len];
            int total = 0;
            while (total < len)
            {
                int n = file.Read(buf, total, len - total);
                if (n <= 0)
                    throw new EndOfStreamException(
                        $"Incomplete read: expected {len} bytes, got {total}.");
                total += n;
            }
            return Encoding.UTF8.GetString(buf, 0, total);
        }

        /// <summary>
        /// Proof-of-concept WRITE test on a bare ext4 image, all on temp files:
        /// wraps the image in an MBR disk, mounts it read-write and reports
        /// <c>CanWrite</c>; if writable, appends <paramref name="testLine"/> to
        /// <paramref name="targetFile"/>, flushes/unmounts, slices the modified
        /// partition back out to a raw ext4 (same format and size), reopens it
        /// and re-reads the file to confirm the change persisted.
        /// Never touches the caller's original files.
        /// </summary>
        public static Ext4WriteResult TestAppendPersists(
            string bareImagePath, string targetFile, string testLine)
        {
            EnsureBareExt4(bareImagePath); // wraps/slices below; require a bare ext4

            // Content before any change (read via the normal wrap-and-read path).
            string before = ReadFile(bareImagePath, targetFile);

            long bareSize = new FileInfo(bareImagePath).Length;
            string disk = WrapBareFilesystem(bareImagePath);
            string modifiedBare = Path.Combine(
                Path.GetTempPath(), $"sharpext4_out_{Guid.NewGuid():N}.ext4");
            try
            {
                bool canWrite;

                // --- write scope: everything is flushed/unmounted when this
                //     block ends (fs then disk are disposed in reverse order). ---
                using (var d = ExtDisk.Open(disk))
                using (var fs = ExtFileSystem.Open(d, d.Partitions[0]))
                {
                    canWrite = fs.CanWrite;
                    if (canWrite)
                    {
                        // Read current content, append the test line, write the
                        // whole file back (Create truncates then rewrites).
                        string current = ReadAllTextFromFs(fs, targetFile);
                        string updated = current;
                        if (updated.Length > 0 && !updated.EndsWith("\n"))
                            updated += "\n";
                        updated += testLine + "\n";

                        byte[] bytes = Encoding.UTF8.GetBytes(updated);
                        using var wf = fs.OpenFile(targetFile, FileMode.Create, FileAccess.Write);
                        wf.Write(bytes, 0, bytes.Length);
                    }
                }

                if (!canWrite)
                    return new Ext4WriteResult(false, before, before, false);

                // Back to a raw ext4: copy the partition region [1 MiB, 1 MiB+size)
                // out of the (now modified) wrapper disk.
                SlicePartitionToBare(disk, modifiedBare, bareSize);

                // Reopen the raw ext4 from scratch and re-read the file.
                string after = ReadFile(modifiedBare, targetFile);
                // Persisted only if the file exactly equals what we wrote (the
                // original content plus the appended line), not merely contains
                // the marker — that would also pass for a pre-existing marker.
                string expected = before;
                if (expected.Length > 0 && !expected.EndsWith("\n")) expected += "\n";
                expected += testLine + "\n";
                bool persisted = after == expected;
                return new Ext4WriteResult(true, before, after, persisted);
            }
            finally
            {
                TryDelete(disk);
                TryDelete(modifiedBare);
            }
        }

        /// <summary>
        /// Copies the partition region (offset 1 MiB, length <paramref name="bareSize"/>)
        /// out of a wrapper disk into a standalone raw ext4 file.
        /// </summary>
        private static void SlicePartitionToBare(string diskImagePath, string outBarePath, long bareSize)
        {
            using var inFs = new FileStream(diskImagePath, FileMode.Open, FileAccess.Read);
            using var outFs = new FileStream(outBarePath, FileMode.CreateNew, FileAccess.Write);
            inFs.Seek(PartitionOffsetBytes, SeekOrigin.Begin);

            var buffer = new byte[81920];
            long remaining = bareSize;
            while (remaining > 0)
            {
                int toRead = (int)Math.Min(buffer.Length, remaining);
                int n = inFs.Read(buffer, 0, toRead);
                if (n <= 0)
                    // The wrapper disk should always be at least PartitionOffset +
                    // bareSize; if it ends early we would emit a truncated ext4 —
                    // fail loudly rather than write a corrupt image.
                    throw new EndOfStreamException(
                        $"Wrapper disk ended early: {remaining} of {bareSize} bytes unread; " +
                        "the sliced ext4 would be truncated.");
                outFs.Write(buffer, 0, n);
                remaining -= n;
            }
        }

        /// <summary>
        /// Detects a plausible MBR: the 0x55AA signature at the end of the first
        /// sector plus at least one partition entry that is non-empty, starts
        /// past the MBR, and fits within the file. If present, the image is
        /// already a partitioned disk and should be read directly (not wrapped).
        /// </summary>
        private static bool HasValidMbr(string imagePath)
        {
            using var fs = new FileStream(imagePath, FileMode.Open, FileAccess.Read);
            long fileLength = fs.Length;
            if (fileLength < SectorSize) return false;

            var mbr = new byte[SectorSize];
            fs.ReadExactly(mbr);
            if (mbr[510] != 0x55 || mbr[511] != 0xAA) return false;

            for (int i = 0; i < 4; i++)
            {
                int entry = 446 + i * 16;
                byte type = mbr[entry + 4];
                uint startSector = ReadUInt32LE(mbr, entry + 8);
                uint sectorCount = ReadUInt32LE(mbr, entry + 12);
                if (type == 0 || startSector == 0 || sectorCount == 0) continue;

                // The declared partition must start past the MBR and fit inside
                // the file — this rejects a stray 0x55AA in a bare ext4 image.
                long end = ((long)startSector + sectorCount) * SectorSize;
                if (end <= fileLength) return true;
            }
            return false;
        }

        /// <summary>
        /// Detects a "bare" ext2/3/4 image (no partition table): the 0xEF53
        /// superblock magic is always at offset 1080 (0x438).
        /// </summary>
        private static bool IsBareExt4(string imagePath)
        {
            using var fs = new FileStream(imagePath, FileMode.Open, FileAccess.Read);
            if (fs.Length < 1082) return false;

            fs.Seek(1080, SeekOrigin.Begin);
            int lo = fs.ReadByte();
            int hi = fs.ReadByte();
            // 0xEF53 little-endian => bytes 0x53, 0xEF.
            return lo == 0x53 && hi == 0xEF;
        }

        /// <summary>
        /// Fast guard for the write-phase entry points, which always wrap the input
        /// in a fresh MBR: require a <b>bare</b> ext4 image (superblock magic at
        /// 0x438, no partition table). A partitioned disk or a non-ext4 file would
        /// otherwise be wrapped blindly and fail in non-obvious ways or corrupt the
        /// output. This mirrors the shape check <see cref="ReadFile"/> uses.
        /// </summary>
        private static void EnsureBareExt4(string bareImagePath)
        {
            // Bare ext4 = NO partition table AND the ext4 superblock magic at
            // 0x438. Reject a partitioned disk even if 0xEF53 happens to appear at
            // that offset, so we never wrap/slice the wrong bytes — same shape
            // decision ReadFile uses (!HasValidMbr && IsBareExt4), failing closed.
            if (HasValidMbr(bareImagePath) || !IsBareExt4(bareImagePath))
                throw new ArgumentException(
                    "Expected a bare ext4 image (no partition table, ext4 superblock magic " +
                    "0xEF53 at offset 0x438). This method operates on the raw ext4 payload, " +
                    "not a .fwz container or an already-partitioned disk image.",
                    nameof(bareImagePath));
        }

        /// <summary>
        /// Creates a temporary disk file made of an MBR (with one Linux
        /// partition starting at the 1 MiB offset) followed by the ext4 data.
        /// Returns the temp path, which must then be deleted.
        /// </summary>
        private static string WrapBareFilesystem(string bareImagePath)
        {
            long fsSize = new FileInfo(bareImagePath).Length;
            long sectorCount = (fsSize + SectorSize - 1) / SectorSize;
            if (sectorCount > uint.MaxValue)
                throw new NotSupportedException(
                    "Image too large to wrap with an MBR (>2TB).");

            string tempPath = Path.Combine(
                Path.GetTempPath(),
                $"sharpext4_probe_{Guid.NewGuid():N}.img");

            try
            {
                using (var outFs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write))
                {
                    var mbr = new byte[SectorSize];
                    const int entry = 446; // first partition table entry
                    mbr[entry + 0] = 0x00;                                     // not bootable
                    mbr[entry + 4] = 0x83;                                     // type: Linux
                    WriteUInt32LE(mbr, entry + 8, (uint)PartitionStartSector); // start LBA
                    WriteUInt32LE(mbr, entry + 12, (uint)sectorCount);         // sector count
                    mbr[510] = 0x55;                                           // MBR signature
                    mbr[511] = 0xAA;
                    outFs.Write(mbr, 0, SectorSize);

                    // Seek to the partition offset (the gap stays zeroed) and
                    // copy the ext4 data into it.
                    outFs.Seek(PartitionOffsetBytes, SeekOrigin.Begin);
                    using (var inFs = new FileStream(bareImagePath, FileMode.Open, FileAccess.Read))
                        inFs.CopyTo(outFs);

                    // Make sure the partition declared in the MBR is fully backed
                    // (zero-padded if fsSize is not a multiple of the sector), so
                    // SharpExt4 can read to the end without running past EOF.
                    outFs.SetLength(PartitionOffsetBytes + sectorCount * (long)SectorSize);
                }

                return tempPath;
            }
            catch
            {
                // If creation/copy fails midway, don't leave an orphan temp file.
                TryDelete(tempPath);
                throw;
            }
        }

        // ---- Write phase: enable SSH (replicates fquinto's rootfs edits) -----

        /// <summary>
        /// Applies the fquinto SSH/root-enable edits (Phase A–D) to a bare ext4
        /// image and returns the path of a NEW modified bare ext4 (same format
        /// and size). The input image is never modified. Throws if the
        /// filesystem mounts read-only.
        /// </summary>
        public static string EnableSsh(string bareImagePath, EnableSshOptions opts)
        {
            ValidateOptions(opts);
            EnsureBareExt4(bareImagePath);
            long bareSize = new FileInfo(bareImagePath).Length;
            string disk = WrapBareFilesystem(bareImagePath);
            string modifiedBare = Path.Combine(
                Path.GetTempPath(), $"sharpext4_ssh_{Guid.NewGuid():N}.ext4");
            try
            {
                using (var d = ExtDisk.Open(disk))
                using (var fs = ExtFileSystem.Open(d, d.Partitions[0]))
                {
                    if (!fs.CanWrite)
                        throw new InvalidOperationException(
                            "The filesystem mounted READ-ONLY (CanWrite=false); cannot write.");
                    ApplySshEnable(fs, opts);
                }
                // fs/disk disposed above => flushed + unmounted; now recut to raw.
                SlicePartitionToBare(disk, modifiedBare, bareSize);
                return modifiedBare;
            }
            catch
            {
                TryDelete(modifiedBare);
                throw;
            }
            finally
            {
                TryDelete(disk);
            }
        }

        /// <summary>
        /// Defensive validation of the options, independent of any UI-layer
        /// checks, so a non-UI caller can't produce an insecure or non-functional
        /// image: at least one credential (a root password and/or an SSH public
        /// key) is required; a supplied key must be a single valid OpenSSH
        /// public-key line; and a key-only build (no password fallback) must use an
        /// RSA key — the only type verified to authenticate on the target firmware.
        /// </summary>
        private static void ValidateOptions(EnableSshOptions opts)
        {
            if (!opts.HasPassword && !opts.HasKey)
                throw new ArgumentException(
                    "At least one credential is required: a root password and/or an SSH public key.",
                    nameof(opts));
            // A supplied key is written into authorized_keys, so it must be a SINGLE
            // valid OpenSSH public-key line — reject multi-line/garbage here too (the
            // UI already checks this) so a non-UI caller cannot pass text that
            // silently authorizes extra keys.
            if (opts.HasKey && !SshKeyGen.IsLikelyPublicKey(opts.PublicKey!))
                throw new ArgumentException(
                    "The SSH public key must be a single valid OpenSSH public-key line " +
                    "(e.g. \"ssh-rsa AAAA… comment\").", nameof(opts));
            // Key-only login has NO password fallback, so the key must be RSA — the
            // only algorithm verified to authenticate on the target firmware's
            // dropbear; a non-RSA key-only build could yield no usable login.
            if (!opts.HasPassword && opts.HasKey && SshKeyGen.KeyType(opts.PublicKey!) != "ssh-rsa")
                throw new ArgumentException(
                    "Key-only login (no password) requires an RSA public key — the only key type " +
                    "verified to authenticate on the target firmware. Add a password, or use an RSA key.",
                    nameof(opts));
        }

        /// <summary>Applies the ordered Phase A–D edits on an open, writable fs.</summary>
        private static void ApplySshEnable(ExtFileSystem fs, EnableSshOptions opts)
        {
            // Guard: the edits are meant for an ORIGINAL firmware. Appending the
            // accounts is not idempotent, so refuse an image that already has a
            // "root2" account (e.g. a previously-modified .fwz) rather than
            // duplicating entries and producing an ambiguous result.
            string existingPasswd = fs.FileExists("/etc/passwd") ? ReadAllTextFromFs(fs, "/etc/passwd") : "";
            bool alreadyModified = existingPasswd.Replace("\r\n", "\n").Split('\n')
                .Any(l => l.StartsWith("root2:", StringComparison.Ordinal));
            if (alreadyModified)
                throw new InvalidOperationException(
                    "This firmware already contains a 'root2' account — it appears to be already " +
                    "SSH-enabled. Run the tool on the ORIGINAL, unmodified firmware.");

            // Phase A — accounts. Password set via MD5-crypt (salt "root") when
            // one was given; otherwise the shadow field is "*" (password login
            // disabled — key-only). At least one credential is guaranteed above.
            string secret = opts.HasPassword ? Md5Crypt.Crypt(opts.RootPassword!, "root") : "*";
            AppendLines(fs, "/etc/passwd", new[]
            {
                "root2:x:0:0:root:/home/root:/bin/sh",
                "bticino2:x:1000:1000::/home/bticino:/bin/sh",
            });
            AppendLines(fs, "/etc/shadow", new[]
            {
                $"root2:{secret}:18033:0:99999:7:::",
                $"bticino2:{secret}:18033:0:99999:7:::",
            });

            // Phases B/C — SSH key (OPTIONAL). Only when a key was supplied: write
            // it to root's home and to dropbear's system path. Without a key, login
            // is by password only and no authorized_keys is created.
            if (opts.HasKey)
            {
                string pub = EnsureTrailingNewline(opts.PublicKey!);

                // Phase B — the key in root's home. Create parents, then .ssh, then
                // authorized_keys (0600, root:root). The .ssh dir is 0755, matching
                // fquinto exactly (its `mkdir -p` under the default umask). Neither
                // /home/root/.ssh nor any authorized_keys exists in the factory
                // firmware (verified: /home/root has only .bash_history and .cache;
                // /etc/dropbear has only dropbear_rsa_host_key) — the whole key-login
                // mechanism is created here, so there is no "factory" mode to copy.
                // Security comes from the parent: /home/root is 0700 root:root at
                // factory (verified drwx------), so anything inside (.ssh at 0755 or
                // 0700) is unreachable by other users regardless. dropbear accepts
                // 0755 — it only rejects a group/other-WRITABLE .ssh, which 0755 is not.
                // /home/root is 0700 root:root at factory — that 0700 is precisely
                // what keeps .ssh unreachable by other users. It always exists on
                // real firmware (so we leave it untouched, like fquinto). This is
                // defensive: if an image ever lacked it, create it at 0700 (not
                // EnsureDir's 0755 default) so the security invariant still holds.
                bool homeRootExisted = fs.DirectoryExists("/home/root");
                EnsureDir(fs, "/home");
                EnsureDir(fs, "/home/root");
                if (!homeRootExisted)
                {
                    fs.SetMode("/home/root", ToMode(700));
                    fs.SetOwner("/home/root", 0, 0);
                }
                EnsureDir(fs, "/home/root/.ssh");
                fs.SetMode("/home/root/.ssh", ToMode(755));
                fs.SetOwner("/home/root/.ssh", 0, 0);
                WriteTextFile(fs, "/home/root/.ssh/authorized_keys", pub);
                fs.SetMode("/home/root/.ssh/authorized_keys", ToMode(600));
                fs.SetOwner("/home/root/.ssh/authorized_keys", 0, 0);

                // Phase C — the key in dropbear's system path (0600, root:root).
                EnsureDir(fs, "/etc/dropbear");
                WriteTextFile(fs, "/etc/dropbear/authorized_keys", pub);
                fs.SetMode("/etc/dropbear/authorized_keys", ToMode(600));
                fs.SetOwner("/etc/dropbear/authorized_keys", 0, 0);
            }

            // Phase D — start dropbear at boot via the rc5.d symlink (relative
            // target, stored verbatim). Check the prerequisites first so a
            // missing init script or rc5.d dir gives a clear error instead of a
            // dangling link or an opaque native failure.
            if (!fs.FileExists("/etc/init.d/dropbear"))
                throw new InvalidOperationException(
                    "/etc/init.d/dropbear is missing in the image; cannot enable dropbear at boot.");
            if (!fs.DirectoryExists("/etc/rc5.d"))
                throw new InvalidOperationException(
                    "/etc/rc5.d is missing in the image; cannot create the S98dropbear symlink.");

            // Create the symlink, but tolerate one that is already correct and
            // fail clearly on one that points elsewhere (rather than letting the
            // native call throw opaquely on an existing path).
            const string linkPath = "/etc/rc5.d/S98dropbear";
            const string linkTarget = "../init.d/dropbear";
            string? existingTarget = null;
            try { existingTarget = fs.ReadSymLink(linkPath); } catch { /* absent or not a symlink */ }
            if (existingTarget != null)
            {
                // A symlink already exists: fine if it points at our target,
                // otherwise fail clearly rather than overwriting it.
                if (existingTarget != linkTarget)
                    throw new InvalidOperationException(
                        $"{linkPath} already exists but points to '{existingTarget}', not '{linkTarget}'.");
            }
            else if (fs.FileExists(linkPath) || fs.DirectoryExists(linkPath))
            {
                // The path is occupied by a non-symlink (regular file or dir);
                // give a clear error instead of an opaque native "exists" throw.
                throw new InvalidOperationException(
                    $"{linkPath} already exists but is not a symlink; refusing to overwrite it.");
            }
            else
            {
                fs.CreateSymLink(linkTarget, linkPath);
            }
        }

        /// <summary>
        /// Reopens a modified bare ext4 and re-reads every expected change,
        /// returning a pass/fail checklist (self-consistency validation).
        /// </summary>
        public static IReadOnlyList<Ext4Check> ValidateSsh(string bareImagePath, EnableSshOptions opts)
        {
            // Same credential/key contract as EnableSsh: reject empty or malformed
            // options up front, so a non-UI caller can't get a misleading all-pass
            // for an image with no usable credential (root2 "*" and no key).
            ValidateOptions(opts);
            EnsureBareExt4(bareImagePath);
            var checks = new List<Ext4Check>();
            string disk = WrapBareFilesystem(bareImagePath);
            try
            {
                using var d = ExtDisk.Open(disk);
                using var fs = ExtFileSystem.Open(d, d.Partitions[0]);

                // Match whole lines (not substrings) so e.g. a "notroot2:…"
                // entry can't satisfy the "root2" check, and require exactly one.
                string passwd = ReadAllTextFromFs(fs, "/etc/passwd");
                checks.Add(new("/etc/passwd has root2",
                    HasExactLine(passwd, "root2:x:0:0:root:/home/root:/bin/sh"), ""));
                checks.Add(new("/etc/passwd has bticino2",
                    HasExactLine(passwd, "bticino2:x:1000:1000::/home/bticino:/bin/sh"), ""));

                string secret = opts.HasPassword ? Md5Crypt.Crypt(opts.RootPassword!, "root") : "*";
                string shadow = ReadAllTextFromFs(fs, "/etc/shadow");
                checks.Add(new("/etc/shadow has root2 entry",
                    HasExactLine(shadow, $"root2:{secret}:18033:0:99999:7:::"), ""));
                checks.Add(new("/etc/shadow has bticino2 entry",
                    HasExactLine(shadow, $"bticino2:{secret}:18033:0:99999:7:::"), ""));

                // With a key: assert it is deployed correctly. Without a key
                // (password-only): assert the key material is ABSENT — a stray
                // authorized_keys would be an unexpected, unauthorized credential.
                if (opts.HasKey)
                {
                    CheckDir(fs, checks, "/home/root/.ssh");
                    CheckAuthKeys(fs, checks, "/home/root/.ssh/authorized_keys", opts.PublicKey!);
                    CheckAuthKeys(fs, checks, "/etc/dropbear/authorized_keys", opts.PublicKey!);
                }
                else
                {
                    checks.Add(new("/home/root/.ssh/authorized_keys absent (password-only)",
                        !fs.FileExists("/home/root/.ssh/authorized_keys"), ""));
                    checks.Add(new("/etc/dropbear/authorized_keys absent (password-only)",
                        !fs.FileExists("/etc/dropbear/authorized_keys"), ""));
                }

                string target = "";
                bool symOk = false;
                try { target = fs.ReadSymLink("/etc/rc5.d/S98dropbear"); symOk = target == "../init.d/dropbear"; }
                catch { /* missing or not a symlink */ }
                checks.Add(new("/etc/rc5.d/S98dropbear -> ../init.d/dropbear", symOk, target));

                // Explicit prerequisites, so a missing rc5.d/init script shows up
                // as its own clear check instead of only as a failing symlink.
                checks.Add(new("/etc/rc5.d exists (prerequisite)",
                    fs.DirectoryExists("/etc/rc5.d"), ""));
                checks.Add(new("/etc/init.d/dropbear exists (prerequisite)",
                    fs.FileExists("/etc/init.d/dropbear"), ""));
            }
            finally
            {
                TryDelete(disk);
            }
            return checks;
        }

        /// <summary>
        /// Inspects an already-built bare ext4 image and REPORTS its SSH-enable
        /// state, instead of comparing against a caller-supplied password/key.
        /// It reads what is actually installed — password-login mode (from the
        /// shadow secret's shape, never the plaintext), the deployed key's
        /// SHA-256 fingerprint — and runs the objective structural checks
        /// (accounts, .ssh/authorized_keys permissions and ownership, dropbear
        /// autostart). This is what the UI's "Verify existing .fwz" uses so the
        /// operator just points at a file and reads a report.
        /// </summary>
        public static SshInspection InspectSsh(string bareImagePath)
        {
            EnsureBareExt4(bareImagePath);
            var checks = new List<Ext4Check>();
            var findings = new List<string>();
            string disk = WrapBareFilesystem(bareImagePath);
            try
            {
                using var d = ExtDisk.Open(disk);
                using var fs = ExtFileSystem.Open(d, d.Partitions[0]);

                // Accounts (objective): the two entries fquinto appends.
                string passwd = ReadAllTextFromFs(fs, "/etc/passwd");
                checks.Add(new("/etc/passwd has root2",
                    HasExactLine(passwd, "root2:x:0:0:root:/home/root:/bin/sh"), ""));
                checks.Add(new("/etc/passwd has bticino2",
                    HasExactLine(passwd, "bticino2:x:1000:1000::/home/bticino:/bin/sh"), ""));

                // Shadow: derive the password-login mode from the secret's shape,
                // WITHOUT knowing (or being able to reverse) the plaintext.
                string shadow = ReadAllTextFromFs(fs, "/etc/shadow");
                string? root2Secret = ShadowSecret(shadow, "root2");
                string? bticino2Secret = ShadowSecret(shadow, "bticino2");
                bool root2Present = root2Secret != null;
                checks.Add(new("/etc/shadow has root2 entry", root2Present, ""));
                checks.Add(new("/etc/shadow has bticino2 entry", bticino2Secret != null, ""));

                bool passwordLogin = IsMd5CryptHash(root2Secret);
                if (passwordLogin)
                    findings.Add("Password login : ENABLED  (root2 has an MD5-crypt $1$ hash in /etc/shadow)");
                else if (root2Present)
                    findings.Add($"Password login : disabled  (root2 shadow field is \"{root2Secret}\" — key-only)");
                else
                    findings.Add("Password login : n/a  (no root2 entry in /etc/shadow)");

                // fquinto sets root2 and bticino2 to the same secret; a mismatch
                // means the image was not built the expected way.
                if (root2Present && bticino2Secret != null)
                    checks.Add(new("/etc/shadow root2 and bticino2 use the same secret",
                        root2Secret == bticino2Secret, ""));

                // Keys: report presence + fingerprint (informational) and enforce
                // the perms/ownership contract wherever a key is actually deployed.
                bool homeKeyPresent = fs.FileExists("/home/root/.ssh/authorized_keys");
                if (homeKeyPresent) CheckDir(fs, checks, "/home/root/.ssh");
                string? homeKey = InspectAuthKeys(fs, checks, findings, "/home/root/.ssh/authorized_keys", "home");
                string? dropbearKey = InspectAuthKeys(fs, checks, findings, "/etc/dropbear/authorized_keys", "dropbear");
                bool keyInstalled = homeKey != null || dropbearKey != null;

                if (homeKey != null && dropbearKey != null)
                    checks.Add(new("authorized_keys identical in both locations",
                        homeKey.Trim() == dropbearKey.Trim(), ""));

                // Dropbear autostart (objective).
                string target = "";
                bool symOk = false;
                try { target = fs.ReadSymLink("/etc/rc5.d/S98dropbear"); symOk = target == "../init.d/dropbear"; }
                catch { /* missing or not a symlink */ }
                checks.Add(new("/etc/rc5.d/S98dropbear -> ../init.d/dropbear", symOk, target));
                checks.Add(new("/etc/rc5.d exists (prerequisite)",
                    fs.DirectoryExists("/etc/rc5.d"), ""));
                checks.Add(new("/etc/init.d/dropbear exists (prerequisite)",
                    fs.FileExists("/etc/init.d/dropbear"), ""));

                // A valid SSH-enable must leave at least one usable login.
                string how = passwordLogin && keyInstalled ? "password + key"
                    : passwordLogin ? "password" : keyInstalled ? "key" : "none";
                checks.Add(new("At least one login credential present (password or key)",
                    passwordLogin || keyInstalled, how));
            }
            finally
            {
                TryDelete(disk);
            }
            bool all = true;
            foreach (var c in checks) all &= c.Pass;
            return new SshInspection(findings, checks, all);
        }

        /// <summary>
        /// Reports an authorized_keys file: appends a finding (absent / present
        /// but invalid / installed with the key's label + SHA-256 fingerprint),
        /// and — when the file exists — adds the objective 0600 mode and 0:0 owner
        /// checks. Returns the trimmed key content ONLY when it is a usable
        /// OpenSSH public key; returns null when the file is absent OR its content
        /// is not a valid key. Returning null for garbage content is important:
        /// the caller counts a non-null return as an installed credential, so a
        /// present-but-unparseable authorized_keys must NOT make the image look
        /// like it has a working key-based login (it cannot authenticate).
        /// </summary>
        private static string? InspectAuthKeys(
            ExtFileSystem fs, List<Ext4Check> checks, List<string> findings, string path, string label)
        {
            if (!fs.FileExists(path))
            {
                findings.Add($"SSH key ({label}) : not installed  ({path} absent)");
                return null;
            }

            // Objective perms/ownership (StrictModes contract) apply to whatever
            // file is there, valid key or not.
            uint mode = fs.GetMode(path) & 0xFFF;
            checks.Add(new($"{path} mode 0600",
                mode == ToMode(600), $"actual 0{Convert.ToString((long)mode, 8)}"));
            var owner = fs.GetOwner(path);
            checks.Add(new($"{path} owner 0:0",
                owner != null && owner.Item1 == 0 && owner.Item2 == 0,
                owner != null ? $"{owner.Item1}:{owner.Item2}" : "null"));

            string content = ReadAllTextFromFs(fs, path).Trim();
            var info = SshKeyGen.DescribePublicKey(content);
            if (info == null)
            {
                // Present but not a usable key: report it and flag a FAILING
                // check, and return null so it is not counted as a credential.
                findings.Add($"SSH key ({label}) : present but INVALID — not a usable OpenSSH public key ({path})");
                checks.Add(new($"{path} is a valid OpenSSH public key", false, ""));
                return null;
            }
            findings.Add($"SSH key ({label}) : installed  {info.Label}  {info.Sha256Fingerprint}");
            return content;
        }

        /// <summary>
        /// Returns the second (secret) field of the /etc/shadow line for
        /// <paramref name="user"/>, or null if there is no such line.
        /// </summary>
        private static string? ShadowSecret(string shadow, string user)
        {
            foreach (var line in shadow.Replace("\r\n", "\n").Split('\n'))
            {
                if (line.StartsWith(user + ":", StringComparison.Ordinal))
                {
                    string[] f = line.Split(':');
                    return f.Length > 1 ? f[1] : "";
                }
            }
            return null;
        }

        /// <summary>True if the shadow secret is an MD5-crypt ($1$) hash — i.e.
        /// password login is enabled (as opposed to "*"/"!" which disable it).</summary>
        private static bool IsMd5CryptHash(string? secret) =>
            secret != null && secret.StartsWith("$1$", StringComparison.Ordinal);

        private static void CheckDir(ExtFileSystem fs, List<Ext4Check> checks, string path)
        {
            bool exists = fs.DirectoryExists(path);
            checks.Add(new($"{path} exists", exists, ""));
            if (!exists) return;

            // Functional requirement (dropbear/OpenSSH StrictModes): the .ssh
            // directory must not be writable by group or other. We set 0755
            // (matching fquinto); the check stays functional — 0755 passes,
            // 0770/0777 would fail — so it also tolerates a stricter 0700.
            uint mode = fs.GetMode(path) & 0xFFF;
            bool safe = (mode & 0b000_010_010u) == 0;
            checks.Add(new($"{path} not group/other-writable",
                safe, $"actual 0{Convert.ToString((long)mode, 8)}"));

            var owner = fs.GetOwner(path);
            checks.Add(new($"{path} owner 0:0",
                owner != null && owner.Item1 == 0 && owner.Item2 == 0,
                owner != null ? $"{owner.Item1}:{owner.Item2}" : "null"));
        }

        private static void CheckAuthKeys(ExtFileSystem fs, List<Ext4Check> checks, string path, string publicKey)
        {
            bool exists = fs.FileExists(path);
            checks.Add(new($"{path} exists", exists, ""));
            if (!exists) return;
            string content = ReadAllTextFromFs(fs, path);
            // Require a non-empty expected key, otherwise an empty authorized_keys
            // would "match" an empty expectation and PASS misleadingly.
            bool keyOk = !string.IsNullOrWhiteSpace(publicKey) && content.Trim() == publicKey.Trim();
            checks.Add(new($"{path} content == key", keyOk, ""));
            uint mode = fs.GetMode(path) & 0xFFF;
            checks.Add(new($"{path} mode 0600",
                mode == ToMode(600), $"actual 0{Convert.ToString((long)mode, 8)}"));
            var owner = fs.GetOwner(path);
            checks.Add(new($"{path} owner 0:0",
                owner != null && owner.Item1 == 0 && owner.Item2 == 0,
                owner != null ? $"{owner.Item1}:{owner.Item2}" : "null"));
        }

        private static uint ToMode(int octalDigits) => Convert.ToUInt32(octalDigits.ToString(), 8);

        private static string EnsureTrailingNewline(string s) => s.EndsWith("\n") ? s : s + "\n";

        /// <summary>True if exactly one line of <paramref name="content"/> equals <paramref name="expected"/>.</summary>
        private static bool HasExactLine(string content, string expected) =>
            content.Replace("\r\n", "\n").Split('\n').Count(line => line == expected) == 1;

        private static void AppendLines(ExtFileSystem fs, string path, string[] lines)
        {
            // /etc/passwd and /etc/shadow must already exist: creating them here
            // would give them unknown metadata, so refuse if they are missing.
            if (!fs.FileExists(path))
                throw new InvalidOperationException(
                    $"{path} does not exist in the image; refusing to create it (it would get unknown mode/owner).");
            string current = ReadAllTextFromFs(fs, path);
            var sb = new StringBuilder(current);
            // Correction #3: don't glue the new line onto the last existing one.
            if (sb.Length > 0 && sb[sb.Length - 1] != '\n') sb.Append('\n');
            foreach (var line in lines) sb.Append(line).Append('\n');

            // Capture the existing mode/owner and re-apply them after the rewrite.
            // WriteTextFile truncates via FileMode.Create; lwext4 truncates in
            // place, but re-applying makes the perms/owner independent of that
            // behaviour — important for /etc/shadow, which must stay 0600 root:root.
            uint mode = fs.GetMode(path) & 0xFFF;
            var owner = fs.GetOwner(path);
            WriteTextFile(fs, path, sb.ToString());
            fs.SetMode(path, mode);
            if (owner != null) fs.SetOwner(path, owner.Item1, owner.Item2);
        }

        private static void WriteTextFile(ExtFileSystem fs, string path, string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            using var f = fs.OpenFile(path, FileMode.Create, FileAccess.Write);
            f.Write(bytes, 0, bytes.Length);
        }

        private static void EnsureDir(ExtFileSystem fs, string path)
        {
            if (fs.DirectoryExists(path)) return;
            // lwext4 does not give a newly created object root:root or a known
            // mode, so set both explicitly (0755 is a safe, not group/other-
            // writable default; callers override it where a specific mode is
            // required).
            fs.CreateDirectory(path);
            fs.SetMode(path, ToMode(755));
            fs.SetOwner(path, 0, 0);
        }

        /// <summary>Reads a little-endian uint32 from a buffer at the given offset.</summary>
        private static uint ReadUInt32LE(byte[] buffer, int offset) =>
            (uint)(buffer[offset]
                 | (buffer[offset + 1] << 8)
                 | (buffer[offset + 2] << 16)
                 | (buffer[offset + 3] << 24));

        /// <summary>Writes a uint32 in little-endian into a buffer at the given offset.</summary>
        private static void WriteUInt32LE(byte[] buffer, int offset, uint value)
        {
            buffer[offset + 0] = (byte)(value & 0xFF);
            buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
            buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
            buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        /// <summary>Deletes a file if it exists, ignoring failures (best-effort).</summary>
        private static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); }
            catch { /* best-effort cleanup */ }
        }
    }
}
