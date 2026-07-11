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
                bool persisted = after.Contains(testLine);
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
                if (n <= 0) break;
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
