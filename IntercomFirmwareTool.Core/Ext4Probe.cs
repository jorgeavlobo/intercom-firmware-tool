using SharpExt4;
using System.Text;

namespace IntercomFirmwareTool.Core
{
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
        /// Detects a plausible MBR: the 0x55AA signature at the end of the first
        /// sector plus at least one non-empty partition entry. If present, the
        /// image is already a partitioned disk and should be read directly (not
        /// wrapped).
        /// </summary>
        private static bool HasValidMbr(string imagePath)
        {
            using var fs = new FileStream(imagePath, FileMode.Open, FileAccess.Read);
            if (fs.Length < SectorSize) return false;

            var mbr = new byte[SectorSize];
            fs.ReadExactly(mbr);
            if (mbr[510] != 0x55 || mbr[511] != 0xAA) return false;

            for (int i = 0; i < 4; i++)
            {
                int entry = 446 + i * 16;
                byte type = mbr[entry + 4];
                uint sectors = (uint)(mbr[entry + 12]
                                    | (mbr[entry + 13] << 8)
                                    | (mbr[entry + 14] << 16)
                                    | (mbr[entry + 15] << 24));
                if (type != 0 && sectors != 0) return true;
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
