using SharpExt4;
using System.Text;

namespace IntercomFirmwareTool.Core
{
    public static class Ext4Probe
    {
        private const int SectorSize = 512;
        // Offset padrão de uma primeira partição: 1 MiB = 2048 setores.
        private const long PartitionStartSector = 2048;
        private const long PartitionOffsetBytes = PartitionStartSector * SectorSize;

        /// <summary>
        /// Abre uma imagem ext4 e lê (só leitura) o conteúdo de um ficheiro lá
        /// de dentro, devolvendo-o como texto.
        ///
        /// Aceita tanto uma imagem de disco com tabela de partições (MBR) como
        /// uma imagem ext4 "crua" (só o sistema de ficheiros): neste último caso
        /// envolve-a automaticamente num disco temporário com MBR, porque a
        /// SharpExt4 só sabe abrir discos particionados.
        /// </summary>
        /// <param name="imagePath">Caminho para a imagem no disco.</param>
        /// <param name="fileInsideImage">Ficheiro dentro da imagem, ex.: "/etc/hostname".</param>
        public static string ReadFile(string imagePath, string fileInsideImage)
        {
            if (IsBareExt4(imagePath))
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

        private static string ReadFromDiskImage(string diskImagePath, string fileInsideImage)
        {
            // 'using' liberta disk, fs e file (todos IDisposable, via destrutor
            // C++/CLI) no fim — em sucesso ou em exceção — evitando fugas de
            // handles nativos.
            using var disk = ExtDisk.Open(diskImagePath);
            if (disk.Partitions.Count == 0)
                throw new InvalidOperationException(
                    "A imagem não tem partições reconhecíveis (MBR sem entradas válidas).");

            // A API real é Open(ExtDisk, Partition) — dois argumentos.
            // (O README da SharpExt4 mostra só um, mas está errado.)
            using var fs = ExtFileSystem.Open(disk, disk.Partitions[0]);
            using var file = fs.OpenFile(fileInsideImage, FileMode.Open, FileAccess.Read);

            long length = file.Length;
            if (length > int.MaxValue)
                throw new NotSupportedException(
                    $"Ficheiro demasiado grande para este teste: {length} bytes (limite ~2GB).");

            int len = (int)length;
            var buf = new byte[len];
            int total = 0;
            while (total < len)
            {
                int n = file.Read(buf, total, len - total);
                if (n <= 0)
                    throw new EndOfStreamException(
                        $"Leitura incompleta: esperados {len} bytes, lidos {total}.");
                total += n;
            }
            return Encoding.UTF8.GetString(buf, 0, total);
        }

        /// <summary>
        /// Deteta uma imagem ext2/3/4 "crua" (sem tabela de partições): o número
        /// mágico 0xEF53 do superbloco está sempre no offset 1080 (0x438).
        /// </summary>
        private static bool IsBareExt4(string imagePath)
        {
            using var fs = new FileStream(imagePath, FileMode.Open, FileAccess.Read);
            if (fs.Length < 1082) return false;

            fs.Seek(1080, SeekOrigin.Begin);
            int lo = fs.ReadByte();
            int hi = fs.ReadByte();
            // 0xEF53 em little-endian => bytes 0x53, 0xEF.
            return lo == 0x53 && hi == 0xEF;
        }

        /// <summary>
        /// Cria um ficheiro de disco temporário composto por um MBR (com uma
        /// partição Linux a começar no offset de 1 MiB) seguido dos dados do
        /// ext4. Devolve o caminho do temporário, que deve depois ser apagado.
        /// </summary>
        private static string WrapBareFilesystem(string bareImagePath)
        {
            long fsSize = new FileInfo(bareImagePath).Length;
            long sectorCount = (fsSize + SectorSize - 1) / SectorSize;
            if (sectorCount > uint.MaxValue)
                throw new NotSupportedException(
                    "Imagem demasiado grande para envolver com MBR (>2TB).");

            string tempPath = Path.Combine(
                Path.GetTempPath(),
                $"sharpext4_probe_{Guid.NewGuid():N}.img");

            try
            {
                using (var outFs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write))
                {
                    var mbr = new byte[SectorSize];
                    const int entry = 446; // primeira entrada da tabela de partições
                    mbr[entry + 0] = 0x00;                                     // não-arrancável
                    mbr[entry + 4] = 0x83;                                     // tipo: Linux
                    WriteUInt32LE(mbr, entry + 8, (uint)PartitionStartSector); // LBA inicial
                    WriteUInt32LE(mbr, entry + 12, (uint)sectorCount);         // nº de setores
                    mbr[510] = 0x55;                                           // assinatura de MBR
                    mbr[511] = 0xAA;
                    outFs.Write(mbr, 0, SectorSize);

                    // Salta para o offset da partição (o intervalo fica a zeros) e
                    // copia lá para dentro os dados do ext4.
                    outFs.Seek(PartitionOffsetBytes, SeekOrigin.Begin);
                    using var inFs = new FileStream(bareImagePath, FileMode.Open, FileAccess.Read);
                    inFs.CopyTo(outFs);
                }

                return tempPath;
            }
            catch
            {
                // Se a criação/cópia falhar a meio, não deixa o temporário órfão.
                TryDelete(tempPath);
                throw;
            }
        }

        private static void WriteUInt32LE(byte[] buffer, int offset, uint value)
        {
            buffer[offset + 0] = (byte)(value & 0xFF);
            buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
            buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
            buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        private static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); }
            catch { /* limpeza best-effort */ }
        }
    }
}
