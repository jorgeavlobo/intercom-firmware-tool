using SharpExt4;
using System.Text;

namespace IntercomFirmwareTool.Core
{
    public static class Ext4Probe
    {
        /// <summary>
        /// Abre uma imagem ext4, entra na primeira partição e lê (só leitura)
        /// o conteúdo de um ficheiro lá de dentro, devolvendo-o como texto.
        /// </summary>
        /// <param name="imagePath">Caminho para a imagem ext4 no disco.</param>
        /// <param name="fileInsideImage">Caminho do ficheiro dentro da imagem, ex.: "/etc/hostname".</param>
        public static string ReadFile(string imagePath, string fileInsideImage)
        {
            // 'using' liberta disk, fs e file (todos IDisposable, via destrutor
            // C++/CLI) no fim do método — em sucesso ou em exceção — evitando
            // fugas de handles nativos em leituras repetidas.
            using var disk = ExtDisk.Open(imagePath);
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
                if (n <= 0) break;
                total += n;
            }
            return Encoding.UTF8.GetString(buf, 0, total);
        }
    }
}
