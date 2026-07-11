using System.IO.Compression;
using ICSharpCode.SharpZipLib.Zip;
// Desambigua: existe ZipFile em System.IO.Compression e na SharpZipLib.
// Aqui "ZipFile" é sempre o da SharpZipLib (o que suporta ZipCrypto).
using ZipFile = ICSharpCode.SharpZipLib.Zip.ZipFile;

namespace IntercomFirmwareTool.Core
{
    /// <summary>Resultado da leitura da cadeia completa a partir de um .fwz.</summary>
    public sealed record FwzReadResult(
        string PasswordUsed,
        string SelectedEntry,
        string Content);

    /// <summary>
    /// Replica (só leitura) o fluxo do instalador do fquinto até à imagem ext4:
    /// abre o .fwz (ZIP com ZipCrypto), tenta as passwords conhecidas, escolhe o
    /// ficheiro correto (contém "gz" e não "recovery"), faz gunzip e lê um
    /// ficheiro de dentro da imagem ext4 resultante.
    /// </summary>
    public static class FwzProbe
    {
        // Passwords do .fwz por modelo (são os próprios nomes de modelo no fquinto).
        private static readonly string[] Passwords = { "C300X", "C100X", "SMARTDES" };

        public static FwzReadResult ReadFileFromFwz(string fwzPath, string fileInsideImage)
        {
            using var zip = new ZipFile(fwzPath);

            // 1) Seleciona a entrada: nome contém "gz" e não contém "recovery"
            //    (regra do fquinto). Dá btweb_only.ext4.gz.
            ZipEntry? selected = null;
            foreach (ZipEntry entry in zip)
            {
                if (!entry.IsFile) continue;
                string name = entry.Name;
                // Regra do fquinto (nome com "gz" e sem "recovery"), mas a exigir
                // que termine mesmo em ".gz" para não apanhar sidecars de
                // assinatura tipo "btweb_only.ext4.gz.sig".
                if (name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) &&
                    !name.Contains("recovery", StringComparison.OrdinalIgnoreCase))
                {
                    selected = entry;
                    break;
                }
            }
            if (selected is null)
                throw new InvalidOperationException(
                    "Nenhum ficheiro 'gz' (não-recovery) encontrado dentro do .fwz.");

            // 2) Descobre qual das passwords conhecidas abre a entrada.
            string? goodPassword = null;
            foreach (string pw in Passwords)
            {
                if (PasswordOpensEntry(zip, selected, pw))
                {
                    goodPassword = pw;
                    break;
                }
            }
            if (goodPassword is null)
                throw new InvalidOperationException(
                    "Nenhuma das passwords conhecidas (C300X, C100X, SMARTDES) abriu o .fwz.");

            zip.Password = goodPassword;

            // 3) Descodifica (ZipCrypto) e descomprime (gzip) num só fluxo,
            //    direto para o temporário .ext4 — sem escrever o .gz intermédio
            //    em disco (menos I/O e menos exposição em %TEMP%). Depois lê o
            //    ficheiro pedido reutilizando o leitor de ext4 (que trata
            //    sozinho do embrulho MBR das imagens cruas).
            string extTemp = NewTempPath(".ext4");
            try
            {
                using (var zin = zip.GetInputStream(selected))
                using (var gunzip = new GZipStream(zin, CompressionMode.Decompress))
                using (var extOut = new FileStream(extTemp, FileMode.CreateNew, FileAccess.Write))
                    gunzip.CopyTo(extOut);

                string content = Ext4Probe.ReadFile(extTemp, fileInsideImage);

                return new FwzReadResult(goodPassword, selected.Name, content);
            }
            finally
            {
                TryDelete(extTemp);
            }
        }

        /// <summary>
        /// Verifica se uma password descodifica a entrada: como cada entrada é um
        /// .gz, o conteúdo descodificado tem de começar pelos bytes mágicos do
        /// gzip (0x1F 0x8B). Isto evita falsos positivos do ZipCrypto.
        /// </summary>
        private static bool PasswordOpensEntry(ZipFile zip, ZipEntry entry, string password)
        {
            zip.Password = password;
            try
            {
                using var s = zip.GetInputStream(entry);
                int b0 = s.ReadByte();
                int b1 = s.ReadByte();
                return b0 == 0x1F && b1 == 0x8B;
            }
            catch (ZipException)
            {
                return false; // password errada
            }
        }

        private static string NewTempPath(string extension) =>
            Path.Combine(Path.GetTempPath(), $"fwzprobe_{Guid.NewGuid():N}{extension}");

        private static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); }
            catch { /* limpeza best-effort */ }
        }
    }
}
