using System;
using System.IO;
using System.Text;
using System.Windows;
using IntercomFirmwareTool.Core;
using Microsoft.Win32;

namespace IntercomFirmwareTool.App
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Botão: escolhe um .fwz e corre a cadeia completa (password, seleção,
        /// gunzip, ext4), mostrando o resultado ou o erro na caixa.
        /// </summary>
        private async void BtnReadFwz_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Escolhe o ficheiro .fwz",
                Filter = "Firmware Bticino (*.fwz)|*.fwz|Todos os ficheiros (*.*)|*.*"
            };
            if (dialog.ShowDialog(this) != true)
                return;

            string fwzPath = dialog.FileName;
            string fileInside = InternalPath();

            var sb = new StringBuilder();
            AppendDiagnostics(sb);
            sb.AppendLine($"Ficheiro .fwz : {fwzPath}");
            sb.AppendLine($"Ficheiro a ler: {fileInside}");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                FwzReadResult r = FwzProbe.ReadFileFromFwz(fwzPath, fileInside);
                sb.AppendLine($"Password que funcionou   : {r.PasswordUsed}");
                sb.AppendLine($"Ficheiro interno escolhido: {r.SelectedEntry}");
                sb.AppendLine();
                sb.AppendLine("SUCESSO:");
                sb.AppendLine(r.Content);
            });
        }

        // ---- Auxiliares partilhados ------------------------------------------

        /// <summary>Devolve o caminho interno da caixa de texto (ou /etc/hostname).</summary>
        private string InternalPath() =>
            string.IsNullOrWhiteSpace(TxtInternalPath.Text)
                ? "/etc/hostname"
                : TxtInternalPath.Text.Trim();

        /// <summary>
        /// Acrescenta o diagnóstico de runtime: se o processo é 64-bit e se as
        /// três DLLs da SharpExt4 estão na pasta de execução.
        /// </summary>
        private static void AppendDiagnostics(StringBuilder sb)
        {
            sb.AppendLine($"Processo 64-bit? {Environment.Is64BitProcess}  (tem de ser True)");
            sb.AppendLine($"Pasta de execução: {AppContext.BaseDirectory}");
            foreach (var dll in new[] { "SharpExt4.dll", "DiskPartitionInfo.dll", "Ijwhost.dll" })
            {
                string path = Path.Combine(AppContext.BaseDirectory, dll);
                sb.AppendLine($"  {(File.Exists(path) ? "OK   " : "FALTA")} {dll}");
            }
            sb.AppendLine();
        }

        /// <summary>
        /// Corre o trabalho em background (para a janela não bloquear), com os
        /// botões desativados, e mostra o resultado ou o erro completo na caixa.
        /// </summary>
        private async Task RunAndShow(StringBuilder sb, Action work)
        {
            BtnReadFwz.IsEnabled = false;
            TxtResult.Text = "A processar…";
            try
            {
                await Task.Run(work);
            }
            catch (Exception ex)
            {
                sb.AppendLine("ERRO:");
                sb.AppendLine(ex.ToString());
            }
            finally
            {
                BtnReadFwz.IsEnabled = true;
            }

            TxtResult.Text = sb.ToString();
        }
    }
}
