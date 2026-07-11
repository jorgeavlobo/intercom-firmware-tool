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

        // ---- Botão: cadeia completa a partir de um .fwz ----------------------
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

        private string InternalPath() =>
            string.IsNullOrWhiteSpace(TxtInternalPath.Text)
                ? "/etc/hostname"
                : TxtInternalPath.Text.Trim();

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
