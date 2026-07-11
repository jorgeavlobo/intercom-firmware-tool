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

        private void BtnRead_Click(object sender, RoutedEventArgs e)
        {
            // 1) Deixa o utilizador escolher a imagem ext4 no disco.
            var dialog = new OpenFileDialog
            {
                Title = "Escolhe a imagem ext4",
                Filter = "Imagens de disco (*.img;*.bin;*.ext4)|*.img;*.bin;*.ext4|Todos os ficheiros (*.*)|*.*"
            };

            if (dialog.ShowDialog(this) != true)
                return; // utilizador cancelou

            string imagePath = dialog.FileName;
            string fileInside = string.IsNullOrWhiteSpace(TxtInternalPath.Text)
                ? "/etc/hostname"
                : TxtInternalPath.Text.Trim();

            var sb = new StringBuilder();

            // 2) Diagnóstico: prova que estamos em x64 e que as DLLs estão no output.
            sb.AppendLine($"Processo 64-bit? {Environment.Is64BitProcess}  (tem de ser True)");
            sb.AppendLine($"Pasta de execução: {AppContext.BaseDirectory}");
            foreach (var dll in new[] { "SharpExt4.dll", "DiskPartitionInfo.dll", "Ijwhost.dll" })
            {
                string path = Path.Combine(AppContext.BaseDirectory, dll);
                sb.AppendLine($"  {(File.Exists(path) ? "OK   " : "FALTA")} {dll}");
            }
            sb.AppendLine();
            sb.AppendLine($"Imagem        : {imagePath}");
            sb.AppendLine($"Ficheiro a ler: {fileInside}");
            sb.AppendLine();

            // 3) A leitura em si, protegida por try/catch.
            try
            {
                string content = Ext4Probe.ReadFile(imagePath, fileInside);
                sb.AppendLine("SUCESSO:");
                sb.AppendLine(content);
            }
            catch (Exception ex)
            {
                sb.AppendLine("ERRO:");
                sb.AppendLine(ex.ToString());
            }

            TxtResult.Text = sb.ToString();
        }
    }
}
