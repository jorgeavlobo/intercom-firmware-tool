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
        /// Button: pick a .fwz and run the full chain (password, selection,
        /// gunzip, ext4), showing the result or the error in the box.
        /// </summary>
        private async void BtnReadFwz_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Choose the .fwz file",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*"
            };
            if (dialog.ShowDialog(this) != true)
                return;

            string fwzPath = dialog.FileName;
            string fileInside = InternalPath();

            var sb = new StringBuilder();
            AppendDiagnostics(sb);
            sb.AppendLine($".fwz file    : {fwzPath}");
            sb.AppendLine($"File to read : {fileInside}");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                FwzReadResult r = FwzProbe.ReadFileFromFwz(fwzPath, fileInside);
                sb.AppendLine($"Password that worked : {r.PasswordUsed}");
                sb.AppendLine($"Selected inner entry : {r.SelectedEntry}");
                sb.AppendLine();
                sb.AppendLine("SUCCESS:");
                sb.AppendLine(r.Content);
            });
        }

        /// <summary>
        /// Button: pick a .fwz and run the WRITE proof of concept — mount the
        /// ext4 read-write, report CanWrite, append a unique test line and
        /// confirm it survives a raw round-trip. All on temp files.
        /// </summary>
        private async void BtnWriteTest_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Choose the .fwz file",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*"
            };
            if (dialog.ShowDialog(this) != true)
                return;

            string fwzPath = dialog.FileName;
            string targetFile = InternalPath();
            string testLine = "# sharpext4 write test " + Guid.NewGuid().ToString("N");

            var sb = new StringBuilder();
            AppendDiagnostics(sb);
            sb.AppendLine($".fwz file    : {fwzPath}");
            sb.AppendLine($"Target file  : {targetFile}");
            sb.AppendLine($"Test line    : {testLine}");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                FwzWriteResult r = FwzProbe.TestWriteFromFwz(fwzPath, targetFile, testLine);
                sb.AppendLine($"Password that worked : {r.PasswordUsed}");
                sb.AppendLine($"Selected inner entry : {r.SelectedEntry}");
                sb.AppendLine();
                sb.AppendLine($"CanWrite: {r.CanWrite}");
                sb.AppendLine();

                if (!r.CanWrite)
                {
                    sb.AppendLine("The filesystem mounted READ-ONLY — no write attempted.");
                    sb.AppendLine();
                    sb.AppendLine("----- FILE CONTENT -----");
                    sb.AppendLine(r.Before);
                    return;
                }

                sb.AppendLine("----- BEFORE -----");
                sb.AppendLine(r.Before);
                sb.AppendLine("----- AFTER (re-read from a raw ext4 round-trip) -----");
                sb.AppendLine(r.After);
                sb.AppendLine("------------------");
                sb.AppendLine();
                sb.AppendLine(r.Persisted
                    ? "PERSISTED: True  ✅  the write survived flush + raw round-trip"
                    : "PERSISTED: False ❌  the test line was NOT found after re-read");
            });
        }

        // ---- Shared helpers --------------------------------------------------

        /// <summary>Returns the internal path from the text box (or /etc/hostname).</summary>
        private string InternalPath() =>
            string.IsNullOrWhiteSpace(TxtInternalPath.Text)
                ? "/etc/hostname"
                : TxtInternalPath.Text.Trim();

        /// <summary>
        /// Appends the runtime diagnostics: whether the process is 64-bit and
        /// whether the three SharpExt4 DLLs are in the execution folder.
        /// </summary>
        private static void AppendDiagnostics(StringBuilder sb)
        {
            sb.AppendLine($"64-bit process? {Environment.Is64BitProcess}  (must be True)");
            sb.AppendLine($"Execution folder: {AppContext.BaseDirectory}");
            foreach (var dll in new[] { "SharpExt4.dll", "DiskPartitionInfo.dll", "Ijwhost.dll" })
            {
                string path = Path.Combine(AppContext.BaseDirectory, dll);
                sb.AppendLine($"  {(File.Exists(path) ? "OK     " : "MISSING")} {dll}");
            }
            sb.AppendLine();
        }

        /// <summary>
        /// Runs the work in the background (so the window doesn't freeze), with
        /// the button disabled, and shows the result or the full error in the box.
        /// </summary>
        private async Task RunAndShow(StringBuilder sb, Action work)
        {
            BtnReadFwz.IsEnabled = false;
            BtnWriteTest.IsEnabled = false;
            TxtResult.Text = "Processing…";
            try
            {
                await Task.Run(work);
            }
            catch (Exception ex)
            {
                sb.AppendLine("ERROR:");
                sb.AppendLine(ex.ToString());
            }
            finally
            {
                BtnReadFwz.IsEnabled = true;
                BtnWriteTest.IsEnabled = true;
            }

            TxtResult.Text = sb.ToString();
        }
    }
}
