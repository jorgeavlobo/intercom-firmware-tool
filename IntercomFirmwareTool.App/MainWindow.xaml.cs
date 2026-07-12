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

        /// <summary>
        /// Button: run the MD5-crypt ($1$) self-test against the known-good
        /// vectors (verified against openssl). No file needed — pure computation.
        /// </summary>
        private async void BtnMd5Test_Click(object sender, RoutedEventArgs e)
        {
            var sb = new StringBuilder();
            sb.AppendLine("MD5-crypt ($1$) self-test — vectors verified against `openssl passwd -1`");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                (bool allPass, string report) = Md5Crypt.SelfTest();
                sb.Append(report);
                sb.AppendLine();
                sb.AppendLine(allPass
                    ? "ALL PASS ✅  the C# MD5-crypt matches openssl byte-for-byte"
                    : "SOME FAILED ❌  the implementation does NOT match — do not use it yet");
            });
        }

        // Fallback public key used only if the user cancels the key dialog, so
        // the test always runs. Replace with your real .pub for a usable image.
        private const string SampleKey =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISampleKeyForWritePhaseTestOnly00000000000 sample@intercom-firmware-tool";

        /// <summary>
        /// Button: pick a .fwz and an SSH public key, apply the fquinto
        /// SSH/root-enable edits on a temp copy, then reopen and validate every
        /// change (content, modes, owners, symlink). All on temp files.
        /// </summary>
        private async void BtnSshEnable_Click(object sender, RoutedEventArgs e)
        {
            var fwzDlg = new OpenFileDialog
            {
                Title = "Choose the .fwz file",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*"
            };
            if (fwzDlg.ShowDialog(this) != true)
                return;
            string fwzPath = fwzDlg.FileName;

            var keyDlg = new OpenFileDialog
            {
                Title = "Choose your SSH public key (.pub) — Cancel to use a built-in sample",
                Filter = "Public key (*.pub)|*.pub|All files (*.*)|*.*"
            };
            string publicKey, keySource;
            if (keyDlg.ShowDialog(this) == true)
            {
                publicKey = File.ReadAllText(keyDlg.FileName).Trim();
                keySource = keyDlg.FileName;
            }
            else
            {
                publicKey = SampleKey;
                keySource = "(built-in sample key)";
            }

            const string rootPassword = "pwned123"; // fquinto default; MD5-crypt path
            var opts = new EnableSshOptions(publicKey, rootPassword);

            var sb = new StringBuilder();
            AppendDiagnostics(sb);
            sb.AppendLine($".fwz file : {fwzPath}");
            sb.AppendLine($"Public key: {keySource}");
            sb.AppendLine($"Root pw   : {rootPassword}  (MD5-crypt $1$root$…)");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                SshEnableReport r = FwzProbe.TestSshEnableFromFwz(fwzPath, opts);
                sb.AppendLine($"Password that worked : {r.PasswordUsed}");
                sb.AppendLine($"Selected inner entry : {r.SelectedEntry}");
                sb.AppendLine();
                sb.AppendLine("Validation (reopened the modified ext4 and re-read every change):");
                foreach (var c in r.Checks)
                {
                    string detail = string.IsNullOrEmpty(c.Detail) ? "" : $"   [{c.Detail}]";
                    sb.AppendLine($"  {(c.Pass ? "PASS" : "FAIL")}  {c.Name}{detail}");
                }
                sb.AppendLine();
                sb.AppendLine(r.AllPass
                    ? "ALL PASS ✅  SSH-enable edits applied and persisted correctly"
                    : "SOME FAILED ❌  see the failing checks above");
            });
        }

        /// <summary>
        /// Button: full write pipeline — pick a .fwz and a public key, apply the
        /// SSH-enable edits, repack a NEW .fwz (chosen via Save As), and
        /// round-trip it (reopen and re-validate). The output is for validation,
        /// not flashing; the input .fwz is never modified.
        /// </summary>
        private async void BtnBuildFwz_Click(object sender, RoutedEventArgs e)
        {
            var fwzDlg = new OpenFileDialog
            {
                Title = "Choose the .fwz file",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*"
            };
            if (fwzDlg.ShowDialog(this) != true)
                return;
            string fwzPath = fwzDlg.FileName;

            var keyDlg = new OpenFileDialog
            {
                Title = "Choose your SSH public key (.pub) — Cancel to use a built-in sample",
                Filter = "Public key (*.pub)|*.pub|All files (*.*)|*.*"
            };
            string publicKey, keySource;
            if (keyDlg.ShowDialog(this) == true)
            {
                publicKey = File.ReadAllText(keyDlg.FileName).Trim();
                keySource = keyDlg.FileName;
            }
            else
            {
                publicKey = SampleKey;
                keySource = "(built-in sample key)";
            }

            var saveDlg = new SaveFileDialog
            {
                Title = "Save the modified .fwz as… (for validation, NOT for flashing)",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*",
                FileName = Path.GetFileNameWithoutExtension(fwzPath) + "_ssh.fwz",
                InitialDirectory = Path.GetDirectoryName(fwzPath)
            };
            if (saveDlg.ShowDialog(this) != true)
                return;
            string outputPath = saveDlg.FileName;

            const string rootPassword = "pwned123"; // fquinto default; MD5-crypt path
            var opts = new EnableSshOptions(publicKey, rootPassword);

            var sb = new StringBuilder();
            AppendDiagnostics(sb);
            sb.AppendLine($".fwz in   : {fwzPath}");
            sb.AppendLine($"Public key: {keySource}");
            sb.AppendLine($"Root pw   : {rootPassword}  (MD5-crypt $1$root$…)");
            sb.AppendLine($".fwz out  : {outputPath}");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                FwzBuildResult r = FwzProbe.BuildModifiedFwz(fwzPath, opts, outputPath);
                sb.AppendLine($"Password used        : {r.PasswordUsed}");
                sb.AppendLine($"Modified inner entry : {r.SelectedEntry}");
                sb.AppendLine($"Wrote                : {r.OutputPath}");
                sb.AppendLine();
                sb.AppendLine("Round-trip (reopened the OUTPUT .fwz through the full read chain):");
                foreach (var c in r.RoundTripChecks)
                {
                    string detail = string.IsNullOrEmpty(c.Detail) ? "" : $"   [{c.Detail}]";
                    sb.AppendLine($"  {(c.Pass ? "PASS" : "FAIL")}  {c.Name}{detail}");
                }
                sb.AppendLine();
                sb.AppendLine(r.RoundTripAllPass
                    ? "ALL PASS ✅  the modified .fwz repacked, decrypted, gunzipped and kept every edit"
                    : "SOME FAILED ❌  see the failing checks above");
            });
        }

        /// <summary>
        /// Button: read-only cross-validation. Pick an already-modified .fwz
        /// (e.g. one produced by fquinto) plus the public key and password it was
        /// built with, and run the same 18-point checklist against it. Nothing
        /// is modified.
        /// </summary>
        private async void BtnValidateFwz_Click(object sender, RoutedEventArgs e)
        {
            var fwzDlg = new OpenFileDialog
            {
                Title = "Choose an already-modified .fwz to validate (e.g. fquinto's output)",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*"
            };
            if (fwzDlg.ShowDialog(this) != true)
                return;
            string fwzPath = fwzDlg.FileName;

            var keyDlg = new OpenFileDialog
            {
                Title = "Choose the SSH public key (.pub) that .fwz was built with — Cancel for the sample",
                Filter = "Public key (*.pub)|*.pub|All files (*.*)|*.*"
            };
            string publicKey, keySource;
            if (keyDlg.ShowDialog(this) == true)
            {
                publicKey = File.ReadAllText(keyDlg.FileName).Trim();
                keySource = keyDlg.FileName;
            }
            else
            {
                publicKey = SampleKey;
                keySource = "(built-in sample key)";
            }

            const string rootPassword = "pwned123"; // must match how that .fwz was built
            var opts = new EnableSshOptions(publicKey, rootPassword);

            var sb = new StringBuilder();
            AppendDiagnostics(sb);
            sb.AppendLine($".fwz to check: {fwzPath}");
            sb.AppendLine($"Public key   : {keySource}");
            sb.AppendLine($"Root pw      : {rootPassword}  (the .fwz must have been built with this)");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                SshEnableReport r = FwzProbe.ValidateSshInFwz(fwzPath, opts);
                sb.AppendLine($"Password that worked : {r.PasswordUsed}");
                sb.AppendLine($"Selected inner entry : {r.SelectedEntry}");
                sb.AppendLine();
                sb.AppendLine("Checklist (read-only, the .fwz is not modified):");
                foreach (var c in r.Checks)
                {
                    string detail = string.IsNullOrEmpty(c.Detail) ? "" : $"   [{c.Detail}]";
                    sb.AppendLine($"  {(c.Pass ? "PASS" : "FAIL")}  {c.Name}{detail}");
                }
                sb.AppendLine();
                sb.AppendLine(r.AllPass
                    ? "ALL PASS ✅  this .fwz has all the expected SSH-enable edits"
                    : "SOME FAILED ❌  this .fwz is missing/differs on the failing checks");
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
            BtnMd5Test.IsEnabled = false;
            BtnSshEnable.IsEnabled = false;
            BtnBuildFwz.IsEnabled = false;
            BtnValidateFwz.IsEnabled = false;
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
                BtnMd5Test.IsEnabled = true;
                BtnSshEnable.IsEnabled = true;
                BtnBuildFwz.IsEnabled = true;
                BtnValidateFwz.IsEnabled = true;
            }

            TxtResult.Text = sb.ToString();
        }
    }
}
