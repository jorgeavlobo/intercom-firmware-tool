using System;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using IntercomFirmwareTool.Core;
using Microsoft.Win32;

namespace IntercomFirmwareTool.App
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml.
    ///
    /// One product flow: choose the original .fwz, an SSH public key and an
    /// output path, then Build a modified .fwz that enables SSH/root login
    /// (the fquinto edits), verified by a full read-back round-trip. Two
    /// secondary actions verify an existing .fwz and run the MD5-crypt self-test.
    /// The input .fwz is never modified.
    /// </summary>
    public partial class MainWindow : Window
    {
        private string? _fwzPath;
        private string? _keyPath;
        private string? _outputPath;

        public MainWindow()
        {
            InitializeComponent();
            ShowStartupDiagnostics();
            TryPrefillDefaultKey();

            // Sensible default (fquinto's), pre-filled in both masked fields so
            // they already match.
            PwdPassword.Password = "pwned123";
            PwdConfirm.Password = "pwned123";
            UpdatePasswordHint();
        }

        // ---- Input selection -------------------------------------------------

        private void BtnBrowseFwz_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Title = "Choose the original firmware (.fwz)",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*"
            };
            if (dlg.ShowDialog(this) != true) return;

            _fwzPath = dlg.FileName;
            SetPathText(TxtFwzPath, _fwzPath);

            // Suggest an output next to the input, if the user hasn't set one.
            if (_outputPath is null)
            {
                string suggested = Path.Combine(
                    Path.GetDirectoryName(_fwzPath) ?? "",
                    Path.GetFileNameWithoutExtension(_fwzPath) + "_ssh.fwz");
                _outputPath = suggested;
                SetPathText(TxtOutputPath, _outputPath);
            }
            UpdateBuildEnabled();
        }

        private void BtnBrowseKey_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Title = "Choose your SSH public key (.pub)",
                Filter = "Public key (*.pub)|*.pub|All files (*.*)|*.*",
                InitialDirectory = DefaultSshDir()
            };
            if (dlg.ShowDialog(this) != true) return;

            _keyPath = dlg.FileName;
            SetPathText(TxtKeyPath, _keyPath);
            UpdateBuildEnabled();
        }

        private void BtnBrowseOutput_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Title = "Save the modified firmware as…",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*",
                FileName = _fwzPath != null
                    ? Path.GetFileNameWithoutExtension(_fwzPath) + "_ssh.fwz"
                    : "modified.fwz",
                InitialDirectory = (_fwzPath != null ? Path.GetDirectoryName(_fwzPath) : null) ?? ""
            };
            if (dlg.ShowDialog(this) != true) return;

            _outputPath = dlg.FileName;
            SetPathText(TxtOutputPath, _outputPath);
            UpdateBuildEnabled();
        }

        private void ChkKeyOnly_Toggled(object sender, RoutedEventArgs e)
        {
            // Key-only means no password login; grey the password fields out.
            bool usePassword = ChkKeyOnly.IsChecked != true;
            PwdPassword.IsEnabled = usePassword;
            TxtPassword.IsEnabled = usePassword;
            PwdConfirm.IsEnabled = usePassword;
            TxtConfirm.IsEnabled = usePassword;
            BtnShowPwd.IsEnabled = usePassword;
            UpdatePasswordHint();
        }

        /// <summary>Reveals or masks BOTH password fields (kept in sync at toggle time).</summary>
        private void BtnShowPwd_Toggled(object sender, RoutedEventArgs e)
        {
            bool reveal = BtnShowPwd.IsChecked == true;
            if (reveal)
            {
                TxtPassword.Text = PwdPassword.Password;
                TxtConfirm.Text = PwdConfirm.Password;
            }
            else
            {
                PwdPassword.Password = TxtPassword.Text;
                PwdConfirm.Password = TxtConfirm.Text;
            }
            PwdPassword.Visibility = reveal ? Visibility.Collapsed : Visibility.Visible;
            PwdConfirm.Visibility = reveal ? Visibility.Collapsed : Visibility.Visible;
            TxtPassword.Visibility = reveal ? Visibility.Visible : Visibility.Collapsed;
            TxtConfirm.Visibility = reveal ? Visibility.Visible : Visibility.Collapsed;
            BtnShowPwd.Content = reveal ? "Hide" : "Show";
        }

        /// <summary>Fires from either the masked or the revealed field; updates the match hint.</summary>
        private void Password_Changed(object sender, RoutedEventArgs e) => UpdatePasswordHint();

        /// <summary>The current password value, from whichever field is visible.</summary>
        private string CurrentPassword() =>
            BtnShowPwd.IsChecked == true ? TxtPassword.Text : PwdPassword.Password;

        /// <summary>The current confirmation value, from whichever field is visible.</summary>
        private string CurrentConfirm() =>
            BtnShowPwd.IsChecked == true ? TxtConfirm.Text : PwdConfirm.Password;

        /// <summary>Shows a small match/mismatch hint next to the confirm field.</summary>
        private void UpdatePasswordHint()
        {
            // TxtPwdHint may not exist yet during very early initialization.
            if (TxtPwdHint is null) return;

            if (ChkKeyOnly.IsChecked == true)
            {
                TxtPwdHint.Text = "(password login disabled)";
                TxtPwdHint.Foreground = Brushes.Gray;
                return;
            }
            if (CurrentPassword().Length == 0 && CurrentConfirm().Length == 0)
            {
                TxtPwdHint.Text = "";
                return;
            }
            bool match = CurrentPassword() == CurrentConfirm();
            TxtPwdHint.Text = match ? "✓ match" : "✗ do not match";
            TxtPwdHint.Foreground = match ? Brushes.Green : Brushes.Firebrick;
        }

        /// <summary>The user's ~/.ssh folder if it exists, else the profile folder.</summary>
        private static string DefaultSshDir()
        {
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string ssh = Path.Combine(profile, ".ssh");
            return Directory.Exists(ssh) ? ssh : profile;
        }

        private void UpdateBuildEnabled()
        {
            BtnBuild.IsEnabled =
                _fwzPath != null && _keyPath != null && _outputPath != null;
        }

        // ---- Primary action: Build ------------------------------------------

        private async void BtnBuild_Click(object sender, RoutedEventArgs e)
        {
            if (_fwzPath is null || _keyPath is null || _outputPath is null) return;

            string publicKey;
            try
            {
                publicKey = File.ReadAllText(_keyPath).Trim();
            }
            catch (Exception ex)
            {
                TxtResult.Text = $"Could not read the public key:\n{ex.Message}";
                return;
            }
            if (publicKey.Length == 0)
            {
                TxtResult.Text = "The selected public key file is empty.";
                return;
            }

            bool keyOnly = ChkKeyOnly.IsChecked == true;
            string password = CurrentPassword();

            // Passwords must match unless key-only login is selected.
            if (!keyOnly && password != CurrentConfirm())
            {
                MessageBox.Show(this,
                    "The password and its confirmation do not match.",
                    "Password mismatch", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Confirm before overwriting an existing output file (the path may
            // have been auto-suggested, bypassing the Save dialog's own prompt).
            if (File.Exists(_outputPath))
            {
                var answer = MessageBox.Show(this,
                    $"The file already exists:\n\n{_outputPath}\n\nOverwrite it?",
                    "File exists", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (answer != MessageBoxResult.Yes) return;
            }

            var opts = new EnableSshOptions(publicKey, password, keyOnly);

            string fwz = _fwzPath, output = _outputPath, keyPath = _keyPath;

            var sb = new StringBuilder();
            sb.AppendLine("Building modified firmware…");
            sb.AppendLine($"  Input      : {fwz}");
            sb.AppendLine($"  Public key : {keyPath}");
            sb.AppendLine(keyOnly
                ? "  Login      : key-only (password disabled)"
                : $"  Root pw    : {password}  (MD5-crypt $1$root$…)");
            sb.AppendLine($"  Output     : {output}");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                FwzBuildResult r = FwzProbe.BuildModifiedFwz(fwz, opts, output);
                sb.AppendLine($"Detected model : {r.PasswordUsed}");
                sb.AppendLine($"Modified entry : {r.SelectedEntry}");
                sb.AppendLine();
                sb.AppendLine("Verification (reopened the OUTPUT .fwz and re-read every change):");
                AppendChecks(sb, r.RoundTripChecks);
                sb.AppendLine();
                if (r.RoundTripAllPass)
                {
                    sb.AppendLine("✅ SUCCESS — the modified firmware was built and verified.");
                    sb.AppendLine($"   Written to: {r.OutputPath}");
                    sb.AppendLine();
                    sb.AppendLine("Before flashing: have USB/SAM-BA recovery ready. Your original");
                    sb.AppendLine(".fwz was not modified.");
                }
                else
                {
                    sb.AppendLine("❌ Some checks FAILED — do NOT flash this output. See above.");
                }
            });
        }

        // ---- Secondary: Verify an existing .fwz -----------------------------

        private async void BtnVerify_Click(object sender, RoutedEventArgs e)
        {
            var fwzDlg = new OpenFileDialog
            {
                Title = "Choose a modified .fwz to verify (e.g. this tool's or fquinto's output)",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*"
            };
            if (fwzDlg.ShowDialog(this) != true) return;
            string fwzPath = fwzDlg.FileName;

            // Reuse the key from the form if set; otherwise ask for it.
            string? keyPath = _keyPath;
            if (keyPath is null)
            {
                var keyDlg = new OpenFileDialog
                {
                    Title = "Choose the SSH public key that .fwz was built with",
                    Filter = "Public key (*.pub)|*.pub|All files (*.*)|*.*",
                    InitialDirectory = DefaultSshDir()
                };
                if (keyDlg.ShowDialog(this) != true) return;
                keyPath = keyDlg.FileName;
            }

            string publicKey;
            try
            {
                publicKey = File.ReadAllText(keyPath).Trim();
            }
            catch (Exception ex)
            {
                TxtResult.Text = $"Could not read the public key:\n{ex.Message}";
                return;
            }

            bool keyOnly = ChkKeyOnly.IsChecked == true;
            string password = CurrentPassword();
            var opts = new EnableSshOptions(publicKey, password, keyOnly);

            var sb = new StringBuilder();
            sb.AppendLine("Verifying an existing firmware (read-only, the .fwz is not modified)…");
            sb.AppendLine($"  .fwz       : {fwzPath}");
            sb.AppendLine($"  Public key : {keyPath}");
            sb.AppendLine(keyOnly
                ? "  Login      : key-only (password disabled)"
                : $"  Root pw    : {password}  (must match how that .fwz was built)");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                SshEnableReport r = FwzProbe.ValidateSshInFwz(fwzPath, opts);
                sb.AppendLine($"Detected model : {r.PasswordUsed}");
                sb.AppendLine($"Inner entry    : {r.SelectedEntry}");
                sb.AppendLine();
                sb.AppendLine("Checklist:");
                AppendChecks(sb, r.Checks);
                sb.AppendLine();
                sb.AppendLine(r.AllPass
                    ? "✅ ALL PASS — this .fwz has all the expected SSH-enable edits."
                    : "❌ SOME FAILED — this .fwz is missing or differs on the checks above.");
            });
        }

        // ---- Secondary: MD5-crypt self-test ---------------------------------

        private async void BtnSelfTest_Click(object sender, RoutedEventArgs e)
        {
            var sb = new StringBuilder();
            sb.AppendLine("MD5-crypt ($1$) self-test — vectors verified against `openssl passwd -1`.");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                (bool allPass, string report) = Md5Crypt.SelfTest();
                sb.Append(report);
                sb.AppendLine();
                sb.AppendLine(allPass
                    ? "✅ ALL PASS — the C# MD5-crypt matches openssl byte-for-byte."
                    : "❌ SOME FAILED — the implementation does not match; do not use it.");
            });
        }

        // ---- Shared helpers --------------------------------------------------

        private static void AppendChecks(StringBuilder sb, System.Collections.Generic.IReadOnlyList<Ext4Check> checks)
        {
            foreach (var c in checks)
            {
                string detail = string.IsNullOrEmpty(c.Detail) ? "" : $"   [{c.Detail}]";
                sb.AppendLine($"  {(c.Pass ? "PASS" : "FAIL")}  {c.Name}{detail}");
            }
        }

        /// <summary>Puts a real path in the box in normal (non-placeholder) colour.</summary>
        private static void SetPathText(TextBox box, string path)
        {
            box.Text = path;
            box.Foreground = SystemColors.WindowTextBrush;
        }

        /// <summary>Pre-fills the key box from the user's default ~/.ssh key, if present.</summary>
        private void TryPrefillDefaultKey()
        {
            try
            {
                string sshDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
                foreach (var name in new[] { "id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub" })
                {
                    string candidate = Path.Combine(sshDir, name);
                    if (File.Exists(candidate))
                    {
                        _keyPath = candidate;
                        SetPathText(TxtKeyPath, candidate);
                        break;
                    }
                }
            }
            catch { /* best-effort convenience only */ }
        }

        /// <summary>
        /// Shows, once at startup, whether the process is 64-bit and whether the
        /// three SharpExt4 DLLs are present. If anything is wrong the line turns
        /// red — nothing will work otherwise.
        /// </summary>
        private void ShowStartupDiagnostics()
        {
            bool is64 = Environment.Is64BitProcess;
            var missing = new System.Collections.Generic.List<string>();
            foreach (var dll in new[] { "SharpExt4.dll", "DiskPartitionInfo.dll", "Ijwhost.dll" })
            {
                if (!File.Exists(Path.Combine(AppContext.BaseDirectory, dll)))
                    missing.Add(dll);
            }

            bool ok = is64 && missing.Count == 0;
            TxtDiag.Foreground = ok ? Brushes.Gray : Brushes.Firebrick;
            TxtDiag.Text = ok
                ? $"Ready · 64-bit · SharpExt4 DLLs present · {AppContext.BaseDirectory}"
                : $"PROBLEM · 64-bit: {is64} · missing DLLs: " +
                  (missing.Count == 0 ? "none" : string.Join(", ", missing)) +
                  $" · {AppContext.BaseDirectory}";
        }

        /// <summary>
        /// Runs the work off the UI thread (so the window stays responsive), with
        /// every button disabled, and shows the result — or the full error — in
        /// the box.
        /// </summary>
        private async Task RunAndShow(StringBuilder sb, Action work)
        {
            SetButtonsEnabled(false);
            TxtResult.Text = sb.ToString() + "\nProcessing…";
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
                SetButtonsEnabled(true);
            }
            TxtResult.Text = sb.ToString();
        }

        private void SetButtonsEnabled(bool enabled)
        {
            BtnBrowseFwz.IsEnabled = enabled;
            BtnBrowseKey.IsEnabled = enabled;
            BtnBrowseOutput.IsEnabled = enabled;
            BtnVerify.IsEnabled = enabled;
            BtnSelfTest.IsEnabled = enabled;
            // Build only re-enables if the three inputs are set.
            BtnBuild.IsEnabled = enabled
                && _fwzPath != null && _keyPath != null && _outputPath != null;
        }
    }
}
