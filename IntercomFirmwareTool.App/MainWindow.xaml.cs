using System;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
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

        // Masked password fields with reveal-last-char behaviour (see
        // MaskedPasswordField); the real values live in these, not in the TextBoxes.
        private readonly MaskedPasswordField _pw;
        private readonly MaskedPasswordField _confirm;

        public MainWindow()
        {
            InitializeComponent();
            ShowStartupDiagnostics();

            // The key is chosen explicitly (Choose existing… / Generate new…), so
            // nothing is pre-selected — this avoids silently picking the wrong key.

            _pw = new MaskedPasswordField(TxtPassword);
            _confirm = new MaskedPasswordField(TxtConfirm);
            _pw.Changed += UpdatePasswordHint;
            _confirm.Changed += UpdatePasswordHint;
            WirePeekButton();

            // Sensible default password (fquinto's), pre-filled in both fields
            // so they already match (shown masked).
            _pw.Value = "pwned123";
            _confirm.Value = "pwned123";
            UpdatePasswordHint();
        }

        // ---- Password reveal button (press-and-hold) -------------------------

        /// <summary>
        /// Wires the "Show" button to reveal the passwords only WHILE it is held
        /// down (mouse or keyboard), re-masking on release — the peek pattern
        /// common in modern forms.
        /// </summary>
        private void WirePeekButton()
        {
            BtnPeek.PreviewMouseLeftButtonDown += (_, _) => SetPeek(true);
            BtnPeek.PreviewMouseLeftButtonUp += (_, _) => SetPeek(false);
            BtnPeek.LostMouseCapture += (_, _) => SetPeek(false);
            BtnPeek.MouseLeave += (_, _) => SetPeek(false);
            BtnPeek.PreviewKeyDown += (_, e) =>
            {
                if (e.Key == Key.Space || e.Key == Key.Enter) { SetPeek(true); e.Handled = true; }
            };
            BtnPeek.PreviewKeyUp += (_, e) =>
            {
                if (e.Key == Key.Space || e.Key == Key.Enter) { SetPeek(false); e.Handled = true; }
            };
        }

        private void SetPeek(bool on)
        {
            if (ChkKeyOnly.IsChecked == true) on = false; // nothing to reveal in key-only
            _pw.Peek = on;
            _confirm.Peek = on;
            BtnPeek.Content = on ? "Hide" : "Show";
        }

        // ---- Input selection -------------------------------------------------

        private async void BtnBrowseFwz_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Title = "Choose the original firmware (.fwz)",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*"
            };
            if (dlg.ShowDialog(this) != true) return;
            string chosen = dlg.FileName;

            // Integrity gate: only a byte-for-byte known-good original may be
            // modified. Verify by size + SHA-256 (may hash ~100 MB, so do it off
            // the UI thread) before accepting the file.
            SetButtonsEnabled(false);
            TxtResult.Text = $"Verifying firmware integrity (size + SHA-256)…\n{chosen}";
            FirmwareCheckResult check;
            try { check = await Task.Run(() => FirmwareRegistry.Verify(chosen)); }
            finally { SetButtonsEnabled(true); }

            if (!check.Ok)
            {
                // Reject and DE-SELECT: no build is allowed on an unrecognized or
                // unmodifiable file.
                _fwzPath = null;
                _outputPath = null;
                TxtFwzPath.Text = "(no valid firmware selected)";
                TxtFwzPath.Foreground = Brushes.Firebrick;
                TxtOutputPath.Text = "(where to write the modified .fwz)";
                TxtOutputPath.Foreground = Brushes.Gray;
                LblOutput.IsEnabled = false;
                TxtOutputPath.IsEnabled = false;
                BtnBrowseOutput.IsEnabled = false;
                UpdateBuildEnabled();

                TxtResult.Text =
                    "❌ This file was NOT accepted — selection cleared, Build stays disabled.\n\n" +
                    check.Message + "\n\n" +
                    "Only known-good original firmware can be modified, so a corrupt or wrong\n" +
                    "download can't be turned into a broken image. The file's NAME does not matter —\n" +
                    "its content (size + SHA-256) must match a known original.";
                MessageBox.Show(this,
                    "This file is not an accepted original firmware.\n\n" + check.Message +
                    "\n\nThe selection was cleared.",
                    "Firmware not accepted", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Accepted: record the path and enable the output row.
            _fwzPath = chosen;
            SetPathText(TxtFwzPath, chosen);
            LblOutput.IsEnabled = true;
            TxtOutputPath.IsEnabled = true;
            BtnBrowseOutput.IsEnabled = true;
            // Always re-suggest the output next to the NEW input, so switching
            // firmware can't leave the output pointing at the previous file's
            // name/location (the user can still Browse to change it).
            _outputPath = Path.Combine(
                Path.GetDirectoryName(chosen) ?? "",
                Path.GetFileNameWithoutExtension(chosen) + "_ssh.fwz");
            SetPathText(TxtOutputPath, _outputPath);
            UpdateBuildEnabled();

            TxtResult.Text =
                "✅ " + check.Message + "\n\n" +
                check.Match!.Describe() + "\n\n" +
                "You can now choose a key and Build.";
        }

        private void BtnChooseKey_Click(object sender, RoutedEventArgs e)
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

        /// <summary>
        /// Generates a fresh RSA key pair: asks where to save the PRIVATE key
        /// (defaults to the .ssh folder), writes it plus the OpenSSH ".pub", and
        /// selects the new public key for the build. The private key stays with
        /// the user — it is what they will log in with.
        /// </summary>
        private async void BtnGenKey_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Title = "Save the NEW private key as… (the public .pub is written beside it)",
                Filter = "SSH private key (all files)|*.*",
                InitialDirectory = DefaultSshDir(),
                FileName = "intercom_id_rsa",
                OverwritePrompt = true
            };
            if (dlg.ShowDialog(this) != true) return;
            string privatePath = dlg.FileName;

            // The Save dialog only prompted about the private-key path; confirm
            // the sibling .pub too, since generating overwrites it.
            string pubDest = privatePath + ".pub";
            if (File.Exists(pubDest))
            {
                var ans = MessageBox.Show(this,
                    $"A public key already exists and will be overwritten:\n\n{pubDest}\n\nContinue?",
                    "Public key exists", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (ans != MessageBoxResult.Yes) return;
            }

            string comment = $"{Environment.UserName}@{Environment.MachineName}";

            SetButtonsEnabled(false);
            TxtResult.Text = "Generating a new 4096-bit RSA key pair…";
            string? pubPath = null;
            string? error = null;
            try
            {
                pubPath = await Task.Run(() => SshKeyGen.Generate(privatePath, comment));
            }
            catch (Exception ex)
            {
                error = ex.ToString();
            }
            finally
            {
                SetButtonsEnabled(true);
            }

            if (error != null || pubPath is null)
            {
                TxtResult.Text = "Could not generate the key:\n" + error;
                return;
            }

            _keyPath = pubPath;
            SetPathText(TxtKeyPath, pubPath);
            UpdateBuildEnabled();

            TxtResult.Text =
                "New SSH key pair created.\n\n" +
                $"  Private key : {privatePath}\n" +
                $"  Public key  : {pubPath}\n\n" +
                "The public key is now selected for the build. KEEP THE PRIVATE KEY SAFE —\n" +
                "it is what you will use to log in (ssh -i \"" + privatePath + "\" root@<device>).\n" +
                "It has no passphrase; add one later with:  ssh-keygen -p -f \"" + privatePath + "\"\n\n" +
                "If Windows OpenSSH later reports the key is too open (\"UNPROTECTED PRIVATE\n" +
                "KEY FILE\"), restrict it to your account with:\n" +
                "  icacls \"" + privatePath + "\" /inheritance:r /grant:r \"%USERNAME%:R\"";

            MessageBox.Show(this,
                $"Key pair created.\n\nPrivate key:\n{privatePath}\n\nPublic key:\n{pubPath}\n\n" +
                "Keep the private key safe — it has no passphrase.",
                "New SSH key", MessageBoxButton.OK, MessageBoxImage.Information);
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
            // Key-only means no password login; grey the password fields out and
            // stop any active reveal.
            bool usePassword = ChkKeyOnly.IsChecked != true;
            if (!usePassword) SetPeek(false);

            TxtPassword.IsEnabled = usePassword;
            TxtConfirm.IsEnabled = usePassword;
            BtnPeek.IsEnabled = usePassword;
            UpdatePasswordHint();
        }

        /// <summary>The current password value (real text, held by the masked field).</summary>
        private string CurrentPassword() => _pw.Value;

        /// <summary>The current confirmation value (real text, held by the masked field).</summary>
        private string CurrentConfirm() => _confirm.Value;

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
            if (!SshKeyGen.IsLikelyPublicKey(publicKey))
            {
                MessageBox.Show(this,
                    "The selected file does not look like an OpenSSH public key\n" +
                    "(expected a line like \"ssh-rsa AAAA… comment\" or \"ssh-ed25519 AAAA…\").\n\n" +
                    "Pick your .pub file, or use \"Generate new…\".",
                    "Not a public key", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            bool keyOnly = ChkKeyOnly.IsChecked == true;
            string password = CurrentPassword();

            // With password login, refuse an empty password — it would produce a
            // valid /etc/shadow hash for a BLANK password, letting the added
            // accounts log in with no password. Require one, or tick key-only.
            if (!keyOnly && password.Length == 0)
            {
                MessageBox.Show(this,
                    "Enter a root password, or tick \"Key-only login (no password)\".\n\n" +
                    "Building with an empty password would let the added accounts log in " +
                    "with no password at all.",
                    "Password required", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

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
                : "  Root pw    : (set — stored as MD5-crypt $1$root$…)");
            sb.AppendLine($"  Output     : {output}");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                FwzBuildResult r = FwzProbe.BuildModifiedFwz(fwz, opts, output);
                sb.AppendLine($"Archive password : {r.PasswordUsed}  (ZipCrypto key, not the device model)");
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
                    sb.AppendLine("❌ Some checks FAILED — the verified build was NOT written.");
                    sb.AppendLine($"   Your chosen output path was left unchanged: {output}");
                    sb.AppendLine("   (any existing file there is NOT this build — do not flash it.)");
                    sb.AppendLine("   See the failing checks above.");
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
            if (publicKey.Length == 0 || !SshKeyGen.IsLikelyPublicKey(publicKey))
            {
                MessageBox.Show(this,
                    "The chosen key file does not look like an OpenSSH public key\n" +
                    "(expected a line like \"ssh-rsa AAAA… comment\"). Verification compares\n" +
                    "against this key, so it must be the .pub the .fwz was built with.",
                    "Not a public key", MessageBoxButton.OK, MessageBoxImage.Warning);
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
                : "  Root pw    : (as entered — must match how that .fwz was built)");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                SshEnableReport r = FwzProbe.ValidateSshInFwz(fwzPath, opts);
                sb.AppendLine($"Archive password : {r.PasswordUsed}  (ZipCrypto key, not the device model)");
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
            BtnChooseKey.IsEnabled = enabled;
            BtnGenKey.IsEnabled = enabled;
            // The output row stays disabled until a firmware is chosen.
            BtnBrowseOutput.IsEnabled = enabled && _fwzPath != null;
            BtnVerify.IsEnabled = enabled;
            BtnSelfTest.IsEnabled = enabled;
            // Build only re-enables if the three inputs are set.
            BtnBuild.IsEnabled = enabled
                && _fwzPath != null && _keyPath != null && _outputPath != null;
        }
    }
}
