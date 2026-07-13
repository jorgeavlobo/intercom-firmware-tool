using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
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

            // Password fields start EMPTY on purpose: the user must enter a root
            // password (or tick key-only), so a build can never ship the publicly
            // known fquinto default. The empty-password guard in Build enforces it.
            UpdatePasswordHint();
        }

        // ---- Inline password actions (reveal / copy / generate) --------------

        private static readonly string EyeShow = ""; // Segoe MDL2: RedEye  → "reveal"
        private static readonly string EyeHide = ""; // Segoe MDL2: Hide    → "conceal"

        /// <summary>
        /// The eye reveals the passwords only WHILE the button is held (mouse or
        /// keyboard), re-masking on release — hold-to-peek, not a toggle.
        /// </summary>
        private void WirePeekButton()
        {
            BtnToggleReveal.PreviewMouseLeftButtonDown += (_, _) => SetReveal(true);
            BtnToggleReveal.PreviewMouseLeftButtonUp += (_, _) => SetReveal(false);
            BtnToggleReveal.LostMouseCapture += (_, _) => SetReveal(false);
            BtnToggleReveal.MouseLeave += (_, _) => SetReveal(false);
            // Re-mask if focus leaves before key-up (e.g. Tab away while held).
            BtnToggleReveal.LostKeyboardFocus += (_, _) => SetReveal(false);
            BtnToggleReveal.PreviewKeyDown += (_, e) =>
            {
                if (e.Key == Key.Space || e.Key == Key.Enter) { SetReveal(true); e.Handled = true; }
            };
            BtnToggleReveal.PreviewKeyUp += (_, e) =>
            {
                if (e.Key == Key.Space || e.Key == Key.Enter) { SetReveal(false); e.Handled = true; }
            };
        }

        /// <summary>Reveals or masks BOTH password fields and updates the eye icon.</summary>
        private void SetReveal(bool on)
        {
            if (ChkKeyOnly.IsChecked == true) on = false; // nothing to reveal in key-only
            // An explicit reveal cancels any pending flash auto-remask, so holding
            // the eye during the ~0.5 s flash window is not cut short by the timer.
            if (on) _flashTimer?.Stop();
            _pw.Peek = on;
            _confirm.Peek = on;
            BtnToggleReveal.Content = on ? EyeHide : EyeShow;
            BtnToggleReveal.ToolTip = on ? "Release to hide" : "Hold to show the password";
        }

        private DispatcherTimer? _flashTimer;

        /// <summary>Briefly reveals both fields (~0.5 s), then re-masks — a visible
        /// cue that the password just changed (e.g. after generating one).</summary>
        private void FlashReveal()
        {
            if (ChkKeyOnly.IsChecked == true) return;
            SetReveal(true);
            if (_flashTimer is null)
            {
                _flashTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
                _flashTimer.Tick += (_, _) => { _flashTimer!.Stop(); SetReveal(false); };
            }
            _flashTimer.Stop();
            _flashTimer.Start();
        }

        /// <summary>Copies the current password to the clipboard (nothing is shown).</summary>
        private void BtnCopyPwd_Click(object sender, RoutedEventArgs e)
        {
            string pwd = _pw.Value;
            if (pwd.Length == 0)
            {
                TxtResult.Text = "Nothing to copy — the password field is empty.";
                return;
            }
            try
            {
                Clipboard.SetText(pwd);
                TxtResult.Text = "Password copied to the clipboard.";
            }
            catch (Exception ex)
            {
                TxtResult.Text = "Could not copy to the clipboard:\n" + ex.Message;
            }
        }

        /// <summary>
        /// Fills both password fields with a fresh strong random password and
        /// briefly reveals them so the user can read/copy it. Only guidance text is
        /// written to the Result box — never the password itself, which appears
        /// only in the (briefly revealed) fields.
        /// </summary>
        private void BtnRandomPwd_Click(object sender, RoutedEventArgs e)
        {
            if (ChkKeyOnly.IsChecked == true) return; // password login disabled

            string pwd = GenerateRandomPassword(20);
            _pw.Value = pwd;
            _confirm.Value = pwd; // both set → the match hint shows ✓
            UpdatePasswordHint();
            FlashReveal();        // briefly show it as a visible "it changed" cue

            TxtResult.Text =
                "Generated a strong random password and filled both fields.\n" +
                "Hold the eye to view it, or use the copy button — keep it safe, it is not " +
                "stored and you'll need it to log in.";
        }

        /// <summary>A strong random password from an unambiguous character set.</summary>
        private static string GenerateRandomPassword(int length)
        {
            // Drop visually ambiguous characters (0/O, 1/l/I) so it is easy to read
            // and retype; include a few symbols for strength. RandomNumberGenerator
            // gives an unbiased, cryptographically strong selection.
            const string alphabet =
                "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^*-_=+";
            var chars = new char[length];
            for (int i = 0; i < length; i++)
                chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
            return new string(chars);
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
            catch (Exception ex)
            {
                // Never let an exception escape this async void handler (it would
                // crash the dispatcher); turn it into a normal rejection below.
                check = new FirmwareCheckResult(false, null, "Could not verify the firmware: " + ex.Message);
            }
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
            string pubDest = privatePath + ".pub";

            // Never write the key pair over a selected firmware / output / key —
            // that would violate "the input is never modified" (and destroy the
            // output or the chosen key).
            foreach (var (label, p) in new[] { ("input firmware", _fwzPath), ("output firmware", _outputPath), ("selected public key", _keyPath) })
            {
                if (p != null && (SamePath(privatePath, p) || SamePath(pubDest, p)))
                {
                    MessageBox.Show(this,
                        $"The key would be written over the {label}:\n\n{p}\n\n" +
                        "Choose a different location for the new key.",
                        "Path collision", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
            }

            // The Save dialog only prompted about the private-key path; confirm
            // the sibling .pub too, since generating overwrites it.
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

            // Report exactly what was generated so the user can see and verify it:
            // the key type/size and the SHA-256 fingerprint (same value that
            // `ssh-keygen -lf <file>.pub` prints).
            string keyDetails = "";
            try
            {
                var info = SshKeyGen.DescribePublicKey(File.ReadAllText(pubPath));
                if (info != null)
                    keyDetails =
                        $"  Key type    : {info.Label}\n" +
                        $"  Fingerprint : {info.Sha256Fingerprint}\n";
            }
            catch { /* details are informational; never block on them */ }

            TxtResult.Text =
                "New SSH key pair created.\n\n" +
                $"  Private key : {privatePath}\n" +
                $"  Public key  : {pubPath}\n" +
                keyDetails + "\n" +
                "The public key is now selected for the build. KEEP THE PRIVATE KEY SAFE —\n" +
                "it is what you will use to log in. This build adds a root2 account (uid 0),\n" +
                "so connect as root2:  ssh -i \"" + privatePath + "\" root2@<device>\n" +
                "It has no passphrase; add one later with:  ssh-keygen -p -f \"" + privatePath + "\"\n\n" +
                "If Windows OpenSSH later reports the key is too open (\"UNPROTECTED PRIVATE\n" +
                "KEY FILE\"), restrict it to your account with:\n" +
                "  icacls \"" + privatePath + "\" /inheritance:r /grant:r \"%USERNAME%:F\"\n" +
                "(Full control for you only — OpenSSH just needs other users locked out, and\n" +
                "you keep write access to add a passphrase later.)";

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
            if (!usePassword) SetReveal(false);

            TxtPassword.IsEnabled = usePassword;
            TxtConfirm.IsEnabled = usePassword;
            BtnToggleReveal.IsEnabled = usePassword;
            BtnCopyPwd.IsEnabled = usePassword;
            BtnRandomPwd.IsEnabled = usePassword;
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

            // The output must not clobber the selected public key OR its private
            // sibling (the build moves the verified artifact onto the output path
            // with overwrite; deleting the private key would make a key-only build
            // impossible to log into).
            string? privKey = SelectedPrivateKeyPath();
            if ((_keyPath != null && SamePath(_outputPath!, _keyPath)) ||
                (privKey != null && SamePath(_outputPath!, privKey)))
            {
                MessageBox.Show(this,
                    "The output path is the same file as the selected SSH key (public or\n" +
                    "private). Choose a different output so the key isn't overwritten.",
                    "Output collides with the key", MessageBoxButton.OK, MessageBoxImage.Warning);
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
                // Re-verify at build time (TOCTOU): the file may have changed
                // since the Browse-time check — a synced/replaced download, or a
                // symlink retargeted — so re-run the size + SHA-256 gate on the
                // actual bytes we are about to modify.
                var recheck = FirmwareRegistry.Verify(fwz);
                if (!recheck.Ok)
                    throw new InvalidOperationException(
                        "The selected firmware no longer matches a known-good original — build aborted. " +
                        "Re-select the file.\n" + recheck.Message);

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

            // With password login, an empty password validates against the
            // BLANK-password /etc/shadow hash — a misleading false-negative that
            // would never match a real build. Require one, or tick key-only.
            if (!keyOnly && password.Length == 0)
            {
                MessageBox.Show(this,
                    "Enter the root password that .fwz was built with, or tick\n" +
                    "\"Key-only login (no password)\" if it has no password login.\n\n" +
                    "Verifying with an empty password compares against the blank-password\n" +
                    "hash, which will fail even for a correctly built firmware.",
                    "Password required", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

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

        /// <summary>
        /// Same underlying file? Delegates to the shared Core rule, which resolves
        /// symlinks/junctions (final component and parent chain) so a path-collision
        /// warning is not bypassed by an alias. Case-insensitive on Windows.
        /// </summary>
        private static bool SamePath(string a, string b) => PathIdentity.SamePath(a, b);

        /// <summary>
        /// The private-key path paired with the selected public key, when derivable:
        /// an OpenSSH "<c>.pub</c>" strips to its private sibling. This also matches
        /// the pair produced by "Generate new…", where the public key is the private
        /// path plus "<c>.pub</c>". Null if the selected key does not end in ".pub".
        /// </summary>
        private string? SelectedPrivateKeyPath()
        {
            const string pub = ".pub";
            return _keyPath != null && _keyPath.EndsWith(pub, StringComparison.OrdinalIgnoreCase)
                ? _keyPath[..^pub.Length]
                : null;
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

            // Also lock the credential inputs during an operation so the visible
            // UI can't drift from the values snapshotted for the build. When
            // re-enabling, respect key-only mode (password fields stay disabled).
            bool creds = enabled && ChkKeyOnly.IsChecked != true;
            ChkKeyOnly.IsEnabled = enabled;
            TxtPassword.IsEnabled = creds;
            TxtConfirm.IsEnabled = creds;
            BtnToggleReveal.IsEnabled = creds;
            BtnCopyPwd.IsEnabled = creds;
            BtnRandomPwd.IsEnabled = creds;
        }
    }
}
