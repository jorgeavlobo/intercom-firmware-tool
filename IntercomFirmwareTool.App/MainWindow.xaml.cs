using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using IntercomFirmwareTool.Core;
using Microsoft.Win32;

namespace IntercomFirmwareTool.App
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml.
    ///
    /// One product flow: choose the original .fwz and an output path, set a root
    /// password and/or an SSH public key (at least one), then Build a modified
    /// .fwz that enables SSH/root login (the fquinto edits), verified by a full
    /// read-back round-trip. Two secondary actions verify an existing .fwz and
    /// run the MD5-crypt self-test. The input .fwz is never modified.
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
            // The password is a Build precondition (the key is optional), so
            // re-evaluate the Build button as it changes.
            _pw.Changed += UpdateBuildEnabled;
            WirePeekButton();

            // Password fields start EMPTY on purpose: the user must enter a root
            // password (or tick key-only), so a build can never ship the publicly
            // known fquinto default. The empty-password guard in Build enforces it.
            UpdatePasswordHint();

            // Start the subtle "shine" on the donate buttons once the visual tree
            // (and their templates) are ready. Loaded can fire again on reparent, so
            // guard to start the loops only once per window instance.
            Loaded += (_, _) =>
            {
                if (_shineStarted) return;
                _shineStarted = true;
                StartDonateShine();
            };
        }

        private readonly Random _shineRng = new();
        private bool _shineStarted;

        /// <summary>
        /// Kicks off an independent, randomly-timed shine sweep on each donate
        /// button. The two loops use separate random delays, so the glints rarely
        /// coincide and never settle into a fixed rhythm — a quiet, occasional
        /// catch-the-eye, not a constant animation.
        /// </summary>
        private void StartDonateShine()
        {
            BeginShineLoop(BtnPayPal);
            BeginShineLoop(BtnRevolut);
        }

        private void BeginShineLoop(Button button)
        {
            // The animated band lives in the control template; pull out its named
            // transform for this specific button instance.
            button.ApplyTemplate();
            if (button.Template?.FindName("sheenT", button) is not TranslateTransform sheen) return;

            void ScheduleNext()
            {
                // Random gap between sweeps (~5–14 s) so the two buttons stay out of
                // phase and the effect feels organic rather than mechanical.
                var timer = new DispatcherTimer
                {
                    Interval = TimeSpan.FromMilliseconds(_shineRng.Next(5000, 14000))
                };
                timer.Tick += (_, _) =>
                {
                    timer.Stop();
                    Sweep(button, sheen);
                    ScheduleNext();
                };
                timer.Start();
            }
            ScheduleNext();
        }

        /// <summary>Sweeps the light band once across a button (left → right, then reverts off-screen).</summary>
        private static void Sweep(Button button, TranslateTransform sheen)
        {
            // End just past the button's right edge so the band fully exits for this
            // button's actual width (+ margin for the skewed band); fall back to a
            // fixed value if the button hasn't been measured yet.
            double end = button.ActualWidth > 0 ? button.ActualWidth + 60 : 170;
            var anim = new DoubleAnimation
            {
                // Start at the template's base X (off the left edge, for any width) so
                // there is no jump when a sweep begins.
                From = -90,
                To = end,
                Duration = TimeSpan.FromMilliseconds(1500),
                // Ease in/out for a smooth, premium glide rather than a linear wipe.
                EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut },
                // Revert to the base (off-screen) X after each sweep instead of holding
                // the final value, so the band is never parked on-screen at rest.
                FillBehavior = FillBehavior.Stop
            };
            sheen.BeginAnimation(TranslateTransform.XProperty, anim);
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
            if (ChkKeyOnly.IsChecked == true) on = false; // nothing to reveal when password is disabled
            // An explicit reveal cancels any pending flash auto-remask, so holding
            // the eye during the ~0.5 s flash window is not cut short by the timer.
            if (on) _flashTimer?.Stop();
            _pw.Peek = on;
            _confirm.Peek = on;
            BtnToggleReveal.Content = on ? EyeHide : EyeShow;
            string hint = on ? "Release to hide the password" : "Hold to show the password";
            BtnToggleReveal.ToolTip = hint;
            // Keep the screen-reader name in sync with the state, not just the
            // tooltip — otherwise it always announces the initial "Hold to show".
            AutomationProperties.SetName(BtnToggleReveal, hint);
        }

        private DispatcherTimer? _flashTimer;

        /// <summary>Briefly reveals both fields (~0.5 s), then re-masks — a visible
        /// cue that the password just changed (e.g. after generating one).</summary>
        private void FlashReveal()
        {
            if (ChkKeyOnly.IsChecked == true) return; // password disabled — nothing to flash
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
                // Copy WITHOUT leaving the plaintext password in Windows Clipboard
                // History or cloud clipboard sync (see SecureClipboard).
                SecureClipboard.SetText(pwd);
                TxtResult.Text = "Password copied (excluded from clipboard history / cloud sync).";
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

        /// <summary>Picks the original firmware, verifies it against the whitelist (size + SHA-256), and selects it.</summary>
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
                "Set a root password and/or an SSH key (at least one), then Build.";
        }

        /// <summary>Picks an existing OpenSSH public key and selects it for the build.</summary>
        private void BtnChooseKey_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Title = "Choose your SSH public key (.pub)",
                Filter = "Public key (*.pub)|*.pub|All files (*.*)|*.*",
                InitialDirectory = DefaultSshDir()
            };
            if (dlg.ShowDialog(this) != true) return;

            // Validate on selection so bad input is caught here, not at Build time.
            string chosen = dlg.FileName;
            string content;
            try { content = File.ReadAllText(chosen).Trim(); }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not read the key file:\n{ex.Message}",
                    "Cannot read key", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (content.Length == 0 || !SshKeyGen.IsLikelyPublicKey(content))
            {
                MessageBox.Show(this,
                    "That file does not look like an OpenSSH public key\n" +
                    "(expected a line like \"ssh-rsa AAAA… comment\"). Pick the .pub file.",
                    "Not a public key", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _keyPath = chosen;
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

            // Lock the private key to the current Windows account (best-effort):
            // OpenSSH refuses a world-readable key, and other local users must not
            // read it. The UI keeps the manual command as a fallback.
            bool restricted = RestrictKeyToCurrentUser(privatePath);

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
                (restricted
                    ? "The private key was restricted to your Windows account (other users locked\n" +
                      "out), so OpenSSH will accept it."
                    : "If Windows OpenSSH reports the key is too open (\"UNPROTECTED PRIVATE KEY\n" +
                      "FILE\"), restrict it to your account with:\n" +
                      "  icacls \"" + privatePath + "\" /inheritance:r /grant:r \"%USERNAME%:F\"\n" +
                      "(Full control for you only — OpenSSH just needs other users locked out.)");

            MessageBox.Show(this,
                $"Key pair created.\n\nPrivate key:\n{privatePath}\n\nPublic key:\n{pubPath}\n\n" +
                "Keep the private key safe — it has no passphrase.",
                "New SSH key", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        /// <summary>
        /// Best-effort: lock a freshly written private key to the current Windows
        /// account (break inheritance, grant only this user) via icacls, so OpenSSH
        /// accepts it and other local users can't read it. Returns true on a clean
        /// exit; the UI keeps the manual command as a fallback.
        /// </summary>
        private static bool RestrictKeyToCurrentUser(string path)
        {
            try
            {
                // Grant by SID (icacls accepts "*<SID>"), not a bare username: the
                // SID is unambiguous and resolves for domain/Microsoft accounts too,
                // where DOMAIN\user or a plain name may not.
                string? sid = WindowsIdentity.GetCurrent().User?.Value;
                if (string.IsNullOrEmpty(sid)) return false;
                // Launch by absolute path (…\System32\icacls.exe), not the bare
                // name: a bare "icacls" resolves through the executable search
                // order, so a planted icacls.exe in the app/working directory could
                // run instead. Environment.SystemDirectory is locale/drive-safe.
                string icacls = Path.Combine(Environment.SystemDirectory, "icacls.exe");
                var psi = new ProcessStartInfo(icacls,
                    $"\"{path}\" /inheritance:r /grant:r \"*{sid}:F\"")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    // Do NOT redirect stdout/stderr: we never read them, and a
                    // redirected pipe that fills would block WaitForExit and cause a
                    // false timeout. Only the exit code matters here, and
                    // CreateNoWindow already suppresses any console window.
                };
                using var p = Process.Start(psi);
                if (p is null) return false;
                if (!p.WaitForExit(5000))
                {
                    // Timed out: kill it (disposing Process wouldn't) and give up.
                    try { p.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                    return false;
                }
                return p.ExitCode == 0;
            }
            catch { return false; }
        }

        /// <summary>Opens the Save dialog to choose the modified-firmware output path.</summary>
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

        /// <summary>Clears the selected SSH key so the build uses the password only.</summary>
        private void BtnClearKey_Click(object sender, RoutedEventArgs e)
        {
            _keyPath = null;
            UpdateKeyPlaceholder();
            UpdateBuildEnabled();
        }

        /// <summary>
        /// Opens an http/https URL in the default browser (best-effort; never
        /// throws to the UI). Only absolute http/https URLs are allowed:
        /// UseShellExecute=true would otherwise hand ANY scheme to the shell
        /// (file:, ms-settings:, …), which is not something this tool should do.
        /// </summary>
        private static void OpenUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
                return;
            try
            {
                Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
            }
            catch { /* opening a browser is best-effort, non-critical */ }
        }

        /// <summary>Opens a header hyperlink (the MyHOME Suite download) in the default browser.</summary>
        private void Hyperlink_RequestNavigate(object sender, System.Windows.Navigation.RequestNavigateEventArgs e)
        {
            // Guard the Uri: a hyperlink wired to this handler without a
            // NavigateUri would otherwise NRE on e.Uri before OpenUrl's try/catch.
            if (e.Uri != null) OpenUrl(e.Uri.AbsoluteUri);
            e.Handled = true;
        }

        /// <summary>Opens the PayPal.me page to buy the author a coffee.</summary>
        private void BtnPayPal_Click(object sender, RoutedEventArgs e) =>
            OpenUrl("https://paypal.me/jorgeavlobo");

        /// <summary>Opens the Revolut.me page to buy the author a coffee.</summary>
        private void BtnRevolut_Click(object sender, RoutedEventArgs e) =>
            OpenUrl("https://revolut.me/jorgeavlobo");

        /// <summary>
        /// Refreshes the key box placeholder to say whether the key is optional or
        /// required (key-only). Only while no key is selected — otherwise the box
        /// shows the chosen path.
        /// </summary>
        private void UpdateKeyPlaceholder()
        {
            if (_keyPath != null) return;
            bool required = ChkKeyOnly.IsChecked == true;
            TxtKeyPath.Text = required
                ? "(required: choose an existing .pub key, or generate a new pair)"
                : "(optional: choose an existing .pub key, or generate a new pair)";
            TxtKeyPath.Foreground = Brushes.Gray;
        }

        /// <summary>
        /// Toggles password login off/on (key-only). When disabled, greys the
        /// password fields and stops any active reveal; a key becomes the credential.
        /// </summary>
        private void ChkKeyOnly_Toggled(object sender, RoutedEventArgs e)
        {
            bool usePassword = ChkKeyOnly.IsChecked != true;
            if (!usePassword) SetReveal(false);

            TxtPassword.IsEnabled = usePassword;
            TxtConfirm.IsEnabled = usePassword;
            BtnToggleReveal.IsEnabled = usePassword;
            BtnCopyPwd.IsEnabled = usePassword;
            BtnRandomPwd.IsEnabled = usePassword;

            // With password login off, the key is the only credential, so mark it
            // required (label + placeholder); with password on, it is optional again.
            LblKey.Text = usePassword ? "SSH public key (optional):" : "SSH public key (required):";
            UpdateKeyPlaceholder();

            UpdatePasswordHint();
            UpdateBuildEnabled();
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

        /// <summary>
        /// Whether a credential is currently available for Build: with password
        /// login disabled a key is required; otherwise a non-empty password.
        /// Single source of truth so the two enable-gates can't drift.
        /// </summary>
        private bool HaveCredential()
        {
            bool passwordOff = ChkKeyOnly.IsChecked == true;
            return passwordOff ? _keyPath != null : CurrentPassword().Length > 0;
        }

        /// <summary>
        /// Enables the Build button when firmware and output are set and at least
        /// one credential is available: with password login disabled a key is
        /// required; otherwise a non-empty password is required (key optional).
        /// </summary>
        private void UpdateBuildEnabled()
        {
            BtnBuild.IsEnabled =
                _fwzPath != null && _outputPath != null && HaveCredential();
        }

        // ---- Primary action: Build ------------------------------------------

        /// <summary>Validates the inputs, builds the modified firmware, and shows the verified round-trip result.</summary>
        private async void BtnBuild_Click(object sender, RoutedEventArgs e)
        {
            if (_fwzPath is null || _outputPath is null) return;

            // One of the password or the key is required. "Disable" turns password
            // login off (key-only); otherwise a non-empty, matching password is used.
            bool passwordOff = ChkKeyOnly.IsChecked == true;
            string? password = null;
            if (!passwordOff)
            {
                password = CurrentPassword();
                if (password.Length == 0)
                {
                    MessageBox.Show(this,
                        "Enter a root password, or tick \"Disable\" to build a key-only\n" +
                        "firmware (which then requires an SSH key).",
                        "Password required", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (password != CurrentConfirm())
                {
                    MessageBox.Show(this,
                        "The password and its confirmation do not match.",
                        "Password mismatch", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
            }

            // The key is required only when password login is disabled; otherwise
            // it is optional. If one is present, read and validate it.
            string? publicKey = null;
            if (_keyPath is { } keyPath) // captured non-null: field re-widens after calls
            {
                try
                {
                    publicKey = File.ReadAllText(keyPath).Trim();
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
                        "Pick a valid .pub file, or generate a new pair.",
                        "Not a public key", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // The output must not clobber the selected key OR its private sibling
                // (the build moves the verified artifact onto the output path with
                // overwrite; deleting the private key would make key login impossible).
                string? privKey = SelectedPrivateKeyPath();
                if (SamePath(_outputPath!, keyPath) ||
                    (privKey != null && SamePath(_outputPath!, privKey)))
                {
                    MessageBox.Show(this,
                        "The output path is the same file as the selected SSH key (public or\n" +
                        "private). Choose a different output so the key isn't overwritten.",
                        "Output collides with the key", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
            }

            // Key-only (password disabled) needs a key, and it must be RSA — the only
            // algorithm verified to authenticate on the target firmware's dropbear,
            // so a non-RSA key-only build could leave the device with no usable login.
            if (passwordOff)
            {
                if (publicKey is null)
                {
                    MessageBox.Show(this,
                        "Password login is disabled, so an SSH key is required.\n\n" +
                        "Choose or generate a key, or untick \"Disable\" and set a password.",
                        "Key required", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (SshKeyGen.KeyType(publicKey) != "ssh-rsa")
                {
                    MessageBox.Show(this,
                        "Key-only login requires an RSA public key.\n\n" +
                        "RSA is the only key type verified to authenticate on this firmware's\n" +
                        "dropbear, so a key-only build with another type could leave the device\n" +
                        "with no way to log in. Use an RSA key, or untick \"Disable\" and set a\n" +
                        "root password as a fallback.",
                        "RSA key required for key-only", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
            }

            // Never build over a PRIVATE KEY file. The .pub-sibling collision guard
            // above only fires when the selected public key follows the .pub naming
            // convention; a public key named otherwise (e.g. id_rsa.public) leaves
            // the private sibling underivable, so the user could pick the matching
            // private key as the output and a successful build would destroy it.
            // A content check closes that gap regardless of file naming.
            if (File.Exists(_outputPath) && LooksLikePrivateKeyFile(_outputPath!))
            {
                MessageBox.Show(this,
                    "The output path is an SSH PRIVATE KEY file:\n\n" + _outputPath + "\n\n" +
                    "Building there would overwrite and destroy the key. Choose a different output.",
                    "Output is a private key", MessageBoxButton.OK, MessageBoxImage.Warning);
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

            var opts = new EnableSshOptions(password, publicKey);

            // Non-null here: guarded above (and Build is only enabled with firmware,
            // output and a credential set). They are fields, so the compiler re-widens
            // them to maybe-null after the intervening calls — assert with '!'.
            string fwz = _fwzPath!, output = _outputPath!;

            var sb = new StringBuilder();
            sb.AppendLine("Building modified firmware…");
            sb.AppendLine($"  Input      : {fwz}");
            sb.AppendLine(opts.HasPassword
                ? "  Root pw    : (set — stored as MD5-crypt $1$root$…)"
                : "  Root pw    : (disabled — key-only login)");
            sb.AppendLine(opts.HasKey
                ? $"  Public key : {_keyPath}"
                : "  Public key : (none — password login only)");
            sb.AppendLine($"  Output     : {output}");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                // No build-time re-hash here: BuildModifiedFwz performs the
                // authoritative whitelist verification (size + SHA-256) itself,
                // atomically under the input file lock — the TOCTOU-safe place to
                // do it. A second ~100 MB hash here would only slow every build
                // without adding safety. It throws a clear error if the input is
                // not a recognized original, which RunAndShow surfaces.
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
                    sb.AppendLine("Before flashing: keep the ORIGINAL firmware and be ready to re-flash it");
                    sb.AppendLine("with My Home Suite over Mini-USB. These units use an i.MX SoC — there is");
                    sb.AppendLine("no documented low-level un-brick (SAM-BA does not apply), so a bad flash");
                    sb.AppendLine("may be unrecoverable. Your original .fwz was not modified.");
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

        /// <summary>
        /// Inspects an existing .fwz and reports its SSH-enable state (read-only).
        /// Self-contained: the operator just picks a file and reads a report — no
        /// password to re-type and no key to re-pick, and it is independent of the
        /// build form's fields. It reports what is actually installed
        /// (password-login mode, the deployed key's SHA-256 fingerprint) plus the
        /// objective structural checks.
        /// </summary>
        private async void BtnVerify_Click(object sender, RoutedEventArgs e)
        {
            var fwzDlg = new OpenFileDialog
            {
                Title = "Choose a modified .fwz to inspect (e.g. this tool's or fquinto's output)",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*"
            };
            if (fwzDlg.ShowDialog(this) != true) return;
            string fwzPath = fwzDlg.FileName;

            var sb = new StringBuilder();
            sb.AppendLine("Inspecting an existing firmware (read-only, the .fwz is not modified)…");
            sb.AppendLine($"  .fwz       : {fwzPath}");
            sb.AppendLine();

            await RunAndShow(sb, () =>
            {
                SshInspectionReport r = FwzProbe.InspectSshInFwz(fwzPath);
                sb.AppendLine($"Archive password : {r.PasswordUsed}  (ZipCrypto key, not the device model)");
                sb.AppendLine($"Inner entry    : {r.SelectedEntry}");
                sb.AppendLine();
                sb.AppendLine("What's inside:");
                foreach (var f in r.Findings) sb.AppendLine("  " + f);
                sb.AppendLine();
                sb.AppendLine("Checklist:");
                AppendChecks(sb, r.Checks);
                sb.AppendLine();
                sb.AppendLine(r.AllPass
                    ? "✅ ALL PASS — a valid, complete SSH-enable with at least one working login."
                    : "❌ SOME FAILED — this .fwz is missing or differs on the checks above.");
            });
        }

        // ---- Secondary: MD5-crypt self-test ---------------------------------

        /// <summary>Runs the MD5-crypt self-test and shows the pass/fail result.</summary>
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

        /// <summary>
        /// Best-effort: true if the file looks like an SSH/PEM PRIVATE key, so a
        /// build must never overwrite it. Reads only a small prefix and matches the
        /// PEM private-key marker (covers RSA/OPENSSH/PKCS#8/ENCRYPTED headers). Any
        /// read error returns false — the generic overwrite prompt still applies.
        /// </summary>
        private static bool LooksLikePrivateKeyFile(string path)
        {
            try
            {
                using var r = new StreamReader(path);
                var buf = new char[256];
                int n = r.Read(buf, 0, buf.Length);
                return new string(buf, 0, n).Contains("PRIVATE KEY-----", StringComparison.Ordinal);
            }
            catch { return false; }
        }

        /// <summary>Enables/disables the action buttons and credential inputs during an operation.</summary>
        private void SetButtonsEnabled(bool enabled)
        {
            // Starting an operation: force the fields back to masked first. If the
            // user was holding the eye (Peek), disabling the button can swallow the
            // mouse/key-up that would re-mask, leaving the password visible for the
            // whole operation.
            if (!enabled) SetReveal(false);

            BtnBrowseFwz.IsEnabled = enabled;
            BtnChooseKey.IsEnabled = enabled;
            BtnGenKey.IsEnabled = enabled;
            BtnClearKey.IsEnabled = enabled;
            // The output row stays disabled until a firmware is chosen.
            BtnBrowseOutput.IsEnabled = enabled && _fwzPath != null;
            BtnVerify.IsEnabled = enabled;
            BtnSelfTest.IsEnabled = enabled;
            // Build only re-enables when firmware + output + a credential are set
            // (a password, or a key when password login is disabled).
            bool passwordOff = ChkKeyOnly.IsChecked == true;
            BtnBuild.IsEnabled = enabled
                && _fwzPath != null && _outputPath != null && HaveCredential();

            // Also lock the credential inputs during an operation so the visible UI
            // can't drift from the values snapshotted for the build. When
            // re-enabling, respect the Disable (key-only) state.
            bool creds = enabled && !passwordOff;
            ChkKeyOnly.IsEnabled = enabled;
            TxtPassword.IsEnabled = creds;
            TxtConfirm.IsEnabled = creds;
            BtnToggleReveal.IsEnabled = creds;
            BtnCopyPwd.IsEnabled = creds;
            BtnRandomPwd.IsEnabled = creds;
        }
    }
}
