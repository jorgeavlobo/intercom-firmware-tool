using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
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
    /// password (or tick Disable for key-only, which requires an SSH public key),
    /// then Build a modified
    /// .fwz that enables SSH/root login (the fquinto edits), verified by a full
    /// read-back round-trip. Two secondary actions verify an existing .fwz and
    /// run the MD5-crypt self-test. The input .fwz is never modified.
    /// </summary>
    public partial class MainWindow : Window
    {
        private string? _fwzPath;
        private string? _keyPath;
        private string? _outputPath;

        // Background locator for the newest unmodified original firmware on the
        // machine, so the picker opens where it lives. Cancelled once a firmware is
        // chosen or the window closes.
        private readonly FirmwareScanner _fwScanner = new();
        private CancellationTokenSource? _scanCts;

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
            // re-evaluate the Build button/cues as either the password OR its
            // confirmation changes (a build needs them to match).
            _pw.Changed += UpdateBuildEnabled;
            _confirm.Changed += UpdateBuildEnabled;
            WirePeekButton();

            // Password fields start EMPTY on purpose: the user must enter a root
            // password (or tick key-only), so a build can never ship the publicly
            // known fquinto default. The empty-password guard in Build enforces it.
            UpdatePasswordHint();
            // Paint the initial required-field cues + "what's still needed" hint on
            // the blank form (also sets the Build button's initial disabled state).
            UpdateBuildEnabled();

            // Start the subtle "shine" on the donate buttons once the visual tree
            // (and their templates) are ready. Loaded can fire again on reparent, so
            // guard to start the loops only once per window instance.
            Loaded += (_, _) =>
            {
                if (_shineStarted) return;
                _shineStarted = true;
                StartDonateShine();
            };

            // Kick off the silent firmware scan immediately (background thread), and
            // make sure it stops when the window closes.
            _scanCts = new CancellationTokenSource();
            var scanToken = _scanCts.Token;
            Task.Run(() => _fwScanner.Scan(scanToken), scanToken);
            Closed += (_, _) => StopFirmwareScan();
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

        /// <summary>True when a key event is Enter or Space — the keyboard activation
        /// for the click-to-browse path fields (WCAG 2.1.1), so keyboard-only and
        /// screen-reader users can open the pickers the mouse handlers open.</summary>
        private static bool IsActivationKey(KeyEventArgs e) => e.Key == Key.Enter || e.Key == Key.Space;

        /// <summary>
        /// The firmware path box doubles as its own "browse" button (there is no
        /// separate folder button — Grid.Column 2 is the clear button instead):
        /// clicking it, or pressing Enter/Space while it has keyboard focus, opens
        /// the picker, verifies the file against the whitelist (size + SHA-256), and
        /// selects it.
        /// </summary>
        private async void TxtFwzPath_MouseDown(object sender, MouseButtonEventArgs e)
        {
            e.Handled = true; // act purely as a browse button (no caret/selection)
            await ChooseFirmwareAsync();
        }

        private async void TxtFwzPath_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (!IsActivationKey(e)) return;
            e.Handled = true;
            await ChooseFirmwareAsync();
        }

        private async Task ChooseFirmwareAsync()
        {
            if (!_uiEnabled) return; // ignored while an operation is running
            var dlg = new OpenFileDialog
            {
                Title = "Choose the original firmware (.fwz)",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*",
                // Open where the background scan found the newest original (if any),
                // else a sensible default (Downloads → Desktop → profile).
                InitialDirectory = FirmwareStartDir()
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

            // Accepted: record the path and enable the output row (BtnClearOutput is
            // driven by UpdateBuildEnabled once _outputPath is set, below).
            _fwzPath = chosen;
            StopFirmwareScan(); // a firmware is chosen — stop and release the scan
            SetPathText(TxtFwzPath, chosen);
            LblOutput.IsEnabled = true;
            TxtOutputPath.IsEnabled = true;
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
                "Set a root password (or tick \"Disable\" to use an SSH key only), then Build.";
        }

        /// <summary>
        /// Clears the firmware selection (the Grid.Column 2 button on the firmware
        /// row), returning the box to its neutral placeholder and disabling the
        /// output row again — mirrors the de-select branch of the picker above.
        /// </summary>
        private void BtnClearFwz_Click(object sender, RoutedEventArgs e)
        {
            _fwzPath = null;
            _outputPath = null;
            TxtFwzPath.Text = "(click to choose the original .fwz to modify)";
            TxtFwzPath.Foreground = Brushes.Gray;
            TxtOutputPath.Text = "(where to write the modified .fwz)";
            TxtOutputPath.Foreground = Brushes.Gray;
            LblOutput.IsEnabled = false;
            TxtOutputPath.IsEnabled = false;
            UpdateBuildEnabled();
        }

        /// <summary>
        /// The SSH key path box is click-to-browse (there is no separate folder
        /// button): clicking it, or pressing Enter/Space while focused, picks an
        /// existing OpenSSH public key. Generate / Clear are the two icon buttons.
        /// </summary>
        private void TxtKeyPath_MouseDown(object sender, MouseButtonEventArgs e)
        {
            e.Handled = true; // act purely as a browse button (no caret/selection)
            ChooseKey();
        }

        private void TxtKeyPath_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (!IsActivationKey(e)) return;
            e.Handled = true;
            ChooseKey();
        }

        /// <summary>Picks an existing OpenSSH public key and selects it for the build.</summary>
        private void ChooseKey()
        {
            if (!_uiEnabled) return; // ignored while an operation is running
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

        /// <summary>
        /// The output path box is click-to-browse (there is no separate save
        /// button — Grid.Column 2 is the clear button instead): clicking it, or
        /// pressing Enter/Space while focused, opens the Save dialog. The box is
        /// disabled until a firmware is chosen, so this only fires once usable.
        /// </summary>
        private void TxtOutputPath_MouseDown(object sender, MouseButtonEventArgs e)
        {
            e.Handled = true; // act purely as a browse button (no caret/selection)
            ChooseOutput();
        }

        private void TxtOutputPath_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (!IsActivationKey(e)) return;
            e.Handled = true;
            ChooseOutput();
        }

        /// <summary>Opens the Save dialog to choose the modified-firmware output path.</summary>
        private void ChooseOutput()
        {
            // The box is only enabled once a firmware is chosen and while no
            // operation is running; guard defensively all the same.
            if (!_uiEnabled || _fwzPath == null) return;
            var dlg = new SaveFileDialog
            {
                Title = "Save the modified firmware as…",
                Filter = "Bticino firmware (*.fwz)|*.fwz|All files (*.*)|*.*",
                FileName = Path.GetFileNameWithoutExtension(_fwzPath) + "_ssh.fwz",
                InitialDirectory = Path.GetDirectoryName(_fwzPath) ?? ""
            };
            if (dlg.ShowDialog(this) != true) return;

            string chosen = dlg.FileName;
            // Never let the output overwrite the original firmware. Reject it here so
            // the bad choice is caught at selection time (Build also refuses, but the
            // user shouldn't have to get that far). SamePath resolves aliases and works
            // for a not-yet-created file via its existing parent chain.
            if (SamePath(chosen, _fwzPath))
            {
                MessageBox.Show(this,
                    "The output must be a different file from the original firmware, so the " +
                    "original .fwz is never overwritten.\n\nChoose a different name or folder.",
                    "Cannot overwrite the original", MessageBoxButton.OK, MessageBoxImage.Warning);
                return; // keep the previous output selection unchanged
            }

            _outputPath = chosen;
            SetPathText(TxtOutputPath, _outputPath);
            UpdateBuildEnabled();
        }

        /// <summary>
        /// Clears the output location (the Grid.Column 2 button on the output row),
        /// returning the box to its placeholder. The firmware stays selected, so the
        /// row remains enabled and the box can be clicked to pick a new location.
        /// </summary>
        private void BtnClearOutput_Click(object sender, RoutedEventArgs e)
        {
            _outputPath = null;
            TxtOutputPath.Text = "(where to write the modified .fwz)";
            TxtOutputPath.Foreground = Brushes.Gray;
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
            // The reveal/copy/generate buttons are set centrally (content-aware) by
            // UpdatePasswordButtonStates, reached via UpdateBuildEnabled below.

            // With password login off, the key is the only credential; the
            // optional/required distinction is conveyed by the placeholder (the
            // label stays the constant "SSH Public Key:").
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

        /// <summary>
        /// Cancels and disposes the background scan's token source, once. Idempotent:
        /// called both when a firmware is chosen and when the window closes, so it
        /// nulls the field to avoid touching (or disposing) it twice.
        /// </summary>
        private void StopFirmwareScan()
        {
            var cts = _scanCts;
            if (cts == null) return;
            _scanCts = null;
            try { cts.Cancel(); } catch { /* nothing registered can throw; be safe */ }
            cts.Dispose();
        }

        /// <summary>
        /// Where the firmware picker should open: the folder of the newest unmodified
        /// original the background scan has found, or a sensible default when the scan
        /// hasn't found one yet (or found nothing).
        /// </summary>
        private string FirmwareStartDir()
        {
            string? best = _fwScanner.BestFolder;
            if (best != null && Directory.Exists(best)) return best;
            return FirmwareDefaultDir();
        }

        /// <summary>Default firmware folder: Downloads, else Desktop, else the profile.</summary>
        private static string FirmwareDefaultDir()
        {
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string downloads = Path.Combine(profile, "Downloads");
            if (Directory.Exists(downloads)) return downloads;
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            if (Directory.Exists(desktop)) return desktop;
            return profile;
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
        /// login disabled a key is required; otherwise a non-empty password that
        /// matches its confirmation. Single source of truth so the gates can't drift.
        /// </summary>
        private bool HaveCredential()
        {
            bool passwordOff = ChkKeyOnly.IsChecked == true;
            if (passwordOff) return _keyPath != null;
            // Password mode: a non-empty password that has been confirmed (matches).
            // Read the value once so the two comparisons can't observe different state.
            string pw = CurrentPassword();
            return pw.Length > 0 && pw == CurrentConfirm();
        }

        /// <summary>
        /// Enables the Build button when firmware and output are set and a credential
        /// is available: with password login disabled a key is required; otherwise a
        /// non-empty root password that matches its confirmation (key optional).
        /// </summary>
        private void UpdateBuildEnabled()
        {
            // _uiEnabled is false while a build/verify/self-test is running, so the
            // Build button (and the hint below, via UpdateRequiredCues) stay disabled
            // and off the "✓ Ready to build." message for the duration of the op.
            BtnBuild.IsEnabled = _uiEnabled
                && _fwzPath != null && _outputPath != null && HaveCredential();
            UpdateRequiredCues();
            // Keep the SSH key row's visibility in step with key-only mode and whether
            // a key is selected (both can change here); the advanced tools are toggled
            // separately by TglAdvanced_Changed.
            UpdateAdvancedVisibility();
        }

        /// <summary>
        /// Shows/hides the advanced surface. The two tool buttons follow the "Advanced
        /// options" toggle. The SSH key row (which lives in the advanced section) is
        /// shown when advanced is on, OR whenever a key is the required credential
        /// (key-only mode) or one is already selected — so a required/active credential
        /// is never hidden behind the toggle. The password label also loses its "Root"
        /// qualifier in the simple view.
        /// </summary>
        private void UpdateAdvancedVisibility()
        {
            bool advanced = TglAdvanced.IsChecked == true;
            bool keyOnly = ChkKeyOnly.IsChecked == true;

            // "Password:" in the simple view; "Root Password:" in Advanced (the rule
            // line below mirrors the same wording).
            LblPassword.Text = advanced ? "Root Password:" : "Password:";
            LblCredentialRule.Text = advanced
                ? "A root password is required — or tick “Disable” to log in with an SSH key only."
                : "A password is required — or tick “Disable” to log in with an SSH key only.";

            KeyRow.Visibility = (advanced || keyOnly || _keyPath != null)
                ? Visibility.Visible : Visibility.Collapsed;

            AdvancedTools.Visibility = advanced ? Visibility.Visible : Visibility.Collapsed;

            // The result output is part of Advanced. When shown, its row fills the
            // window; when hidden, the spacer row takes the slack so the footer stays
            // pinned to the bottom (no empty gap).
            ResultGroup.Visibility = advanced ? Visibility.Visible : Visibility.Collapsed;
            RowResult.Height = advanced ? new GridLength(1, GridUnitType.Star) : GridLength.Auto;
            RowSpacer.Height = advanced ? GridLength.Auto : new GridLength(1, GridUnitType.Star);
        }

        private double? _heightBeforeAdvanced;

        /// <summary>Toggles the advanced surface (SSH key row + tool buttons + result).</summary>
        private void TglAdvanced_Changed(object sender, RoutedEventArgs e)
        {
            UpdateAdvancedVisibility();
            if (TglAdvanced.IsChecked == true)
            {
                // Opening: remember the current height, then grow so the result output
                // has room (only if we haven't already grown for this open session).
                if (_heightBeforeAdvanced == null)
                {
                    _heightBeforeAdvanced = Height;
                    if (Height < 720) Height = 720;
                }
            }
            else if (_heightBeforeAdvanced != null)
            {
                // Closing: restore the window to the size it had before opening Advanced.
                Height = _heightBeforeAdvanced.Value;
                _heightBeforeAdvanced = null;
            }
        }

        // Amber cue for a required field that is still blank. Colour is never the
        // ONLY signal: it is paired with the field labels and the textual
        // "what's still needed" hint (WCAG 1.4.1).
        private static readonly SolidColorBrush NeededBrush = MakeFrozen(Color.FromRgb(0xD9, 0x8A, 0x00));
        private static readonly SolidColorBrush ReadyBrush = MakeFrozen(Color.FromRgb(0x2E, 0x7D, 0x32));
        // Error cue (e.g. confirm doesn't match) — Firebrick, matching the ✗ text hint.
        private static readonly Brush ErrorBrush = Brushes.Firebrick;

        private static SolidColorBrush MakeFrozen(Color c)
        {
            var b = new SolidColorBrush(c);
            b.Freeze();
            return b;
        }

        /// <summary>
        /// Highlights the fields still blocking a Build (blank + required) with an
        /// amber border, and refreshes the "what's still needed" hint by the Build
        /// button. Respects the password-OR-key rule — it flags whichever credential
        /// is actually required for the current mode, never both. Driven from
        /// UpdateBuildEnabled so it always matches the Build gate.
        /// </summary>
        private void UpdateRequiredCues()
        {
            bool passwordOff = ChkKeyOnly.IsChecked == true;
            string pw = CurrentPassword();
            string confirm = CurrentConfirm();

            bool needFirmware = _fwzPath == null;
            bool needOutput = _outputPath == null;
            bool needPassword = !passwordOff && pw.Length == 0;
            // Confirm becomes relevant only once a password is entered (password mode):
            // amber while it is still blank, red while it is filled but doesn't match.
            bool needConfirm = !passwordOff && pw.Length > 0 && confirm.Length == 0;
            bool confirmMismatch = !passwordOff && pw.Length > 0 && confirm.Length > 0 && pw != confirm;
            bool needKey = passwordOff && _keyPath == null;

            SetFieldBorder(TxtFwzPath, needFirmware ? NeededBrush : null);
            // Output is disabled until a firmware is chosen; only cue it once usable.
            SetFieldBorder(TxtOutputPath, needOutput && _fwzPath != null ? NeededBrush : null);
            SetFieldBorder(TxtPassword, needPassword ? NeededBrush : null);
            SetFieldBorder(TxtConfirm, needConfirm ? NeededBrush : confirmMismatch ? ErrorBrush : null);
            SetFieldBorder(TxtKeyPath, needKey ? NeededBrush : null);

            // "(required)" placeholders: on the password while it is blank, and on
            // confirm only once a password has been typed (mirrors needPassword/needConfirm).
            PhPassword.Visibility = needPassword ? Visibility.Visible : Visibility.Collapsed;
            PhConfirm.Visibility = needConfirm ? Visibility.Visible : Visibility.Collapsed;

            // Mirror every visual cue into the accessibility tree so a screen reader
            // announces the required / mismatch state when the field takes focus — the
            // colour and "(required)" overlay are never the only signal (WCAG 1.4.1 /
            // 1.3.1). The base names double as the (otherwise unassociated) field labels.
            AutomationProperties.SetName(TxtFwzPath, needFirmware ? "Firmware, required" : "Firmware");
            AutomationProperties.SetName(TxtOutputPath,
                needOutput && _fwzPath != null ? "Save output as, required" : "Save output as");
            AutomationProperties.SetName(TxtPassword, needPassword ? "Root Password, required" : "Root Password");
            AutomationProperties.SetName(TxtConfirm,
                needConfirm ? "Confirm Password, required"
                : confirmMismatch ? "Confirm Password, does not match the password"
                : "Confirm Password");
            AutomationProperties.SetName(TxtKeyPath, needKey ? "SSH Public Key, required" : "SSH Public Key");

            // Each clear/erase button is only useful when its field holds something to
            // clear — disable it while the path is empty (and while an op is running).
            BtnClearFwz.IsEnabled = _uiEnabled && _fwzPath != null;
            BtnClearKey.IsEnabled = _uiEnabled && _keyPath != null;
            BtnClearOutput.IsEnabled = _uiEnabled && _outputPath != null;

            var missing = new List<string>();
            if (needFirmware) missing.Add("firmware");
            if (needOutput && _fwzPath != null) missing.Add("output path");
            if (needPassword) missing.Add("a root password");
            if (needConfirm) missing.Add("confirm the password");
            if (needKey) missing.Add("an SSH key");

            string previousHint = TxtBuildHint.Text;
            if (!_uiEnabled)
            {
                // An operation is running. The Build button itself shows the progress
                // ("⏳ Building…"), so keep the hint blank — no duplicated info.
                TxtBuildHint.Text = "";
            }
            else if (confirmMismatch)
            {
                // A concrete error takes priority over the "still needed" list.
                string prefix = missing.Count > 0 ? "Still needed: " + string.Join(", ", missing) + " — " : "";
                TxtBuildHint.Text = prefix + "passwords don't match.";
                TxtBuildHint.Foreground = ErrorBrush;
            }
            else if (missing.Count == 0)
            {
                TxtBuildHint.Text = "✓ Ready to build.";
                TxtBuildHint.Foreground = ReadyBrush;
            }
            else
            {
                TxtBuildHint.Text = "Still needed: " + string.Join(", ", missing) + ".";
                TxtBuildHint.Foreground = Brushes.Gray;
            }

            // The hint is a Polite live region (XAML), but WPF still needs the peer to
            // raise the change event for it to be announced. Only do this when an
            // assistive client is actually listening (ListenerExists) — then get or,
            // if the peer hasn't been created yet, create it, so a running screen
            // reader still hears the change. Fire only on an actual text change.
            if (!string.Equals(previousHint, TxtBuildHint.Text, StringComparison.Ordinal) &&
                AutomationPeer.ListenerExists(AutomationEvents.LiveRegionChanged))
            {
                var peer = FrameworkElementAutomationPeer.FromElement(TxtBuildHint)
                    ?? FrameworkElementAutomationPeer.CreatePeerForElement(TxtBuildHint);
                peer?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
            }

            // Reveal/copy availability depends on the same password/confirm content.
            UpdatePasswordButtonStates();
        }

        /// <summary>Sets (or clears, when <paramref name="brush"/> is null) a 2px cue border on a field.</summary>
        private static void SetFieldBorder(Control field, Brush? brush)
        {
            if (brush != null)
            {
                field.BorderBrush = brush;
                field.BorderThickness = new Thickness(2);
            }
            else
            {
                field.ClearValue(Control.BorderBrushProperty);
                field.ClearValue(Control.BorderThicknessProperty);
            }
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

            FwzBuildResult? built = null;
            string? buildError = null;
            await RunAndShow(sb, () =>
            {
                try
                {
                    // No build-time re-hash here: BuildModifiedFwz performs the
                    // authoritative whitelist verification (size + SHA-256) itself,
                    // atomically under the input file lock — the TOCTOU-safe place to
                    // do it. A second ~100 MB hash here would only slow every build
                    // without adding safety. It throws a clear error if the input is
                    // not a recognized original, which RunAndShow surfaces.
                    FwzBuildResult r = FwzProbe.BuildModifiedFwz(fwz, opts, output);
                    built = r;
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
                }
                catch (Exception ex)
                {
                    buildError = ex.Message;   // for the popup
                    throw;                     // let RunAndShow log full details to the console
                }
            }, BtnBuild);

            // Report the outcome in a popup. Advanced stays exactly as the user left
            // it — a build never opens (or closes) it; the full log is in Advanced →
            // Result if they want it.
            if (buildError != null)
            {
                MessageBox.Show(this,
                    "The build could not be completed:\n\n" + buildError +
                    "\n\nOpen Advanced → Result for the full log.",
                    "Build failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else if (built?.RoundTripAllPass == true)
            {
                MessageBox.Show(this,
                    "✅ The modified firmware was built and verified successfully.\n\n" +
                    "Saved to:\n" + built.OutputPath + "\n\nThe process is finished.",
                    "Build complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show(this,
                    "Some verification checks did not pass, so the modified firmware was NOT written.\n\n" +
                    "Open Advanced → Result to see which checks failed.",
                    "Build not written", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
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
        private async Task RunAndShow(StringBuilder sb, Action work, Button? busyButton = null)
        {
            // Note: we deliberately do NOT open Advanced here. Verify/Self-test are
            // launched from an already-open Advanced surface (their buttons live
            // there), and Build must not force Advanced open — it reports its outcome
            // in a popup instead.
            SetButtonsEnabled(false);
            if (busyButton != null) SetButtonBusy(busyButton, true);
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
                if (busyButton != null) SetButtonBusy(busyButton, false);
            }
            TxtResult.Text = sb.ToString();
        }

        // Idle content of a button currently showing the busy state, so it can be
        // restored when the operation finishes; and the timer driving the dots.
        private readonly Dictionary<Button, object?> _idleContent = new();
        private DispatcherTimer? _buildDots;

        /// <summary>
        /// While busy, turns the button into a non-interactive "loading" button: it
        /// keeps its full colour so the label stays readable (unlike the greyed-out
        /// disabled look), but can't be clicked or focused, and its label animates
        /// "⏳ Building." → ".." → "..." once per second. Restored when the op finishes.
        /// </summary>
        private void SetButtonBusy(Button button, bool busy)
        {
            if (busy)
            {
                if (!_idleContent.ContainsKey(button)) _idleContent[button] = button.Content;
                // Loading button: full colour + readable, but not clickable/focusable
                // (SetButtonsEnabled disabled it a moment ago; re-enable the visuals).
                button.IsEnabled = true;
                button.IsHitTestVisible = false;
                button.Focusable = false;

                // Keep the WORD "Building" centered in the button: it sits in the
                // middle column, with the ⏳ emoji in an equal-width left column and
                // the dots in an equal-width right column. Equal side columns keep
                // "Building" centered while the emoji stays left and the dots grow
                // right, none of which shifts the word.
                var emoji = new TextBlock { Text = "⏳", VerticalAlignment = VerticalAlignment.Center,
                                            HorizontalAlignment = HorizontalAlignment.Right,
                                            Margin = new Thickness(0, 0, 5, 0) };
                var baseText = new TextBlock { Text = "Building", VerticalAlignment = VerticalAlignment.Center };
                var dotsText = new TextBlock { VerticalAlignment = VerticalAlignment.Center,
                                               HorizontalAlignment = HorizontalAlignment.Left };
                var grid = new Grid();
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(26) }); // ⏳ (left)
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });    // "Building"
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(26) }); // dots (right)
                Grid.SetColumn(emoji, 0);
                Grid.SetColumn(baseText, 1);
                Grid.SetColumn(dotsText, 2);
                grid.Children.Add(emoji);
                grid.Children.Add(baseText);
                grid.Children.Add(dotsText);
                button.Content = grid;

                int dots = 0;
                _buildDots = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
                _buildDots.Tick += (_, _) =>
                {
                    dots = (dots + 1) % 4;   // 0 → 1 → 2 → 3 → 0 …  ("" . .. ...)
                    dotsText.Text = new string('.', dots);
                };
                _buildDots.Start();
            }
            else
            {
                _buildDots?.Stop();
                _buildDots = null;
                button.IsHitTestVisible = true;
                button.Focusable = true;
                if (_idleContent.TryGetValue(button, out var idle))
                {
                    button.Content = idle;
                    _idleContent.Remove(button);
                }
                // IsEnabled is restored by SetButtonsEnabled/UpdateBuildEnabled next.
            }
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

            // The firmware and key path boxes are click-to-browse controls, so they
            // must be disabled during an operation too — otherwise they would look
            // active (hand cursor, focusable) while doing nothing.
            TxtFwzPath.IsEnabled = enabled;
            TxtKeyPath.IsEnabled = enabled;
            BtnGenKey.IsEnabled = enabled;
            // The output row stays disabled until a firmware is chosen.
            TxtOutputPath.IsEnabled = enabled && _fwzPath != null;
            LblOutput.IsEnabled = enabled && _fwzPath != null;
            BtnVerify.IsEnabled = enabled;
            BtnSelfTest.IsEnabled = enabled;
            // The three clear buttons are content-aware (enabled only when their field
            // has something to clear); UpdateBuildEnabled below drives them from the
            // current paths + _uiEnabled, so they aren't set here.

            // Also lock the credential inputs during an operation so the visible UI
            // can't drift from the values snapshotted for the build. When
            // re-enabling, respect the Disable (key-only) state.
            bool passwordOff = ChkKeyOnly.IsChecked == true;
            bool creds = enabled && !passwordOff;
            ChkKeyOnly.IsEnabled = enabled;
            TxtPassword.IsEnabled = creds;
            TxtConfirm.IsEnabled = creds;
            // Refresh the Build gate, the "still needed" hint/cues, and the content-
            // aware reveal/copy/generate buttons so they all reflect the new op state
            // (UpdateBuildEnabled gates Build on _uiEnabled; the hint blanks while busy).
            _uiEnabled = enabled;
            UpdateBuildEnabled();
        }

        // Whether the UI is currently interactive (false during a build/verify op).
        private bool _uiEnabled = true;

        /// <summary>
        /// Enables the password action buttons by what is actually present:
        /// • Reveal (eye) needs at least one of the password/confirm fields to have
        ///   text — nothing to reveal otherwise.
        /// • Copy needs a confirmed, MATCHING password: blank → nothing to copy;
        ///   mismatch → ambiguous which line the user means, so it must match first.
        /// • Generate is always available while password login is on.
        /// All gated by password-login mode and whether the UI is interactive.
        /// </summary>
        private void UpdatePasswordButtonStates()
        {
            bool active = _uiEnabled && ChkKeyOnly.IsChecked != true;
            string pw = CurrentPassword();
            string confirm = CurrentConfirm();

            BtnRandomPwd.IsEnabled = active;
            BtnToggleReveal.IsEnabled = active && (pw.Length > 0 || confirm.Length > 0);
            BtnCopyPwd.IsEnabled = active && pw.Length > 0 && pw == confirm;
        }
    }
}
