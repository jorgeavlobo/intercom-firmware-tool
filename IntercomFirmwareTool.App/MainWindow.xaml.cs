using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using IntercomFirmwareTool.App.Localization;
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

        // True after a firmware was rejected (invalid): keeps the firebrick "(no valid
        // firmware selected)" cue across a language switch instead of reverting to the
        // neutral placeholder, which would make a rejected file look merely unselected.
        private bool _fwzRejected;

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
            // Pick the UI language (saved choice → system language → English) BEFORE the
            // visual tree is built, so every {loc:Loc} binding resolves in that language.
            LocalizationManager.Instance.Initialize();
            InitializeComponent();
            // Re-apply imperatively-set localized text whenever the language changes.
            LocalizationManager.Instance.LanguageChanged += (_, _) => ApplyLanguage();
            BuildLanguageMenu();
            RefreshPlaceholders();
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

            // Optional MQTT bridge (Advanced): wire its masked password field before
            // the first UpdateBuildEnabled below reads it. Everything else in the MQTT
            // section is inert until the user ticks "Install MQTT bridge".
            InitMqttUi();

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
            _revealOn = on;
            BtnToggleReveal.Content = on ? EyeHide : EyeShow;
            string hint = on ? L("Tip_RevealRelease") : L("Tip_RevealHold");
            BtnToggleReveal.ToolTip = hint;
            // Keep the screen-reader name in sync with the state, not just the
            // tooltip — otherwise it always announces the initial "Hold to show".
            AutomationProperties.SetName(BtnToggleReveal, hint);
        }

        private DispatcherTimer? _flashTimer;
        private bool _revealOn;

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
                SetStatus(() => L("Status_NothingToCopy"));
                return;
            }
            try
            {
                // Copy WITHOUT leaving the plaintext password in Windows Clipboard
                // History or cloud clipboard sync (see SecureClipboard).
                SecureClipboard.SetText(pwd);
                SetStatus(() => L("Status_Copied"));
            }
            catch (Exception ex)
            {
                SetStatus(() => LF("Fmt_CopyFailed", SafeMessage(ex)), error: true);
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

            SetResult(() => L("Result_RandomPwd"));
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
                Title = L("Dlg_ChooseFirmware_Title"),
                Filter = L("Dlg_FirmwareFilter"),
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
            SetStatus(() => L("Status_Verifying")); // visible while it hashes
            TxtResult.Text = LF("Fmt_Result_Verifying", chosen);
            FirmwareCheckResult check;
            try { check = await Task.Run(() => FirmwareRegistry.Verify(chosen)); }
            catch (Exception ex)
            {
                // Never let an exception escape this async void handler (it would
                // crash the dispatcher); turn it into a normal rejection below.
                string em = SafeMessage(ex);
                check = new FirmwareCheckResult(false, null, () => LF("Fmt_VerifyFailed", em));
            }
            finally { SetButtonsEnabled(true); }

            if (!check.Ok)
            {
                // Reject and DE-SELECT: no build is allowed on an unrecognized or
                // unmodifiable file.
                _fwzPath = null;
                _outputPath = null;
                _fwzRejected = true;
                TxtFwzPath.Text = L("Ph_Firmware_Invalid");
                TxtFwzPath.Foreground = Brushes.Firebrick;
                TxtOutputPath.Text = L("Ph_Output");
                TxtOutputPath.Foreground = Brushes.Gray;
                LblOutput.IsEnabled = false;
                TxtOutputPath.IsEnabled = false;
                UpdateBuildEnabled();

                SetResult(() => LF("Fmt_Result_Rejected", check.Message));
                SetStatus(""); // the popup below is the feedback; clear the "verifying…" line
                MessageBox.Show(this,
                    LF("Fmt_Msg_FirmwareNotAccepted", check.Message),
                    L("Cap_FirmwareNotAccepted"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Accepted: record the path and enable the output row (BtnClearOutput is
            // driven by UpdateBuildEnabled once _outputPath is set, below).
            _fwzPath = chosen;
            _fwzRejected = false;
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

            SetResult(() => LF("Fmt_Result_Accepted", check.Message, check.Match!.Describe()));
            SetStatus(() => L("Status_FirmwareVerified")); // visible confirmation in the simple view
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
            _fwzRejected = false;
            TxtFwzPath.Text = L("Ph_Firmware");
            TxtFwzPath.Foreground = Brushes.Gray;
            TxtOutputPath.Text = L("Ph_Output");
            TxtOutputPath.Foreground = Brushes.Gray;
            LblOutput.IsEnabled = false;
            TxtOutputPath.IsEnabled = false;
            SetStatus(""); // don't leave "✓ Firmware verified." while nothing is selected
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
                Title = L("Dlg_ChooseKey_Title"),
                Filter = L("Dlg_KeyFilter"),
                InitialDirectory = DefaultSshDir()
            };
            if (dlg.ShowDialog(this) != true) return;

            // Validate on selection so bad input is caught here, not at Build time.
            string chosen = dlg.FileName;
            string content;
            try { content = File.ReadAllText(chosen).Trim(); }
            catch (Exception ex)
            {
                MessageBox.Show(this, LF("Fmt_Msg_ReadKeyFailed", SafeMessage(ex)),
                    L("Cap_CannotReadKey"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (content.Length == 0 || !SshKeyGen.IsLikelyPublicKey(content))
            {
                MessageBox.Show(this,
                    L("Msg_NotPublicKey_Choose"),
                    L("Cap_NotPublicKey"), MessageBoxButton.OK, MessageBoxImage.Warning);
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
                Title = L("Dlg_SaveKey_Title"),
                Filter = L("Dlg_SaveKeyFilter"),
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
            foreach (var (label, p) in new[] { (L("CollisionLabel_Input"), _fwzPath), (L("CollisionLabel_Output"), _outputPath), (L("CollisionLabel_Key"), _keyPath) })
            {
                if (p != null && (SamePath(privatePath, p) || SamePath(pubDest, p)))
                {
                    MessageBox.Show(this,
                        LF("Fmt_Msg_KeyCollision", label, p),
                        L("Cap_PathCollision"), MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
            }

            // The Save dialog only prompted about the private-key path; confirm
            // the sibling .pub too, since generating overwrites it.
            if (File.Exists(pubDest))
            {
                var ans = MessageBox.Show(this,
                    LF("Fmt_Msg_PubExists", pubDest),
                    L("Cap_PubExists"), MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (ans != MessageBoxResult.Yes) return;
            }

            string comment = $"{Environment.UserName}@{Environment.MachineName}";

            SetButtonsEnabled(false);
            SetStatus(() => L("Status_GenKey")); // visible (KeyRow can be shown without the console)
            TxtResult.Text = L("Result_GeneratingKey");
            string? pubPath = null;
            string? error = null;    // full detail for the result log
            string? errorMsg = null; // short message for the popup
            try
            {
                pubPath = await Task.Run(() => SshKeyGen.Generate(privatePath, comment));
            }
            catch (Exception ex)
            {
                error = ex.ToString();
                errorMsg = SafeMessage(ex);
            }
            finally
            {
                SetButtonsEnabled(true);
            }

            if (error != null || pubPath is null)
            {
                SetResult(() => LF("Fmt_Result_GenKeyFailed",
                    error ?? L("Result_GenKeyFailed_Unknown")));
                SetStatus(""); // the popup below is the feedback
                MessageBox.Show(this,
                    LF("Fmt_Msg_GenKeyFailed", errorMsg ?? L("Msg_GenKeyFailed_Unknown")),
                    L("Cap_GenKeyFailed"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _keyPath = pubPath;
            SetPathText(TxtKeyPath, pubPath);
            SetStatus(() => L("Status_KeyGenerated")); // visible confirmation
            UpdateBuildEnabled();

            // Lock the private key to the current Windows account (best-effort):
            // OpenSSH refuses a world-readable key, and other local users must not
            // read it. The UI keeps the manual command as a fallback.
            bool restricted = RestrictKeyToCurrentUser(privatePath);

            // Report exactly what was generated so the user can see and verify it:
            // the key type/size and the SHA-256 fingerprint (same value that
            // `ssh-keygen -lf <file>.pub` prints).
            string? keyLabel = null, keyFingerprint = null;
            try
            {
                var info = SshKeyGen.DescribePublicKey(File.ReadAllText(pubPath));
                if (info != null) { keyLabel = info.Label; keyFingerprint = info.Sha256Fingerprint; }
            }
            catch { /* details are informational; never block on them */ }

            SetResult(() => BuildKeyCreatedResult(privatePath, pubPath, keyLabel, keyFingerprint, restricted));

            MessageBox.Show(this,
                LF("Fmt_Msg_KeyCreated", privatePath, pubPath),
                L("Cap_NewSshKey"), MessageBoxButton.OK, MessageBoxImage.Information);
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
                Title = L("Dlg_SaveOutput_Title"),
                Filter = L("Dlg_FirmwareFilter"),
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
                    L("Msg_CannotOverwriteInput"),
                    L("Cap_CannotOverwriteInput"), MessageBoxButton.OK, MessageBoxImage.Warning);
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
            TxtOutputPath.Text = L("Ph_Output");
            TxtOutputPath.Foreground = Brushes.Gray;
            UpdateBuildEnabled();
        }

        /// <summary>Clears the selected SSH key so the build uses the password only.</summary>
        private void BtnClearKey_Click(object sender, RoutedEventArgs e)
        {
            _keyPath = null;
            SetStatus(""); // don't leave a "✓ SSH key…" message after clearing the key
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
                ? L("Ph_Key_Required")
                : L("Ph_Key_Optional");
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

        // Toggling the OTA-block option just recomputes visibility, so an unticked
        // box doesn't linger visible after Advanced is collapsed (it stays visible
        // while ticked, like the MQTT/key rows). No build-enable impact — the option
        // is independent and never gates Build.
        private void ChkBlockUpdates_Toggled(object sender, RoutedEventArgs e)
            => UpdateAdvancedVisibility();

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
                TxtPwdHint.Text = L("PwdHint_Disabled");
                TxtPwdHint.Foreground = Brushes.Gray;
                return;
            }
            if (CurrentPassword().Length == 0 && CurrentConfirm().Length == 0)
            {
                TxtPwdHint.Text = "";
                return;
            }
            bool match = CurrentPassword() == CurrentConfirm();
            TxtPwdHint.Text = match ? L("PwdHint_Match") : L("PwdHint_Mismatch");
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
                && _fwzPath != null && _outputPath != null && HaveCredential()
                && MqttOkToBuild();
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
            LblPassword.Text = advanced ? L("Field_Password_Advanced") : L("Field_Password_Simple");
            // In key-only mode the password fields are disabled and the SSH key is the
            // required credential, so the rule reflects that instead.
            LblCredentialRule.Text = keyOnly
                ? L("Rule_KeyOnly")
                : advanced
                    ? L("Rule_Advanced")
                    : L("Rule_Simple");

            KeyRow.Visibility = (advanced || keyOnly || _keyPath != null)
                ? Visibility.Visible : Visibility.Collapsed;

            AdvancedTools.Visibility = advanced ? Visibility.Visible : Visibility.Collapsed;

            // The OTA-block option lives in Advanced too; like the MQTT/key rows it
            // stays visible while ticked so an active build option isn't hidden by the
            // toggle, and locks with the other inputs during a build.
            BlockUpdatesSection.Visibility = (advanced || ChkBlockUpdates.IsChecked == true)
                ? Visibility.Visible : Visibility.Collapsed;
            ChkBlockUpdates.IsEnabled = _uiEnabled;

            // The optional MQTT bridge section lives in Advanced too; it stays visible
            // while enabled so an active build option isn't hidden by the toggle.
            UpdateMqttVisibility(advanced);

            // The result output is part of Advanced. The body scrolls (a page-level
            // ScrollViewer) and the footer is pinned outside it, so the result box no
            // longer needs star/spacer row juggling to stay reachable — it just shows
            // or hides with Advanced (its own MaxHeight bounds a long log).
            ResultGroup.Visibility = advanced ? Visibility.Visible : Visibility.Collapsed;
        }

        private double? _heightBeforeAdvanced;
        private double? _topBeforeAdvanced;

        /// <summary>
        /// Shows a short message in the always-visible status line under the Build
        /// button (collapsed when empty). Used for simple-view feedback that would
        /// otherwise only reach the result console, which is hidden in the simple view.
        /// </summary>
        // The status line is rebuildable in any language: a render closure regenerates
        // it (null = cleared), so ApplyLanguage re-renders it after a switch.
        private Func<string>? _statusRender;
        private bool _statusError;

        /// <summary>Sets a fixed status message (empty string clears/hides the line).</summary>
        private void SetStatus(string message, bool error = false)
            => SetStatus(string.IsNullOrEmpty(message) ? null : () => message, error);

        /// <summary>
        /// Shows a localized status message that re-renders on a language switch. Pass
        /// a closure that produces the message in the current language.
        /// </summary>
        private void SetStatus(Func<string>? render, bool error = false)
        {
            _statusRender = render;
            _statusError = error;
            RenderStatus();
        }

        /// <summary>(Re)draws the status line from the current render closure.</summary>
        private void RenderStatus()
        {
            string message = _statusRender?.Invoke() ?? "";
            TxtStatus.Text = message;
            TxtStatus.Foreground = _statusError ? ErrorBrush : Brushes.Gray;
            TxtStatus.Visibility = string.IsNullOrEmpty(message)
                ? Visibility.Collapsed : Visibility.Visible;
            // The status line is a Polite live region (XAML); announce the change so a
            // screen reader hears it (LiveSetting alone is inert — see AnnounceLiveRegion).
            if (!string.IsNullOrEmpty(message)) AnnounceLiveRegion(TxtStatus);
        }

        /// <summary>
        /// Raises LiveRegionChanged on a Polite live-region element so assistive tech
        /// actually announces a text change (WPF needs the peer to raise it). No-op
        /// unless an automation client is listening; creates the peer if needed.
        /// </summary>
        private static void AnnounceLiveRegion(FrameworkElement element)
        {
            if (!AutomationPeer.ListenerExists(AutomationEvents.LiveRegionChanged)) return;
            var peer = FrameworkElementAutomationPeer.FromElement(element)
                ?? FrameworkElementAutomationPeer.CreatePeerForElement(element);
            peer?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
        }

        /// <summary>A user-facing message for an exception: its Message, or the
        /// exception type name when Message is empty (some exceptions have none), so a
        /// popup is never blank.</summary>
        private static string SafeMessage(Exception ex) =>
            string.IsNullOrWhiteSpace(ex.Message) ? ex.GetType().Name : ex.Message;

        // ---- Localization ----------------------------------------------------

        /// <summary>Look up a localized string by key.</summary>
        private static string L(string key) => LocalizationManager.Instance.Get(key);

        /// <summary>Look up a localized format string by key and fill it in the current culture.</summary>
        private static string LF(string key, params object?[] args) => LocalizationManager.Instance.Format(key, args);

        /// <summary>
        /// Re-applies every imperatively-set localized string after a runtime language
        /// change. XAML {loc:Loc} bindings update themselves; this covers the text set
        /// from code (placeholders, hints, credential rule, password label, a11y names).
        /// </summary>
        private void ApplyLanguage()
        {
            RefreshPlaceholders();
            RefreshRevealTooltip();
            UpdatePasswordHint();
            UpdateBuildEnabled();       // password label, credential rule, cues, hint, a11y names
            UpdateLanguageMenuHeader();
            // SetButtonBusy swaps BtnBuild.Content for the busy visual, dropping its
            // {loc:Loc} binding; re-apply the label so a language change after a build
            // still updates it (skip while a build is running — the busy visual owns it).
            if (!string.Equals(BtnBuild.Tag as string, "busy", StringComparison.Ordinal))
                BtnBuild.Content = L("Btn_Build");
            // Re-render the Result console from the active operation's render closure
            // (or the localized default when no operation output is showing).
            TxtResult.Text = _resultRender != null ? _resultRender() : L("Result_Default");
            // The always-visible status line re-renders too.
            RenderStatus();
        }

        /// <summary>Sets the neutral placeholder on any path box that has no selection.</summary>
        private void RefreshPlaceholders()
        {
            if (_fwzPath == null)
            {
                // Preserve the rejected-firmware cue (firebrick) across a language
                // switch; otherwise show the neutral "click to choose" placeholder.
                if (_fwzRejected) { TxtFwzPath.Text = L("Ph_Firmware_Invalid"); TxtFwzPath.Foreground = Brushes.Firebrick; }
                else { TxtFwzPath.Text = L("Ph_Firmware"); TxtFwzPath.Foreground = Brushes.Gray; }
            }
            if (_outputPath == null) { TxtOutputPath.Text = L("Ph_Output"); TxtOutputPath.Foreground = Brushes.Gray; }
            UpdateKeyPlaceholder();
            RefreshMqttPlaceholders();
        }

        /// <summary>Re-applies the hold/release reveal tooltip + a11y name in the current language.</summary>
        private void RefreshRevealTooltip()
        {
            string hint = _revealOn ? L("Tip_RevealRelease") : L("Tip_RevealHold");
            BtnToggleReveal.ToolTip = hint;
            AutomationProperties.SetName(BtnToggleReveal, hint);
        }

        // ---- Language menu (globe, top-right) --------------------------------

        /// <summary>Populates the globe menu with one item per shipped language.</summary>
        private void BuildLanguageMenu()
        {
            foreach (var lang in LocalizationManager.Languages)
            {
                var item = new MenuItem { Header = lang.NativeName, IsCheckable = true, Tag = lang.Code };
                item.Click += LangItem_Click;
                LangMenuRoot.Items.Add(item);
            }
            UpdateLanguageMenuHeader();
        }

        private void LangItem_Click(object sender, RoutedEventArgs e)
        {
            if (sender is MenuItem mi && mi.Tag is string code)
                LocalizationManager.Instance.SetLanguage(code);
        }

        /// <summary>Refreshes the globe header (current native name) and the tick on the active language.</summary>
        private void UpdateLanguageMenuHeader()
        {
            string current = LocalizationManager.Instance.CurrentCode;
            string nativeName = LocalizationManager.Languages
                .FirstOrDefault(l => l.Code == current)?.NativeName ?? "English";

            var header = new StackPanel { Orientation = Orientation.Horizontal };
            header.Children.Add(new TextBlock
            {
                Text = "", // Segoe MDL2 Assets: Globe
                FontFamily = new FontFamily("Segoe MDL2 Assets"),
                FontSize = 14,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0)
            });
            header.Children.Add(new TextBlock { Text = nativeName, VerticalAlignment = VerticalAlignment.Center });
            LangMenuRoot.Header = header;

            foreach (var obj in LangMenuRoot.Items)
                if (obj is MenuItem mi && mi.Tag is string code)
                    mi.IsChecked = code == current;
        }

        /// <summary>Toggles the advanced surface (SSH key row + tool buttons + result).</summary>
        private void TglAdvanced_Changed(object sender, RoutedEventArgs e)
        {
            // Refresh visibility AND the mode-dependent cues (build hint wording,
            // AutomationProperties.Name) so toggling Advanced alone can't leave them
            // stale. UpdateBuildEnabled runs both UpdateRequiredCues and
            // UpdateAdvancedVisibility.
            UpdateBuildEnabled();
            if (TglAdvanced.IsChecked == true)
            {
                // Opening: remember the current size/position, then grow so the result
                // output has room (only if we haven't already grown for this session).
                if (_heightBeforeAdvanced == null)
                {
                    _heightBeforeAdvanced = Height;
                    _topBeforeAdvanced = Top;

                    // Work area of the monitor THIS window is on (not the primary —
                    // SystemParameters.WorkArea only ever reports the primary display,
                    // which would push us off-screen on a secondary monitor offset
                    // above/below it). Falls back to the primary work area if the
                    // native query is unavailable.
                    Rect wa = CurrentMonitorWorkArea();
                    double want = Math.Min(720, wa.Height);
                    if (Height < want) Height = want;
                    // The window's Top didn't change, so growing downward could push the
                    // footer off-screen. Nudge Top up so the whole window stays within
                    // this monitor's work area.
                    if (Top + Height > wa.Bottom) Top = Math.Max(wa.Top, wa.Bottom - Height);
                }
            }
            else if (_heightBeforeAdvanced != null)
            {
                // Closing: restore the size AND position from before Advanced was opened.
                Height = _heightBeforeAdvanced.Value;
                if (_topBeforeAdvanced != null) Top = _topBeforeAdvanced.Value;
                _heightBeforeAdvanced = null;
                _topBeforeAdvanced = null;
            }
        }

        /// <summary>
        /// Work area (excluding the taskbar) of the monitor that currently contains
        /// this window, in device-independent units so it can be compared to
        /// Top/Left/Height/Width directly. Unlike <see cref="SystemParameters.WorkArea"/>
        /// — which always describes the PRIMARY monitor — this follows the window to a
        /// secondary display. Degrades to the primary work area if the window has no
        /// HWND yet or the native query fails, so callers never get a worse answer.
        /// </summary>
        private Rect CurrentMonitorWorkArea()
        {
            try
            {
                IntPtr hwnd = new WindowInteropHelper(this).Handle;
                if (hwnd == IntPtr.Zero) return SystemParameters.WorkArea;

                IntPtr monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
                var mi = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
                if (monitor == IntPtr.Zero || !GetMonitorInfo(monitor, ref mi))
                    return SystemParameters.WorkArea;

                // rcWork is in physical pixels (virtual-screen coords). Convert to DIPs
                // with the window's own device transform — a pure scale, so applying it
                // to screen coordinates yields the DIP space WPF uses for Top/Left.
                Matrix fromDevice = PresentationSource.FromVisual(this)?.CompositionTarget?
                    .TransformFromDevice ?? Matrix.Identity;
                Point tl = fromDevice.Transform(new Point(mi.rcWork.left, mi.rcWork.top));
                Point br = fromDevice.Transform(new Point(mi.rcWork.right, mi.rcWork.bottom));
                return new Rect(tl, br);
            }
            catch
            {
                // Never let a layout tweak fault — fall back to the primary work area.
                return SystemParameters.WorkArea;
            }
        }

        private const uint MONITOR_DEFAULTTONEAREST = 2;

        [DllImport("user32.dll")]
        private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT { public int left, top, right, bottom; }

        [StructLayout(LayoutKind.Sequential)]
        private struct MONITORINFO
        {
            public int cbSize;
            public RECT rcMonitor;
            public RECT rcWork;
            public uint dwFlags;
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
            // MQTT bridge (optional): the broker host is required when the bridge is on;
            // the port and the both-or-neither / TLS rules surface as a build error.
            bool needMqttHost = MqttEnabled && TxtMqttHost.Text.Trim().Length == 0;
            bool mqttPortBad = MqttEnabled && !IsValidPortText(TxtMqttPort.Text);
            string? mqttError = MqttStructuralError();

            SetFieldBorder(TxtFwzPath, needFirmware ? NeededBrush : null);
            // Output is disabled until a firmware is chosen; only cue it once usable.
            SetFieldBorder(TxtOutputPath, needOutput && _fwzPath != null ? NeededBrush : null);
            SetFieldBorder(TxtPassword, needPassword ? NeededBrush : null);
            SetFieldBorder(TxtConfirm, needConfirm ? NeededBrush : confirmMismatch ? ErrorBrush : null);
            SetFieldBorder(TxtKeyPath, needKey ? NeededBrush : null);
            SetFieldBorder(TxtMqttHost, needMqttHost ? NeededBrush : null);
            SetFieldBorder(TxtMqttPort, mqttPortBad ? ErrorBrush : null);

            // "(required)" placeholders: on the password while it is blank, and on
            // confirm only once a password has been typed (mirrors needPassword/needConfirm).
            PhPassword.Visibility = needPassword ? Visibility.Visible : Visibility.Collapsed;
            PhConfirm.Visibility = needConfirm ? Visibility.Visible : Visibility.Collapsed;

            // Mirror every visual cue into the accessibility tree so a screen reader
            // announces the required / mismatch state when the field takes focus — the
            // colour and "(required)" overlay are never the only signal (WCAG 1.4.1 /
            // 1.3.1). The base names double as the (otherwise unassociated) field labels.
            AutomationProperties.SetName(TxtFwzPath, needFirmware ? LF("Fmt_Required", L("Name_Firmware")) : L("Name_Firmware"));
            AutomationProperties.SetName(TxtOutputPath,
                needOutput && _fwzPath != null ? LF("Fmt_Required", L("Name_Output")) : L("Name_Output"));
            // Match the visible label, which drops "Root" in the simple view.
            bool advanced = TglAdvanced.IsChecked == true;
            string pwLabel = advanced ? L("Name_Password_Advanced") : L("Name_Password_Simple");
            AutomationProperties.SetName(TxtPassword, needPassword ? LF("Fmt_Required", pwLabel) : pwLabel);
            AutomationProperties.SetName(TxtConfirm,
                needConfirm ? LF("Fmt_Required", L("Name_Confirm"))
                : confirmMismatch ? L("Name_Confirm_Mismatch")
                : L("Name_Confirm"));
            AutomationProperties.SetName(TxtKeyPath, needKey ? LF("Fmt_Required", L("Name_Key")) : L("Name_Key"));

            // Each clear/erase button is only useful when its field holds something to
            // clear — disable it while the path is empty (and while an op is running).
            BtnClearFwz.IsEnabled = _uiEnabled && _fwzPath != null;
            BtnClearKey.IsEnabled = _uiEnabled && _keyPath != null;
            BtnClearOutput.IsEnabled = _uiEnabled && _outputPath != null;

            var missing = new List<string>();
            if (needFirmware) missing.Add(L("Miss_Firmware"));
            if (needOutput && _fwzPath != null) missing.Add(L("Miss_Output"));
            if (needPassword) missing.Add(advanced ? L("Miss_Password_Advanced") : L("Miss_Password_Simple"));
            if (needConfirm) missing.Add(L("Miss_Confirm"));
            if (needKey) missing.Add(L("Miss_Key"));
            if (needMqttHost) missing.Add(L("Miss_Mqtt"));

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
                string prefix = missing.Count > 0 ? LF("Fmt_StillNeeded_Prefix", string.Join(", ", missing)) : "";
                TxtBuildHint.Text = prefix + L("Hint_Mismatch");
                TxtBuildHint.Foreground = ErrorBrush;
            }
            else if (mqttError != null)
            {
                // An MQTT misconfiguration (port range, both-or-neither, TLS/auth
                // rules) blocks the build the same way; show it after any still-needed
                // items so the user sees both.
                string prefix = missing.Count > 0 ? LF("Fmt_StillNeeded_Prefix", string.Join(", ", missing)) : "";
                TxtBuildHint.Text = prefix + mqttError;
                TxtBuildHint.Foreground = ErrorBrush;
            }
            else if (missing.Count == 0)
            {
                TxtBuildHint.Text = L("Hint_Ready");
                TxtBuildHint.Foreground = ReadyBrush;
            }
            else
            {
                TxtBuildHint.Text = LF("Fmt_StillNeeded", string.Join(", ", missing));
                TxtBuildHint.Foreground = Brushes.Gray;
            }

            // The hint is a Polite live region (XAML); announce it, but only on an
            // actual change to NON-empty text. Announcing "" (the hint is blanked
            // while a build runs) makes some screen readers say "blank" — SetStatus
            // follows the same rule.
            if (!string.IsNullOrEmpty(TxtBuildHint.Text) &&
                !string.Equals(previousHint, TxtBuildHint.Text, StringComparison.Ordinal))
                AnnounceLiveRegion(TxtBuildHint);

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
                        L("Msg_PasswordRequired"),
                        L("Cap_PasswordRequired"), MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (password != CurrentConfirm())
                {
                    MessageBox.Show(this,
                        L("Msg_PasswordMismatch"),
                        L("Cap_PasswordMismatch"), MessageBoxButton.OK, MessageBoxImage.Warning);
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
                    MessageBox.Show(this, LF("Fmt_Msg_CannotReadPubKey", SafeMessage(ex)),
                        L("Cap_CannotReadKey"), MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (publicKey.Length == 0)
                {
                    MessageBox.Show(this,
                        L("Msg_EmptyKey"),
                        L("Cap_EmptyKey"), MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (!SshKeyGen.IsLikelyPublicKey(publicKey))
                {
                    MessageBox.Show(this,
                        L("Msg_NotPublicKey_Build"),
                        L("Cap_NotPublicKey"), MessageBoxButton.OK, MessageBoxImage.Warning);
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
                        L("Msg_OutputCollidesKey"),
                        L("Cap_OutputCollidesKey"), MessageBoxButton.OK, MessageBoxImage.Warning);
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
                        L("Msg_KeyRequired"),
                        L("Cap_KeyRequired"), MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (SshKeyGen.KeyType(publicKey) != "ssh-rsa")
                {
                    MessageBox.Show(this,
                        L("Msg_RsaRequired"),
                        L("Cap_RsaRequired"), MessageBoxButton.OK, MessageBoxImage.Warning);
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
                    LF("Fmt_Msg_OutputIsPrivateKey", _outputPath),
                    L("Cap_OutputIsPrivateKey"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Never build over a selected MQTT TLS file: the build overwrites the
            // output path with the generated .fwz, which would destroy the CA/cert/key
            // on disk (its bytes are already in memory, but the file would be lost).
            // Mirror the SSH-key collision guard above.
            if (MqttEnabled)
            {
                foreach (var p in new[] { _mqttCaPath, _mqttCertPath, _mqttKeyPath })
                    if (p != null && SamePath(_outputPath!, p))
                    {
                        MessageBox.Show(this,
                            LF("Fmt_Msg_OutputCollidesMqtt", p),
                            L("Cap_OutputCollidesMqtt"), MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
            }

            // Confirm before overwriting an existing output file (the path may
            // have been auto-suggested, bypassing the Save dialog's own prompt).
            if (File.Exists(_outputPath))
            {
                var answer = MessageBox.Show(this,
                    LF("Fmt_Msg_FileExists", _outputPath),
                    L("Cap_FileExists"), MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (answer != MessageBoxResult.Yes) return;
            }

            SetStatus(""); // clear any stale status; the build reports via its popup
            var opts = new EnableSshOptions(password, publicKey,
                BlockFirmwareUpdates: ChkBlockUpdates.IsChecked == true);

            // Optional MQTT bridge: collect + validate its options (null when the
            // bridge is off). A file-read failure or invalid config shows a popup and
            // aborts before the build starts.
            if (!TryBuildMqttOptions(out MqttOptions? mqttOpts)) return;

            // Non-null here: guarded above (and Build is only enabled with firmware,
            // output and a credential set). They are fields, so the compiler re-widens
            // them to maybe-null after the intervening calls — assert with '!'.
            string fwz = _fwzPath!, output = _outputPath!;
            string? keyForLog = opts.HasKey ? _keyPath : null;

            FwzBuildResult? built = null;
            string? buildError = null;
            await RunAndShow(
                () =>
                {
                    // No build-time re-hash here: BuildModifiedFwz performs the
                    // authoritative whitelist verification (size + SHA-256) itself,
                    // atomically under the input file lock — the TOCTOU-safe place to
                    // do it. It throws a clear error if the input is not a recognized
                    // original, which RunAndShow surfaces.
                    try
                    {
                        built = FwzProbe.BuildModifiedFwz(fwz, opts, output, mqttOpts);
                    }
                    catch (Exception ex)
                    {
                        buildError = SafeMessage(ex);   // for the popup
                        throw;                          // let RunAndShow log full details
                    }
                },
                () => BuildBuildLog(fwz, output, opts, keyForLog, built!),
                () => BuildBuildHeaderText(fwz, output, opts, keyForLog),
                BtnBuild);

            // Report the outcome in a popup. Advanced stays exactly as the user left
            // it — a build never opens (or closes) it; the full log is in Advanced →
            // Result if they want it.
            if (buildError != null)
            {
                MessageBox.Show(this,
                    LF("Fmt_Msg_BuildFailed", buildError),
                    L("Cap_BuildFailed"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else if (built?.RoundTripAllPass == true)
            {
                MessageBox.Show(this,
                    LF("Fmt_Msg_BuildComplete", built.OutputPath),
                    L("Cap_BuildComplete"), MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show(this,
                    L("Msg_BuildNotWritten"),
                    L("Cap_BuildNotWritten"), MessageBoxButton.OK, MessageBoxImage.Warning);
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
                Title = L("Dlg_Inspect_Title"),
                Filter = L("Dlg_FirmwareFilter")
            };
            if (fwzDlg.ShowDialog(this) != true) return;
            string fwzPath = fwzDlg.FileName;

            SshInspectionReport? report = null;
            await RunAndShow(
                () => report = FwzProbe.InspectSshInFwz(fwzPath),
                () => BuildInspectLog(fwzPath, report!),
                () => BuildInspectHeaderText(fwzPath));
        }

        // ---- Secondary: MD5-crypt self-test ---------------------------------

        /// <summary>Runs the MD5-crypt self-test and shows the pass/fail result.</summary>
        private async void BtnSelfTest_Click(object sender, RoutedEventArgs e)
        {
            bool stAllPass = false;
            string stReport = "";
            await RunAndShow(
                () => { (stAllPass, stReport) = Md5Crypt.SelfTest(); },
                () => BuildSelfTestLog(stAllPass, stReport),
                () => L("Result_SelfTest_Head"));
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

        // ---- Localized result renderers (re-run on a language switch) ---------
        // Each builds a result's full console text from captured data + the current
        // language's templates, so ApplyLanguage can re-render it after a switch.

        private static void AppendBuildHeader(StringBuilder sb, string fwz, string output, EnableSshOptions opts, string? keyPath)
        {
            sb.AppendLine(L("Result_Build_Head"));
            sb.AppendLine(LF("Fmt_Result_Build_Input", fwz));
            sb.AppendLine(opts.HasPassword ? L("Result_Build_RootPw_Set") : L("Result_Build_RootPw_Disabled"));
            sb.AppendLine(opts.HasKey ? LF("Fmt_Result_Build_PubKey", keyPath) : L("Result_Build_PubKey_None"));
            if (opts.BlockFirmwareUpdates)
                sb.AppendLine(L("Result_Build_BlockUpdates_On"));
            sb.AppendLine(LF("Fmt_Result_Build_Output", output));
        }

        private static string BuildBuildHeaderText(string fwz, string output, EnableSshOptions opts, string? keyPath)
        {
            var sb = new StringBuilder();
            AppendBuildHeader(sb, fwz, output, opts, keyPath);
            return sb.ToString();
        }

        private static string BuildBuildLog(string fwz, string output, EnableSshOptions opts, string? keyPath, FwzBuildResult r)
        {
            var sb = new StringBuilder();
            AppendBuildHeader(sb, fwz, output, opts, keyPath);
            sb.AppendLine();
            sb.AppendLine(LF("Fmt_Result_ArchivePw", r.PasswordUsed));
            sb.AppendLine(LF("Fmt_Result_Build_ModifiedEntry", r.SelectedEntry));
            sb.AppendLine();
            sb.AppendLine(L("Result_Build_VerifyHeader"));
            AppendChecks(sb, r.RoundTripChecks);
            sb.AppendLine();
            if (r.RoundTripAllPass)
            {
                sb.AppendLine(L("Result_Build_Success"));
                sb.AppendLine(LF("Fmt_Result_Build_WrittenTo", r.OutputPath));
                sb.AppendLine();
                sb.AppendLine(L("Result_Build_FlashAdvisory"));
            }
            else
            {
                sb.AppendLine(L("Result_Build_FailChecks"));
                sb.AppendLine(LF("Fmt_Result_Build_FailUnchanged", output));
                sb.AppendLine(L("Result_Build_FailNoFlash"));
                sb.AppendLine(L("Result_Build_FailSeeAbove"));
            }
            return sb.ToString();
        }

        private static string BuildInspectHeaderText(string fwzPath)
        {
            var sb = new StringBuilder();
            sb.AppendLine(L("Result_Inspect_Head"));
            sb.AppendLine(LF("Fmt_Result_Inspect_File", fwzPath));
            return sb.ToString();
        }

        private static string BuildInspectLog(string fwzPath, SshInspectionReport r)
        {
            var sb = new StringBuilder();
            sb.AppendLine(L("Result_Inspect_Head"));
            sb.AppendLine(LF("Fmt_Result_Inspect_File", fwzPath));
            sb.AppendLine();
            sb.AppendLine(LF("Fmt_Result_ArchivePw", r.PasswordUsed));
            sb.AppendLine(LF("Fmt_Result_Inspect_InnerEntry", r.SelectedEntry));
            sb.AppendLine();
            sb.AppendLine(L("Result_Inspect_WhatsInside"));
            // Findings are factories, so they re-localize in the current culture too.
            foreach (var f in r.Findings) sb.AppendLine("  " + f());
            sb.AppendLine();
            sb.AppendLine(L("Result_Inspect_Checklist"));
            AppendChecks(sb, r.Checks);
            sb.AppendLine();
            sb.AppendLine(r.AllPass ? L("Result_Inspect_AllPass") : L("Result_Inspect_SomeFailed"));
            return sb.ToString();
        }

        private static string BuildSelfTestLog(bool allPass, string report)
        {
            var sb = new StringBuilder();
            sb.AppendLine(L("Result_SelfTest_Head"));
            sb.AppendLine();
            sb.Append(report);
            sb.AppendLine();
            sb.AppendLine(allPass ? L("Result_SelfTest_AllPass") : L("Result_SelfTest_SomeFailed"));
            return sb.ToString();
        }

        private static string BuildKeyCreatedResult(string privatePath, string pubPath, string? keyLabel, string? keyFingerprint, bool restricted)
        {
            var sb = new StringBuilder();
            sb.AppendLine(L("Result_KeyCreated_Header"));
            sb.AppendLine();
            sb.AppendLine(LF("Fmt_Result_KeyCreated_Priv", privatePath));
            sb.AppendLine(LF("Fmt_Result_KeyCreated_Pub", pubPath));
            if (keyLabel != null && keyFingerprint != null)
                sb.Append(LF("Fmt_Result_KeyDetails", keyLabel, keyFingerprint));
            sb.AppendLine();
            sb.AppendLine(LF("Fmt_Result_KeyCreated_Body", privatePath));
            sb.AppendLine();
            sb.Append(restricted
                ? L("Result_KeyCreated_Restricted")
                : LF("Fmt_Result_KeyCreated_NotRestricted", privatePath));
            return sb.ToString();
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

        // The Result console is rebuildable in any language: each operation stores a
        // render closure that regenerates its localized text from captured data, so a
        // language switch re-renders it (see ApplyLanguage). Null = show the default.
        private Func<string>? _resultRender;

        /// <summary>Records a result's render closure and shows it now.</summary>
        private void SetResult(Func<string> render)
        {
            _resultRender = render;
            TxtResult.Text = render();
        }

        /// <summary>
        /// Runs the work off the UI thread (so the window stays responsive) with the
        /// buttons disabled, then shows the localized result — or, on failure, the
        /// header plus the raw error. <paramref name="renderResult"/> and
        /// <paramref name="renderHeader"/> rebuild their text from captured data, so a
        /// later language switch re-renders the console.
        /// </summary>
        private async Task RunAndShow(Action work, Func<string> renderResult, Func<string> renderHeader, Button? busyButton = null)
        {
            // Note: we deliberately do NOT open Advanced here. Verify/Self-test are
            // launched from an already-open Advanced surface (their buttons live
            // there), and Build must not force Advanced open — it reports its outcome
            // in a popup instead.
            SetButtonsEnabled(false);
            if (busyButton != null) SetButtonBusy(busyButton, true);
            TxtResult.Text = renderHeader() + "\n" + L("Result_Processing");
            string? errorDump = null;
            try
            {
                await Task.Run(work);
            }
            catch (Exception ex)
            {
                errorDump = ex.ToString();
            }
            finally
            {
                SetButtonsEnabled(true);
                if (busyButton != null) SetButtonBusy(busyButton, false);
            }
            if (errorDump != null)
            {
                // Re-render the header on a language switch; keep the raw diagnostic
                // dump (a stack trace — English) exactly as captured.
                string dump = errorDump;
                SetResult(() => renderHeader() + "\nERROR:\n" + dump);
            }
            else
            {
                SetResult(renderResult);
            }
        }

        // Idle content of a button currently showing the busy state, so it can be
        // restored when the operation finishes; and the timer driving the dots.
        private readonly Dictionary<Button, object?> _idleContent = new();
        private DispatcherTimer? _buildDots;

        /// <summary>
        /// While busy, turns the button into a "loading" button. It stays DISABLED
        /// (so it can't be re-invoked, including via UI Automation), but Tag="busy"
        /// makes the style keep it full-colour and readable instead of greyed out.
        /// The centered "⏳ Building" label keeps a growing dot suffix once per
        /// second ("" → "." → ".." → "..." → repeat); the word stays put while the
        /// dots grow to its right. Restored when the op finishes.
        /// </summary>
        private void SetButtonBusy(Button button, bool busy)
        {
            if (busy)
            {
                _buildDots?.Stop(); // never leave a previous timer running (re-entrancy)
                if (!_idleContent.ContainsKey(button)) _idleContent[button] = button.Content;
                // The button stays DISABLED (SetButtonsEnabled disabled it), so it can't
                // be re-invoked — including via UI Automation, which ignores
                // IsHitTestVisible/Focusable. Tag="busy" makes the style keep it
                // full-colour and readable instead of greyed out.
                button.Tag = "busy";

                // Keep the WORD "Building" centered in the button: it sits in the
                // middle column, with the ⏳ emoji in an equal-width left column and
                // the dots in an equal-width right column. Equal side columns keep
                // "Building" centered while the emoji stays left and the dots grow
                // right, none of which shifts the word.
                var emoji = new TextBlock { Text = "⏳", VerticalAlignment = VerticalAlignment.Center,
                                            HorizontalAlignment = HorizontalAlignment.Right,
                                            Margin = new Thickness(0, 0, 5, 0) };
                var baseText = new TextBlock { Text = L("Btn_Build_Busy"), VerticalAlignment = VerticalAlignment.Center };
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
                button.ClearValue(FrameworkElement.TagProperty);
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
            // whole operation. Re-mask the MQTT broker password too — its reveal is a
            // sticky toggle, so it would otherwise stay in cleartext for the whole run.
            if (!enabled) { SetReveal(false); if (_mqttPass != null) _mqttPass.Peek = false; }

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
            // Lock the Advanced disclosure while an operation runs. Inspect/Self-test
            // report ONLY into the Result box (no popup), so if the user could collapse
            // Advanced mid-run the outcome would land in a hidden TxtResult and look
            // like nothing happened. Keeping the toggle disabled holds Advanced open
            // (its IsChecked is untouched) so the Result stays visible until done.
            TglAdvanced.IsEnabled = enabled;
            // Lock the language menu during an operation too, so the culture can't
            // change while a result is mid-write (it re-renders freely once idle).
            LangMenu.IsEnabled = enabled;
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
