using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;   // DropShadowEffect on the "Latest" badge
using IntercomFirmwareTool.Core;
using Microsoft.Win32;

namespace IntercomFirmwareTool.App
{
    /// <summary>
    /// Optional "download official firmware" flow (issue #23). At startup it probes
    /// the official <see cref="KnownFirmware.DownloadUrl"/>s of the customizable
    /// (Door Entry) entries — in the background, with Polly resilience — and reveals a
    /// "Download official firmware" link under the firmware box <b>only</b> for the
    /// entries that are currently online and serve the expected file. Opening the link
    /// shows a card to pick the model + version and a destination folder, then downloads
    /// (fast multipart, single-connection fallback; each run starts fresh — no resume) and
    /// <b>verifies the bytes</b> (size + SHA-256)
    /// against the chosen entry before feeding the result into the normal build flow —
    /// exactly as if the user had picked the file by hand. The download is <b>not</b> a
    /// substitute for that integrity gate: the same file is re-verified downstream.
    ///
    /// This is a convenience over downloading the identical, publicly-available file by
    /// hand from BTicino/Legrand; the tool only fetches and checks it.
    /// </summary>
    public partial class MainWindow
    {
        // The customizable entries whose official URL probed as online + right-sized.
        private readonly List<KnownFirmware> _availableFw = new();
        private FirmwareAvailabilityChecker? _availChecker;
        private readonly CancellationTokenSource _dlProbeCts = new();

        // Current selection in the card.
        private string? _dlModelLine;      // selected product line (model pill)
        // True only while BuildModelPills rebuilds the pills for a language switch. The rebuild
        // re-checks the remembered model/version, firing the same Checked handlers a real click
        // would — this flag lets SelectVersion tell the two apart, so a language switch keeps the
        // last download's inline status while an actual selection change clears it.
        private bool _dlRebuilding;
        private KnownFirmware? _dlSelected; // selected version (feeds the download)
        private string _dlFolder = "";      // destination folder

        // The transfer.
        private readonly FirmwareDownloader _downloader = new();
        private CancellationTokenSource? _dlCts;
        private bool _downloading;
        // Snapshot of the (always-editable) HA node id taken when a download starts, so
        // completion can tell whether the user retyped it mid-transfer and, if so, keep
        // their value instead of overwriting it with the model default.
        private string? _dlNodeIdAtStart;

        // Success is green, cancelled is neutral, failure reuses the app error colour.
        private static readonly Brush DlOkBrush = MakeFrozen(Color.FromRgb(0x2E, 0x7D, 0x32));

        // ---- Init + startup availability probe -------------------------------

        /// <summary>Wire the default destination and kick off the background probe.
        /// Called from the ctor after InitMqttUi (so the controls exist).</summary>
        private void InitDownloadUi()
        {
            _dlFolder = FirmwareDefaultDir();
            TxtDlFolder.Text = _dlFolder;
            Closed += (_, _) => StopDownload();
            StartAvailabilityProbe();
        }

        /// <summary>Cancels the probe / any in-flight download and releases the checker.</summary>
        private void StopDownload()
        {
            try { _dlProbeCts.Cancel(); } catch { /* nothing registered can throw */ }
            try { _dlProbeCts.Dispose(); } catch { /* best-effort: only runs on window close */ }
            try { _dlCts?.Cancel(); } catch { /* best-effort */ }
            try { _availChecker?.Dispose(); } catch { /* best-effort */ }
            _availChecker = null; // idempotent: a second Stop won't re-dispose a released checker
        }

        /// <summary>Probe the official URLs off the UI thread; on completion, marshal
        /// back to build the pills. Best-effort — any failure just leaves the link
        /// hidden and manual file-picking as the only path.</summary>
        private void StartAvailabilityProbe()
        {
            var checker = new FirmwareAvailabilityChecker();
            _availChecker = checker; // non-null local: the closure captures it without a null-check
            var token = _dlProbeCts.Token;
            _ = Task.Run(async () =>
            {
                try
                {
                    var results = await checker.ProbeAsync(token).ConfigureAwait(false);
                    if (token.IsCancellationRequested) return;
                    await Dispatcher.InvokeAsync(() => OnAvailabilityReady(results));
                }
                catch { /* unreachable network / cancelled — leave the link hidden */ }
                finally
                {
                    // One-shot probe: release the HttpClient/handlers the instant it finishes rather
                    // than holding them for the whole app lifetime. StopDownload's later dispose then
                    // no-ops (it's idempotent and null-guarded); nulling the field keeps that safe
                    // even under the race with a shutdown Stop.
                    checker.Dispose();
                    _availChecker = null;
                }
            });
        }

        /// <summary>Store the online entries and, if any, reveal the link and build the pills.</summary>
        private void OnAvailabilityReady(IReadOnlyList<FirmwareAvailability> results)
        {
            _availableFw.Clear();
            // Only customizable (Door Entry) entries may be offered — the checker already probes
            // only those, but assert it here too so the download path can't drift from the manual
            // picker's IsCustomizable gate.
            _availableFw.AddRange(results
                .Where(r => r.Available && r.Firmware.IsCustomizable)
                .Select(r => r.Firmware));
            if (_availableFw.Count == 0) return; // nothing online — keep manual-only

            // Default to the line of the newest online firmware (a sensible pick).
            _dlModelLine = _availableFw
                .OrderByDescending(f => ParseVersion(f.Version))
                .First().Line;

            BuildModelPills();
            TglDownload.Visibility = Visibility.Visible;
            // A fast probe can reveal this entry point within the cue's arming delay; announce it so
            // the reveal isn't silently swallowed and the download section goes unnoticed below the fold.
            NotifyContentRevealed();
        }

        // ---- Model / version pills -------------------------------------------

        private void BuildModelPills()
        {
            // A rebuild re-checks the remembered pills, which fires the selection handlers exactly
            // as a user click would; flag it so SelectVersion preserves (not clears) the last
            // download's inline status across a language switch.
            _dlRebuilding = true;
            try
            {
                ModelPills.Children.Clear();
                // Distinct preserves registry order (100X before 300X).
                var lines = _availableFw.Select(f => f.Line).Distinct().ToList();
                RadioButton? target = null;
                foreach (var line in lines)
                {
                    var pill = new RadioButton
                    {
                        Style = (Style)FindResource("SegmentPill"),
                        GroupName = "dlModel",
                        Content = line,
                        Tag = line,
                    };
                    pill.Checked += ModelPill_Checked;
                    ModelPills.Children.Add(pill);
                    if (line == _dlModelLine) target = pill;
                }
                target ??= ModelPills.Children.OfType<RadioButton>().FirstOrDefault();
                // Setting IsChecked here (after the handler is wired + the pill is in the
                // tree) fires ModelPill_Checked → SelectModel → BuildVersionPills.
                if (target != null) target.IsChecked = true;
            }
            finally { _dlRebuilding = false; }
        }

        private void ModelPill_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is RadioButton rb && rb.Tag is string line)
                SelectModel(line);
        }

        private void SelectModel(string line)
        {
            _dlModelLine = line;
            BuildVersionPills(line);
        }

        private void BuildVersionPills(string line)
        {
            VersionPills.Children.Clear();
            var versions = _availableFw
                .Where(f => f.Line == line)
                // Ascending: oldest on the left → newest on the right, so the row reads as a
                // natural version timeline and the newest (the default) sits at the end.
                .OrderBy(f => ParseVersion(f.Version))
                .ToList();
            if (versions.Count == 0) { _dlSelected = null; UpdateDlStartEnabled(); return; }

            KnownFirmware newestFw = versions[^1]; // last = newest

            // Keep the current pick if it belongs to this line; otherwise default to the newest.
            KnownFirmware target =
                (_dlSelected != null && _dlSelected.Line == line
                    && versions.Any(v => v.Version == _dlSelected.Version))
                    ? versions.First(v => v.Version == _dlSelected.Version)
                    : newestFw;

            foreach (var fw in versions)
            {
                bool isNewest = ReferenceEquals(fw, newestFw);
                var pill = new RadioButton
                {
                    Style = (Style)FindResource("SegmentPill"),
                    GroupName = "dlVersion",
                    Content = fw.Version,
                    Tag = fw,
                };
                pill.Checked += VersionPill_Checked;

                if (isNewest)
                {
                    // Overlay a "Latest" badge on the pill's TOP-RIGHT corner, half outside the
                    // button (a notification-badge look): the pill sits in a Grid and the badge is
                    // a sibling pinned top-right with a negative margin, drawn on top. The newest
                    // is always the last (rightmost) pill, so the overhang falls into free space.
                    var host = new Grid { Margin = new Thickness(0, 0, 8, 8) };
                    pill.Margin = new Thickness(0); // the host carries the inter-pill spacing
                    host.Children.Add(pill);
                    Border badge = BuildLatestBadge();
                    Panel.SetZIndex(badge, 1);
                    host.Children.Add(badge);
                    VersionPills.Children.Add(host);
                }
                else
                {
                    VersionPills.Children.Add(pill);
                }

                if (ReferenceEquals(fw, target))
                    pill.IsChecked = true; // fires VersionPill_Checked → SelectVersion(target)
            }
        }

        // Emerald "Latest" badge — self-contained (its own fill + white text + white ring + soft
        // shadow) so it reads as a floating chip on the pill's corner, over either the light pill
        // or the accent-blue selected pill.
        private static readonly Brush LatestBadgeBrush = MakeFrozen(Color.FromRgb(0x10, 0xB9, 0x81));

        /// <summary>A rounded "Latest" chip pinned to a pill's top-right corner, half outside it.</summary>
        private Border BuildLatestBadge() => new()
        {
            Background = LatestBadgeBrush,
            CornerRadius = new CornerRadius(9),
            Padding = new Thickness(7, 1, 7, 2),
            HorizontalAlignment = HorizontalAlignment.Right,
            VerticalAlignment = VerticalAlignment.Top,
            Margin = new Thickness(0, -9, -7, 0), // lift up + right, so it half-overhangs the corner
            IsHitTestVisible = false,             // click-through: never steal a click from the pill
            // Elevation, not an outline: a soft, diffuse shadow tinted with the badge's own colour
            // and offset downward, so the chip reads as floating above the pill (a green "lift"
            // glow — the premium colored-shadow look) rather than a flat sticker with a border.
            Effect = new DropShadowEffect
            {
                Color = Color.FromRgb(0x05, 0x5F, 0x43), // deep emerald
                BlurRadius = 13,
                ShadowDepth = 2.5,
                Opacity = 0.6,
                Direction = 270, // straight down
            },
            Child = new TextBlock
            {
                Text = L("Dl_Latest"),
                Foreground = Brushes.White,
                FontSize = 9,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center,
            },
        };

        private void VersionPill_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is RadioButton rb && rb.Tag is KnownFirmware fw)
                SelectVersion(fw);
        }

        private void SelectVersion(KnownFirmware fw)
        {
            _dlSelected = fw;
            // A genuine selection change makes the previous download's inline status (e.g. the
            // generic "Download failed"/"cancelled") describe a firmware no longer selected — clear
            // it. A language-only pill rebuild re-selects the same entry, so keep the status there.
            if (!_dlRebuilding) SetDlStatus(null);
            UpdateDlStartEnabled();
        }

        /// <summary>System.Version parse with a safe fallback, so a stray version
        /// string can never throw during sorting.</summary>
        private static Version ParseVersion(string v) =>
            Version.TryParse(v, out var parsed) ? parsed : new Version(0, 0);

        // ---- Disclosure + folder picker --------------------------------------

        private void TglDownload_Changed(object sender, RoutedEventArgs e)
        {
            bool open = TglDownload.IsChecked == true;
            DownloadCard.Visibility = open ? Visibility.Visible : Visibility.Collapsed;
            if (open) DownloadCard.BringIntoView(); // scroll it into view in the page ScrollViewer
        }

        private void DlFolder_MouseDown(object sender, MouseButtonEventArgs e)
        {
            e.Handled = true; // act purely as a browse button (no caret/selection)
            ChooseDownloadFolder();
        }

        // Keyboard parity with the other click-to-browse boxes: Enter/Space opens the picker.
        private void DlFolder_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (!IsActivationKey(e)) return;
            e.Handled = true;
            ChooseDownloadFolder();
        }

        private void BtnDlBrowse_Click(object sender, RoutedEventArgs e) => ChooseDownloadFolder();

        private void ChooseDownloadFolder()
        {
            if (_downloading) return;
            var dlg = new OpenFolderDialog
            {
                Title = L("Dl_ChooseFolder"),
                InitialDirectory = Directory.Exists(_dlFolder) ? _dlFolder : FirmwareDefaultDir(),
            };
            if (dlg.ShowDialog(this) != true) return;
            bool changed = !string.Equals(_dlFolder, dlg.FolderName, StringComparison.Ordinal);
            _dlFolder = dlg.FolderName;
            TxtDlFolder.Text = _dlFolder;
            // A different destination has never been scanned/downloaded to, so a prior verified/
            // cached/failed result (scoped to the old folder) no longer applies — clear it, mirroring
            // the selection-change clear in SelectVersion.
            if (changed) SetDlStatus(null);
            UpdateDlStartEnabled();
        }

        // _uiEnabled is false while a build/verify/self-test runs, so a download can't be
        // started concurrently with (and publish a firmware into) an in-flight build.
        private void UpdateDlStartEnabled() =>
            // Blocked while a build/verify runs (_uiEnabled), while a download is in flight, or while
            // an MQTT connection test / MAC capture is running — the two must not overlap.
            BtnDlStart.IsEnabled = _uiEnabled && !_downloading && !_mqttTesting && !_mqttCapturing
                                   && _dlSelected != null && !string.IsNullOrWhiteSpace(_dlFolder);

        // ---- Download --------------------------------------------------------

        private async void BtnDlStart_Click(object sender, RoutedEventArgs e)
        {
            // Don't start a download over another operation: a build/verify (_uiEnabled) or an MQTT
            // connection test / MAC capture in flight. The Start button gate mirrors this.
            if (_downloading || !_uiEnabled || _mqttTesting || _mqttCapturing || _dlSelected is null)
                return;
            if (string.IsNullOrWhiteSpace(_dlFolder) || !Directory.Exists(_dlFolder))
            {
                ChooseDownloadFolder();
                if (string.IsNullOrWhiteSpace(_dlFolder) || !Directory.Exists(_dlFolder)) return;
            }

            KnownFirmware fw = _dlSelected;
            _downloading = true;
            // The node id field stays editable during the transfer (its clear/opt-out path
            // needs it); snapshot it so completion won't clobber an edit the user made while
            // the download ran.
            _dlNodeIdAtStart = TxtMqttHaNodeId.Text;
            _dlCts = new CancellationTokenSource();
            SetDownloadBusy(true);
            SetDlStatus(null);
            DlProgress.Value = 0;
            SetDlProgress(() => LF("Dl_ProgressStarting", fw.OriginalName));
            DlProgressPanel.Visibility = Visibility.Visible;

            // Progress<T> captures this UI SynchronizationContext, so the report
            // callbacks run back on the UI thread.
            var progress = new Progress<DownloadProgress>(OnDownloadProgress);
            DownloadResult result;
            try
            {
                result = await _downloader.DownloadAsync(fw, _dlFolder, progress, _dlCts.Token);
            }
            catch (Exception ex)
            {
                // DownloadAsync is written not to throw for expected failures, but never
                // let anything escape this async void handler.
                string em = SafeMessage(ex);
                result = new DownloadResult(DownloadOutcome.HttpError, null,
                    () => LF("Dl_UnexpectedError", em));
            }
            finally
            {
                _downloading = false;
                _dlCts?.Dispose();
                _dlCts = null;
                SetDownloadBusy(false);
                DlProgressPanel.Visibility = Visibility.Collapsed;
            }

            HandleDownloadResult(fw, result);
        }

        private void BtnDlCancel_Click(object sender, RoutedEventArgs e)
        {
            if (!_downloading) return;
            BtnDlCancel.IsEnabled = false;
            SetDlProgress(() => L("Dl_Cancelling"));
            try { _dlCts?.Cancel(); } catch { /* best-effort */ }
        }

        private void OnDownloadProgress(DownloadProgress p)
        {
            // Once Cancel is pressed, BtnDlCancel_Click shows "Cancelling…"; CancelAsync is async, so
            // queued Progress<T> callbacks can still arrive. Drop them, so they don't overwrite the
            // "Cancelling…" acknowledgement and make the button look like it did nothing.
            if (_dlCts?.IsCancellationRequested == true) return;
            if (p.Fraction is double f)
            {
                double clamped = Math.Clamp(f * 100.0, 0, 100);
                DlProgress.Value = clamped;
                // Clamp the shown percent too: with TotalBytes pinned to the registry size, a server
                // that returns more bytes than expected could otherwise print "101%".
                int pct = (int)Math.Round(clamped);
                // Capture the values so the render closure re-localizes on a later language switch.
                long recv = p.BytesReceived, total = p.TotalBytes;
                double rate = p.BytesPerSecond;
                SetDlProgress(() => LF("Dl_ProgressFmt", pct,
                    HumanBytes(recv), HumanBytes(total), HumanRate(rate)));
            }
            else
            {
                long recv = p.BytesReceived;
                double rate = p.BytesPerSecond;
                SetDlProgress(() => LF("Dl_ProgressUnknown", HumanBytes(recv), HumanRate(rate)));
            }
        }

        private void HandleDownloadResult(KnownFirmware fw, DownloadResult result)
        {
            if (result.Ok && result.Path is string path)
            {
                // Feed the verified file into the build flow, exactly like a manual pick.
                // If the user retyped the HA node id while the download ran, keep their
                // value; only re-suggest the model default when they left it untouched.
                bool nodeIdUntouched = TxtMqttHaNodeId.Text == _dlNodeIdAtStart;
                AcceptVerifiedFirmware(path, fw, fillNodeId: nodeIdUntouched);
                // result.Message is a factory (re-localizes on each render), so these closures
                // re-render in the current language on a later switch, like the rest of the app.
                SetDlStatus(() => "✓ " + result.Message, DlOkBrush);
                SetResult(() => LF("Fmt_Result_Accepted", result.Message, fw.Describe()));
                SetStatus(() => L("Status_FirmwareVerified")); // simple-view confirmation
            }
            else if (result.Outcome == DownloadOutcome.Cancelled)
            {
                SetDlStatus(() => result.Message, null);
            }
            else
            {
                SetDlStatus(() => result.Message, ErrorBrush);
            }
        }

        // ---- Busy state + status line ----------------------------------------

        /// <summary>Locks the card's inputs while a download runs (and shows Cancel);
        /// the Start button keeps its accent fill via the Tag="busy" style trick.</summary>
        private void SetDownloadBusy(bool busy)
        {
            // Lock the disclosure OPEN while a download runs: the card can only be open now
            // (Start lives inside it), and collapsing it would hide the sole progress bar AND
            // the Cancel button while the transfer continued and every other op stays locked —
            // the operation would look like it vanished, with no way to cancel. Disabling the
            // toggle pins it in its current (open) state.
            TglDownload.IsEnabled = !busy;
            foreach (var r in ModelPills.Children.OfType<RadioButton>()) r.IsEnabled = !busy;
            foreach (var r in VersionPillButtons()) r.IsEnabled = !busy;
            TxtDlFolder.IsEnabled = !busy; // click-to-browse box: dead while a download runs
            BtnDlBrowse.IsEnabled = !busy;
            BtnDlCancel.IsEnabled = busy;
            // Lock the other operation launchers while a download runs (a build already blocks
            // the download; this is the mirror). They share the Result/status surface, and a
            // download's completion mutates the selected firmware — so they must not overlap.
            BtnVerify.IsEnabled = !busy;
            BtnSelfTest.IsEnabled = !busy;
            BtnGenKey.IsEnabled = !busy;
            // The firmware picker box, too: ChooseFirmwareAsync no-ops while _downloading, so leaving
            // it enabled/focusable would just swallow clicks; lock it like the other browse fields.
            // (A download and a build are mutually exclusive, so !busy is the right restore state.)
            TxtFwzPath.IsEnabled = !busy;
            // Also the MQTT connection test: a download's completion changes the HA node id, which
            // would silently invalidate an in-flight test.
            BtnMqttTest.IsEnabled = !busy;
            // And the output row: completion overwrites _outputPath with the auto-suggested path,
            // so don't let the user edit/clear it mid-download.
            TxtOutputPath.IsEnabled = !busy && _fwzPath != null;
            LblOutput.IsEnabled = !busy && _fwzPath != null;
            BtnClearOutput.IsEnabled = !busy && _fwzPath != null && _outputPath != null;
            if (busy)
            {
                BtnDlStart.Tag = "busy";      // keep it full-colour while disabled
                BtnDlStart.IsEnabled = false;
                BtnDlStart.Content = L("Dl_Downloading");
            }
            else
            {
                BtnDlStart.Tag = null;
                BtnDlStart.Content = L("Dl_Start");
                UpdateDlStartEnabled();
            }
            // A running download blocks Build (and vice-versa) — refresh the Build gate.
            UpdateBuildEnabled();
        }

        // Every version pill's RadioButton, unwrapping the newest one (which sits in a Grid
        // host so its "Latest" badge can overhang) — a plain OfType over direct children
        // would miss it, leaving it clickable mid-download.
        private IEnumerable<RadioButton> VersionPillButtons()
        {
            foreach (var child in VersionPills.Children)
            {
                if (child is RadioButton rb) yield return rb;
                else if (child is Grid g)
                    foreach (var gc in g.Children)
                        if (gc is RadioButton grb) yield return grb;
            }
        }

        // The download status line is rebuildable in any language via a render closure
        // (null = hidden), mirroring the main SetStatus pattern.
        private Func<string>? _dlStatusRender;
        private Brush _dlStatusBrush = Brushes.Gray;

        private void SetDlStatus(Func<string>? render, Brush? brush = null)
        {
            _dlStatusRender = render;
            _dlStatusBrush = brush ?? Brushes.Gray;
            RenderDlStatus();
        }

        private void RenderDlStatus()
        {
            string msg = _dlStatusRender?.Invoke() ?? "";
            TxtDlStatus.Text = msg;
            TxtDlStatus.Foreground = _dlStatusBrush;
            TxtDlStatus.Visibility = string.IsNullOrEmpty(msg) ? Visibility.Collapsed : Visibility.Visible;
            if (!string.IsNullOrEmpty(msg)) AnnounceLiveRegion(TxtDlStatus);
        }

        // The in-progress line (TxtDlProgress) is likewise held as a render closure, so a language
        // switch mid-transfer re-localizes it — even a "Starting download…" that's stalled waiting
        // for the first bytes and so isn't being refreshed by progress callbacks.
        private Func<string>? _dlProgressRender;

        private void SetDlProgress(Func<string> render)
        {
            _dlProgressRender = render;
            TxtDlProgress.Text = render();
        }

        /// <summary>Re-applies the card's code-set text after a runtime language switch:
        /// rebuild the pills (the "latest" tag localizes), the Start/Downloading label,
        /// and the status line.</summary>
        private void ApplyDownloadLanguage()
        {
            if (_availableFw.Count > 0) BuildModelPills(); // re-selects _dlModelLine/_dlSelected
            // Freshly rebuilt pills default to enabled, so re-apply the busy lock if a download
            // is running (the language menu stays usable mid-download).
            if (_downloading) SetDownloadBusy(true);
            BtnDlStart.Content = _downloading ? L("Dl_Downloading") : L("Dl_Start");
            RenderDlStatus();
            // Re-localize the in-progress line too (e.g. a stalled "Starting download…"): the
            // progress callbacks may not fire while waiting for the first bytes.
            if (_downloading && _dlProgressRender != null) TxtDlProgress.Text = _dlProgressRender();
        }

        // ---- Byte / rate formatting ------------------------------------------

        private static string HumanBytes(long bytes)
        {
            if (bytes < 0) bytes = 0;
            double mb = bytes / (1024.0 * 1024.0);
            return mb >= 1024.0
                ? string.Format(CultureInfo.CurrentCulture, "{0:N1} GB", mb / 1024.0)
                : string.Format(CultureInfo.CurrentCulture, "{0:N1} MB", mb);
        }

        private static string HumanRate(double bytesPerSecond)
        {
            if (bytesPerSecond < 0) bytesPerSecond = 0;
            double mbps = bytesPerSecond / (1024.0 * 1024.0);
            if (mbps >= 1.0)
                return string.Format(CultureInfo.CurrentCulture, "{0:N1} MB/s", mbps);
            double kbps = bytesPerSecond / 1024.0;
            return string.Format(CultureInfo.CurrentCulture, "{0:N0} KB/s", kbps);
        }
    }
}
