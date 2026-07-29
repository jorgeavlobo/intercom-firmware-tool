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
    /// (fast, resumable, multipart) and <b>verifies the bytes</b> (size + SHA-256)
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
        private KnownFirmware? _dlSelected; // selected version (feeds the download)
        private string _dlFolder = "";      // destination folder

        // The transfer.
        private readonly FirmwareDownloader _downloader = new();
        private CancellationTokenSource? _dlCts;
        private bool _downloading;

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
            try { _dlCts?.Cancel(); } catch { /* best-effort */ }
            try { _availChecker?.Dispose(); } catch { /* best-effort */ }
        }

        /// <summary>Probe the official URLs off the UI thread; on completion, marshal
        /// back to build the pills. Best-effort — any failure just leaves the link
        /// hidden and manual file-picking as the only path.</summary>
        private void StartAvailabilityProbe()
        {
            _availChecker = new FirmwareAvailabilityChecker();
            var checker = _availChecker;
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
            });
        }

        /// <summary>Store the online entries and, if any, reveal the link and build the pills.</summary>
        private void OnAvailabilityReady(IReadOnlyList<FirmwareAvailability> results)
        {
            _availableFw.Clear();
            _availableFw.AddRange(results.Where(r => r.Available).Select(r => r.Firmware));
            if (_availableFw.Count == 0) return; // nothing online — keep manual-only

            // Default to the line of the newest online firmware (a sensible pick).
            _dlModelLine = _availableFw
                .OrderByDescending(f => ParseVersion(f.Version))
                .First().Line;

            BuildModelPills();
            TglDownload.Visibility = Visibility.Visible;
        }

        // ---- Model / version pills -------------------------------------------

        private void BuildModelPills()
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
                .OrderByDescending(f => ParseVersion(f.Version))
                .ToList();
            if (versions.Count == 0) { _dlSelected = null; UpdateDlStartEnabled(); return; }

            // Keep the current pick if it belongs to this line; otherwise default to
            // the newest version.
            KnownFirmware target =
                (_dlSelected != null && _dlSelected.Line == line
                    && versions.Any(v => v.Version == _dlSelected.Version))
                    ? versions.First(v => v.Version == _dlSelected.Version)
                    : versions[0];

            foreach (var fw in versions)
            {
                bool newest = ReferenceEquals(fw, versions[0]);
                var pill = new RadioButton
                {
                    Style = (Style)FindResource("SegmentPill"),
                    GroupName = "dlVersion",
                    Content = newest ? LF("Dl_VersionLatest", fw.Version) : fw.Version,
                    Tag = fw,
                };
                pill.Checked += VersionPill_Checked;
                VersionPills.Children.Add(pill);
                if (ReferenceEquals(fw, target))
                    pill.IsChecked = true; // fires VersionPill_Checked → SelectVersion(target)
            }
        }

        private void VersionPill_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is RadioButton rb && rb.Tag is KnownFirmware fw)
                SelectVersion(fw);
        }

        private void SelectVersion(KnownFirmware fw)
        {
            _dlSelected = fw;
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
            _dlFolder = dlg.FolderName;
            TxtDlFolder.Text = _dlFolder;
            UpdateDlStartEnabled();
        }

        private void UpdateDlStartEnabled() =>
            BtnDlStart.IsEnabled = !_downloading && _dlSelected != null
                                   && !string.IsNullOrWhiteSpace(_dlFolder);

        // ---- Download --------------------------------------------------------

        private async void BtnDlStart_Click(object sender, RoutedEventArgs e)
        {
            if (_downloading || _dlSelected is null) return;
            if (string.IsNullOrWhiteSpace(_dlFolder) || !Directory.Exists(_dlFolder))
            {
                ChooseDownloadFolder();
                if (string.IsNullOrWhiteSpace(_dlFolder) || !Directory.Exists(_dlFolder)) return;
            }

            KnownFirmware fw = _dlSelected;
            _downloading = true;
            _dlCts = new CancellationTokenSource();
            SetDownloadBusy(true);
            SetDlStatus(null);
            DlProgress.Value = 0;
            TxtDlProgress.Text = LF("Dl_ProgressStarting", fw.OriginalName);
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
                result = new DownloadResult(DownloadOutcome.HttpError, null,
                    LF("Dl_UnexpectedError", SafeMessage(ex)));
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
            TxtDlProgress.Text = L("Dl_Cancelling");
            try { _dlCts?.Cancel(); } catch { /* best-effort */ }
        }

        private void OnDownloadProgress(DownloadProgress p)
        {
            if (p.Fraction is double f)
            {
                DlProgress.Value = Math.Clamp(f * 100.0, 0, 100);
                int pct = (int)Math.Round(f * 100.0);
                TxtDlProgress.Text = LF("Dl_ProgressFmt", pct,
                    HumanBytes(p.BytesReceived), HumanBytes(p.TotalBytes), HumanRate(p.BytesPerSecond));
            }
            else
            {
                TxtDlProgress.Text = LF("Dl_ProgressUnknown",
                    HumanBytes(p.BytesReceived), HumanRate(p.BytesPerSecond));
            }
        }

        private void HandleDownloadResult(KnownFirmware fw, DownloadResult result)
        {
            if (result.Ok && result.Path is string path)
            {
                // Feed the verified file into the build flow, exactly like a manual pick.
                AcceptVerifiedFirmware(path, fw);
                // The Core message is already localized at download time; show it with a
                // check. (Transient, so it doesn't need to re-localize on a later switch.)
                string msg = result.Message;
                SetDlStatus(() => "✓ " + msg, DlOkBrush);
                SetResult(() => LF("Fmt_Result_Accepted", msg, fw.Describe()));
                SetStatus(() => L("Status_FirmwareVerified")); // simple-view confirmation
            }
            else if (result.Outcome == DownloadOutcome.Cancelled)
            {
                string msg = result.Message;
                SetDlStatus(() => msg, null);
            }
            else
            {
                string msg = result.Message;
                SetDlStatus(() => msg, ErrorBrush);
            }
        }

        // ---- Busy state + status line ----------------------------------------

        /// <summary>Locks the card's inputs while a download runs (and shows Cancel);
        /// the Start button keeps its accent fill via the Tag="busy" style trick.</summary>
        private void SetDownloadBusy(bool busy)
        {
            foreach (var r in ModelPills.Children.OfType<RadioButton>()) r.IsEnabled = !busy;
            foreach (var r in VersionPills.Children.OfType<RadioButton>()) r.IsEnabled = !busy;
            BtnDlBrowse.IsEnabled = !busy;
            BtnDlCancel.IsEnabled = busy;
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

        /// <summary>Re-applies the card's code-set text after a runtime language switch:
        /// rebuild the pills (the "latest" tag localizes), the Start/Downloading label,
        /// and the status line.</summary>
        private void ApplyDownloadLanguage()
        {
            if (_availableFw.Count > 0) BuildModelPills(); // re-selects _dlModelLine/_dlSelected
            BtnDlStart.Content = _downloading ? L("Dl_Downloading") : L("Dl_Start");
            RenderDlStatus();
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
