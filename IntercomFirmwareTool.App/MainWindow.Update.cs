using System;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using IntercomFirmwareTool.App.Settings;
using IntercomFirmwareTool.Core.Updates;

namespace IntercomFirmwareTool.App
{
    /// <summary>
    /// Startup update check (issue #85). On launch — after the window is shown, on a background,
    /// time-boxed, best-effort task — the app fetches a small manifest from the repository and,
    /// if a newer release exists, shows a dismissible "update available" banner (app stays fully
    /// usable). Only when the running build is below a maintainer-flagged minimum-supported
    /// version, on a clear and sane signal, does it hard-block the actions (red banner). Everything
    /// fails OPEN: no network, timeout, opt-out, dev build, or bad manifest ⇒ no banner, no block.
    /// It never downloads or runs anything — the Download button just opens the Releases page.
    /// </summary>
    public partial class MainWindow
    {
        // The download destination is HARDCODED here — a tampered/mis-edited manifest can never
        // redirect users elsewhere. Any URL in the manifest is ignored by design.
        private const string ReleasesUrl = "https://github.com/jorgeavlobo/intercom-firmware-tool/releases";

        // The manifest is served raw (Fastly CDN, no API rate limit) from the default branch.
        private const string ManifestUrl =
            "https://raw.githubusercontent.com/jorgeavlobo/intercom-firmware-tool/master/.well-known/updates.json";

        private const int MaxManifestBytes = 64 * 1024;                 // size-cap a hostile/oversized body
        private static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(4);

        // One reused client: default handler enforces TLS and respects the system proxy (corporate
        // networks); a short timeout keeps a per-launch check unobtrusive.
        private static readonly HttpClient Http = CreateHttpClient();

        private static HttpClient CreateHttpClient()
        {
            // No auto-redirect: the manifest lives at a fixed raw.githubusercontent.com URL, so a
            // redirect (to another host, or downgraded to HTTP) is unexpected — a 3xx is not a
            // success status, so FetchManifestAsync treats it as a failure and fails open.
            var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            {
                Timeout = HttpTimeout,
            };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("IntercomFirmwareTool-UpdateCheck");
            return client;
        }

        private SemanticVersion? _currentVersion;      // null for a dev/untagged (0.0.0) build ⇒ never nag
        private string _displayVersion = "0.0.0";      // raw version string for the About dialog
        private bool _updateCheckStarted;
        private SemanticVersion? _pendingUpdateVersion; // the version offered in the info banner (for dismiss/relabel)
        private SemanticVersion? _blockedVersion;       // the minimum-supported version shown in the block banner
        private bool _blocked;                          // an unsafe-version hard-block is in effect (sticky for the session)

        /// <summary>Reads the running version and syncs the settings-menu checkbox. Called from the ctor.</summary>
        private void InitUpdateUi()
        {
            string? info = typeof(MainWindow).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            _displayVersion = string.IsNullOrWhiteSpace(info) ? "0.0.0" : info!.Trim();

            // 0.0.0 is the csproj default that marks a local/dev build (the release workflow stamps
            // the real tag). A dev build never nags and never blocks.
            if (SemanticVersion.TryParse(_displayVersion, out var v) &&
                !(v!.Major == 0 && v.Minor == 0 && v.Patch == 0))
            {
                _currentVersion = v;
            }

            MnuCheckUpdatesStartup.IsChecked = AppSettings.Load().UpdateCheckEnabled;
        }

        /// <summary>Kicks off the automatic check once, after the window is shown (from Loaded).</summary>
        private void StartUpdateCheck()
        {
            if (_updateCheckStarted) return;
            _updateCheckStarted = true;

            if (_currentVersion is null) return;                    // dev build ⇒ silent
            if (!AppSettings.Load().UpdateCheckEnabled) return;     // opt-out ⇒ no network call
            _ = RunUpdateCheckAsync(manual: false);
        }

        private async Task RunUpdateCheckAsync(bool manual)
        {
            try
            {
                UpdateManifest? manifest = await FetchManifestAsync().ConfigureAwait(true);
                var status = UpdateChecker.Evaluate(_currentVersion, manifest);
                ApplyUpdateStatus(status, manual);
            }
            catch
            {
                // Fire-and-forget: never let a check failure surface or crash the app.
                if (manual) TryInform("Update_Failed");
            }
        }

        /// <summary>Fetches and parses the manifest, size-capped and fully fail-open (null on any problem).</summary>
        private static async Task<UpdateManifest?> FetchManifestAsync()
        {
            try
            {
                // ResponseHeadersRead means HttpClient.Timeout only covers up to the headers, so
                // bound the WHOLE fetch (headers + body) with one linked token — otherwise a server
                // that trickles or stalls the body could hang the read indefinitely (a leaked
                // fire-and-forget task) instead of failing open.
                using var cts = new CancellationTokenSource(HttpTimeout);
                using var resp = await Http
                    .GetAsync(ManifestUrl, HttpCompletionOption.ResponseHeadersRead, cts.Token)
                    .ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                    return null;
                if (resp.Content.Headers.ContentLength is long declared && declared > MaxManifestBytes)
                    return null;

                await using var stream = await resp.Content.ReadAsStreamAsync(cts.Token)
                    .ConfigureAwait(false);

                // Bounded read: never buffer more than the cap (+1 byte to detect an over-cap body).
                var buffer = new byte[MaxManifestBytes + 1];
                int total = 0, read;
                while (total < buffer.Length &&
                       (read = await stream.ReadAsync(buffer.AsMemory(total), cts.Token)
                           .ConfigureAwait(false)) > 0)
                {
                    total += read;
                }
                if (total > MaxManifestBytes)
                    return null;

                string json = Encoding.UTF8.GetString(buffer, 0, total);
                return UpdateManifest.TryParse(json, out var manifest) ? manifest : null;
            }
            catch
            {
                return null; // DNS, timeout, TLS, 4xx/5xx, cancellation — all fail open
            }
        }

        private void ApplyUpdateStatus(UpdateStatus status, bool manual)
        {
            // An unsafe-version block is terminal for the session: once actions are disabled with
            // the red banner shown, never let a later result (a manual re-check, or re-enabling the
            // setting) hide that banner and leave the actions disabled with no explanation.
            if (_blocked) return;

            switch (status.Kind)
            {
                case UpdateStatusKind.UpdateAvailable:
                    string version = status.Version!.ToString();
                    // A routine (automatic) check honours a per-version dismissal; a manual "Check
                    // now" always re-surfaces the offer.
                    if (!manual &&
                        string.Equals(version, AppSettings.Load().LastDismissedUpdateVersion, StringComparison.Ordinal))
                    {
                        HideInformationalBanner();
                        return;
                    }
                    ShowUpdateAvailable(status.Version!);
                    break;

                case UpdateStatusKind.Unsupported:
                    ShowUnsupported(status.Version!);
                    break;

                default: // UpToDate / Unknown
                    HideInformationalBanner();
                    if (manual)
                        TryInform(status.Kind == UpdateStatusKind.UpToDate ? "Update_None" : "Update_Failed");
                    break;
            }
        }

        private void ShowUpdateAvailable(SemanticVersion version)
        {
            _pendingUpdateVersion = version;
            TxtUpdateBanner.Text = LFormat("Update_Available", version.ToString());
            // Informational banner coexists ABOVE the (still visible) safety warning.
            UpdateBlockBanner.Visibility = Visibility.Collapsed;
            UpdateBanner.Visibility = Visibility.Visible;
            // LiveSetting alone is inert in WPF — raise the notification so a screen reader
            // announces the newly shown banner.
            AnnounceLiveRegion(TxtUpdateBanner);
        }

        private void ShowUnsupported(SemanticVersion minimum)
        {
            _blockedVersion = minimum;
            TxtUpdateBlockBanner.Text = LFormat("Update_Unsafe", minimum.ToString());
            // The mandatory banner REPLACES the flash-warning and the info banner.
            UpdateBanner.Visibility = Visibility.Collapsed;
            RiskBanner.Visibility = Visibility.Collapsed;
            UpdateBlockBanner.Visibility = Visibility.Visible;
            // Assertive live region — announce the mandatory message so a screen-reader user hears
            // WHY the controls just became disabled.
            AnnounceLiveRegion(TxtUpdateBlockBanner);
            EnterUnsupportedBlockedState();
        }

        private void HideInformationalBanner() => UpdateBanner.Visibility = Visibility.Collapsed;

        /// <summary>Disables the actions on an unsafe-version block while keeping the user free to
        /// read the message, switch language, open Help/About, and quit (never trap the user).</summary>
        private void EnterUnsupportedBlockedState()
        {
            _blocked = true;
            SetButtonsEnabled(false); // honours _blocked: disables actions but re-enables the menus
        }

        /// <summary>Re-renders the imperatively-set banner text after a language switch.</summary>
        private void ApplyUpdateLanguage()
        {
            if (UpdateBanner.Visibility == Visibility.Visible && _pendingUpdateVersion is not null)
                TxtUpdateBanner.Text = LFormat("Update_Available", _pendingUpdateVersion.ToString());
            if (UpdateBlockBanner.Visibility == Visibility.Visible && _blockedVersion is not null)
                TxtUpdateBlockBanner.Text = LFormat("Update_Unsafe", _blockedVersion.ToString());
        }

        // ---- Banner + settings-menu event handlers ------------------------------------------------

        /// <summary>Both Download buttons open the HARDCODED Releases page — never a manifest URL.</summary>
        private void BtnUpdateDownload_Click(object sender, RoutedEventArgs e) => OpenUrl(ReleasesUrl);

        private void BtnUpdateDismiss_Click(object sender, RoutedEventArgs e)
        {
            if (_pendingUpdateVersion is not null)
            {
                string version = _pendingUpdateVersion.ToString();
                AppSettings.Update(s => s.LastDismissedUpdateVersion = version);
            }
            HideInformationalBanner();
        }

        private void MnuCheckUpdatesStartup_Click(object sender, RoutedEventArgs e)
        {
            bool enabled = MnuCheckUpdatesStartup.IsChecked; // IsCheckable item: already the new state
            AppSettings.Update(s => s.UpdateCheckEnabled = enabled);
            // Turning it on mid-session runs a check now (unless a dev build); turning it off just
            // persists — any banner already shown stays until dismissed or the app restarts.
            if (enabled && _currentVersion is not null)
                _ = RunUpdateCheckAsync(manual: false);
        }

        private void MnuCheckNow_Click(object sender, RoutedEventArgs e)
        {
            if (_currentVersion is null)
            {
                TryInform("Update_DevBuild"); // dev/untagged build: nothing to compare against
                return;
            }
            _ = RunUpdateCheckAsync(manual: true);
        }

        private void MnuAbout_Click(object sender, RoutedEventArgs e) =>
            MessageBox.Show(this, LFormat("About_Body", _displayVersion), L("About_Title"),
                MessageBoxButton.OK, MessageBoxImage.Information);

        private void TryInform(string key) =>
            MessageBox.Show(this, L(key), L("Update_CheckTitle"),
                MessageBoxButton.OK, MessageBoxImage.Information);

        /// <summary>Formats a localized string with the user's regional number format.</summary>
        private static string LFormat(string key, params object?[] args) =>
            Localization.LocalizationManager.Instance.Format(key, args);
    }
}
