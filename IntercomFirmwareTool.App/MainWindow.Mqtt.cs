using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
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
    /// Advanced-section UI for the optional MQTT bridge (Phase 1d). Off by default:
    /// the whole panel is inert unless the "Install MQTT bridge" box is ticked. It
    /// collects an <see cref="MqttOptions"/> — broker host/port, optional
    /// username/password, optional TLS material (CA + client cert/key, as PEM
    /// files), and the gated remote command channel — and passes it as the optional
    /// fourth argument to <c>FwzProbe.BuildModifiedFwz</c>.
    ///
    /// The gate mirrors <c>MqttInstaller.Validate</c> so the user gets inline cues
    /// before Build; the Core validator still enforces every rule at build time
    /// (and again on the read-back), so this UI check is guidance, not the guard.
    /// </summary>
    public partial class MainWindow
    {
        // Selected PEM file paths (null = not chosen). The bytes are read at Build
        // time, mirroring how the SSH public key is read from its path — never held
        // in memory longer than the build call needs them.
        private string? _mqttCaPath;
        private string? _mqttCertPath;
        private string? _mqttKeyPath;

        // The broker password lives in this masked field, not in the TextBox (same
        // pattern as the root password). Reveal is a simple show/hide toggle.
        private MaskedPasswordField? _mqttPass;

        // Guards the programmatic (un)checking of the remote-shell box from
        // re-triggering its confirmation dialog.
        private bool _suppressMqttShell;

        private bool MqttEnabled => ChkMqtt.IsChecked == true;

        /// <summary>Wire up the MQTT masked password field + topic defaults. Called
        /// from the ctor after InitializeComponent (so the controls exist) and before
        /// the first UpdateBuildEnabled (so the gate can read the fields).</summary>
        private void InitMqttUi()
        {
            _mqttPass = new MaskedPasswordField(TxtMqttPass);
            _mqttPass.Changed += UpdateBuildEnabled;
            // Default the port here (not in XAML) so its TextChanged handler — which
            // calls UpdateBuildEnabled — can never fire during InitializeComponent,
            // before the password fields it reads are constructed.
            TxtMqttPort.Text = "1883";

            // Prefill the topic boxes with the record's defaults (Home Assistant set).
            var d = new MqttOptions("x"); // a throwaway just to read the default topics
            TxtMqttTopicRx.Text = d.TopicRx;
            TxtMqttTopicDump.Text = d.TopicDump;
            TxtMqttTopicStartDate.Text = d.TopicStartDate;
            TxtMqttTopicLastWill.Text = d.TopicLastWill;
            TxtMqttTopicKey.Text = d.TopicKey;
            TxtMqttTopicCmdResult.Text = d.TopicCmdResult;
            TxtMqttTopicFileContent.Text = d.TopicFileContent;

            RefreshMqttPlaceholders();
        }

        // ---- Enable toggle + field-change plumbing --------------------------

        /// <summary>Show/hide the config panel with the enable box, then re-gate.</summary>
        private void ChkMqtt_Toggled(object sender, RoutedEventArgs e) => UpdateBuildEnabled();

        /// <summary>Any MQTT text field changed — re-evaluate the Build gate/cues.
        /// (Also refreshes the host-IP row and remote-shell enablement via the
        /// UpdateBuildEnabled → UpdateMqttVisibility cascade.)</summary>
        private void MqttField_TextChanged(object sender, TextChangedEventArgs e) => UpdateBuildEnabled();

        /// <summary>The remote-shell DANGER toggle changed. Turning it ON asks for an
        /// explicit confirmation (it can run commands on the device, cleartext without
        /// TLS); declining reverts it.</summary>
        private void MqttOption_Changed(object sender, RoutedEventArgs e)
        {
            if (!_suppressMqttShell && sender == ChkMqttRemoteShell && ChkMqttRemoteShell.IsChecked == true)
            {
                var answer = MessageBox.Show(this, L("Msg_MqttRemoteShellConfirm"),
                    L("Cap_MqttRemoteShell"), MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (answer != MessageBoxResult.Yes)
                {
                    _suppressMqttShell = true;
                    ChkMqttRemoteShell.IsChecked = false;
                    _suppressMqttShell = false;
                }
            }
            UpdateBuildEnabled();
        }

        /// <summary>Show/hide the collapsible topics panel (prefilled with defaults).</summary>
        private void ChkMqttTopics_Toggled(object sender, RoutedEventArgs e) =>
            MqttTopicsPanel.Visibility = ChkMqttTopics.IsChecked == true
                ? Visibility.Visible : Visibility.Collapsed;

        /// <summary>Toggle whole-value reveal on the broker password.</summary>
        private void BtnMqttReveal_Click(object sender, RoutedEventArgs e)
        {
            if (_mqttPass != null) _mqttPass.Peek = !_mqttPass.Peek;
        }

        // ---- PEM file pickers (CA / client cert / client key) ---------------

        private void MqttPem_MouseDown(object sender, MouseButtonEventArgs e)
        {
            e.Handled = true; // act purely as a browse button (no caret/selection)
            PickMqttPemInto((TextBox)sender);
        }

        private void MqttPem_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (!IsActivationKey(e)) return;
            e.Handled = true;
            PickMqttPemInto((TextBox)sender);
        }

        private void PickMqttPemInto(TextBox box)
        {
            if (!_uiEnabled) return; // ignored while an operation is running
            string titleKey = box == TxtMqttCaPath ? "Dlg_MqttCa_Title"
                : box == TxtMqttCertPath ? "Dlg_MqttCert_Title"
                : "Dlg_MqttKey_Title";
            var dlg = new OpenFileDialog
            {
                Title = L(titleKey),
                Filter = L("Dlg_MqttPemFilter"),
            };
            if (dlg.ShowDialog(this) != true) return;

            string chosen = dlg.FileName;
            if (box == TxtMqttCaPath) _mqttCaPath = chosen;
            else if (box == TxtMqttCertPath) _mqttCertPath = chosen;
            else _mqttKeyPath = chosen;
            SetPathText(box, chosen);
            UpdateBuildEnabled();
        }

        private void MqttPemClear_Click(object sender, RoutedEventArgs e)
        {
            if (sender == BtnClearMqttCa) _mqttCaPath = null;
            else if (sender == BtnClearMqttCert) _mqttCertPath = null;
            else _mqttKeyPath = null;
            RefreshMqttPlaceholders();
            UpdateBuildEnabled();
        }

        /// <summary>Neutral "(optional: choose a PEM file)" placeholder on any TLS
        /// box with no selection; the chosen path otherwise. Re-run on a language
        /// switch (via RefreshPlaceholders) so the placeholder text follows.</summary>
        private void RefreshMqttPlaceholders()
        {
            SetMqttPemBox(TxtMqttCaPath, _mqttCaPath);
            SetMqttPemBox(TxtMqttCertPath, _mqttCertPath);
            SetMqttPemBox(TxtMqttKeyPath, _mqttKeyPath);
        }

        private void SetMqttPemBox(TextBox box, string? path)
        {
            if (path == null) { box.Text = L("Ph_MqttPem"); box.Foreground = Brushes.Gray; }
            else SetPathText(box, path);
        }

        // ---- Visibility (called from UpdateAdvancedVisibility) --------------

        /// <summary>The MQTT section follows the Advanced toggle, but stays visible
        /// while the bridge is enabled so an active build option is never hidden
        /// (mirrors the SSH key row). The config panel shows only when enabled.</summary>
        private void UpdateMqttVisibility(bool advanced)
        {
            MqttSection.Visibility = (advanced || MqttEnabled)
                ? Visibility.Visible : Visibility.Collapsed;
            MqttPanel.Visibility = MqttEnabled ? Visibility.Visible : Visibility.Collapsed;

            BtnClearMqttCa.IsEnabled = _uiEnabled && _mqttCaPath != null;
            BtnClearMqttCert.IsEnabled = _uiEnabled && _mqttCertPath != null;
            BtnClearMqttKey.IsEnabled = _uiEnabled && _mqttKeyPath != null;
            BtnMqttTest.IsEnabled = _uiEnabled;

            UpdateMqttHostIpVisibility();
            UpdateRemoteShellEnabled();
        }

        /// <summary>The host-IP row applies only when the broker is a hostname (an IP
        /// host needs no bt_hosts mapping). Hidden otherwise.</summary>
        private void UpdateMqttHostIpVisibility()
        {
            string host = TxtMqttHost.Text.Trim();
            bool hostIsName = host.Length > 0 && !IPAddress.TryParse(host, out _);
            var vis = (MqttEnabled && hostIsName) ? Visibility.Visible : Visibility.Collapsed;
            LblMqttHostIp.Visibility = vis;
            TxtMqttHostIp.Visibility = vis;
        }

        /// <summary>The remote command channel is a DANGER option: keep it disabled
        /// until client authentication is configured (user+pass or mutual TLS), and
        /// drop it if the auth that justified it is later removed.</summary>
        private void UpdateRemoteShellEnabled()
        {
            bool hasAuth = TxtMqttUser.Text.Trim().Length > 0 && (_mqttPass?.Value.Length ?? 0) > 0;
            bool mutualTls = _mqttCaPath != null && _mqttCertPath != null && _mqttKeyPath != null;
            bool authOk = hasAuth || mutualTls;

            ChkMqttRemoteShell.IsEnabled = _uiEnabled && MqttEnabled && authOk;
            if (!authOk && ChkMqttRemoteShell.IsChecked == true)
            {
                _suppressMqttShell = true;   // don't re-open the confirmation dialog
                ChkMqttRemoteShell.IsChecked = false;
                _suppressMqttShell = false;
            }
        }

        // ---- Test connection (raw TCP reachability, dependency-free) ---------

        private async void BtnMqttTest_Click(object sender, RoutedEventArgs e)
        {
            string host = TxtMqttHost.Text.Trim();
            if (host.Length == 0 || !IsValidPortText(TxtMqttPort.Text))
            {
                SetMqttTestStatus(L("MqttTest_NeedHostPort"), error: true);
                return;
            }
            int port = int.Parse(TxtMqttPort.Text.Trim());

            BtnMqttTest.IsEnabled = false;
            SetMqttTestStatus(L("MqttTest_Testing"), error: false);
            bool ok = false;
            string? err = null;
            try
            {
                // A plain TCP connect confirms the broker host/port is reachable; it
                // does NOT check MQTT credentials or TLS (those surface at build/run).
                using var client = new TcpClient();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(4));
                await client.ConnectAsync(host, port, cts.Token);
                ok = client.Connected;
            }
            catch (OperationCanceledException) { err = L("MqttTest_Timeout"); }
            catch (Exception ex) { err = SafeMessage(ex); }

            BtnMqttTest.IsEnabled = _uiEnabled;
            SetMqttTestStatus(
                ok ? LF("Fmt_MqttTest_Ok", host, port) : LF("Fmt_MqttTest_Fail", err ?? ""),
                error: !ok);
        }

        private void SetMqttTestStatus(string text, bool error)
        {
            TxtMqttTestStatus.Text = text;
            TxtMqttTestStatus.Foreground = error ? ErrorBrush : ReadyBrush;
            TxtMqttTestStatus.Visibility = Visibility.Visible;
        }

        // ---- Validation (mirror of MqttInstaller.Validate for inline cues) --

        private static bool IsValidPortText(string s) =>
            int.TryParse(s.Trim(), out int p) && p >= 1 && p <= 65535;

        /// <summary>True when the MQTT config is acceptable to build (or the bridge
        /// is off). Host presence is required; the rest is delegated to
        /// <see cref="MqttStructuralError"/>.</summary>
        private bool MqttOkToBuild()
        {
            if (!MqttEnabled) return true;
            if (TxtMqttHost.Text.Trim().Length == 0) return false;
            return MqttStructuralError() == null;
        }

        /// <summary>A localized one-line reason the MQTT config can't build —
        /// EXCLUDING the missing-host case, which the "still needed" list covers —
        /// or null when the structural rules pass. Mirrors MqttInstaller.Validate.</summary>
        private string? MqttStructuralError()
        {
            if (!MqttEnabled) return null;
            if (!IsValidPortText(TxtMqttPort.Text)) return L("MqttHint_Port");

            bool hasUser = TxtMqttUser.Text.Trim().Length > 0;
            bool hasPass = (_mqttPass?.Value.Length ?? 0) > 0;
            if (hasUser != hasPass) return L("MqttHint_UserPass");

            bool hasCert = _mqttCertPath != null;
            bool hasKey = _mqttKeyPath != null;
            if (hasCert != hasKey) return L("MqttHint_CertKey");

            bool hasCa = _mqttCaPath != null;
            if (hasCert && hasKey && !hasCa) return L("MqttHint_MutualCa");

            bool hasAuth = hasUser && hasPass;
            bool mutualTls = hasCa && hasCert && hasKey;
            if (ChkMqttRemoteShell.IsChecked == true && !(hasAuth || mutualTls))
                return L("MqttHint_ShellAuth");

            // Topic sanity — catch the obvious mistakes inline (empty; a publish
            // topic with a space or a '+'/'#' wildcard). The subtler rules (a valid
            // TopicRx subscription filter; TopicRx not matching a publish topic) stay
            // with the Core validator's pre-build popup.
            if (TxtMqttTopicRx.Text.Trim().Length == 0) return L("MqttHint_Topic");
            var publishTopics = new[]
            {
                TxtMqttTopicDump, TxtMqttTopicStartDate, TxtMqttTopicLastWill,
                TxtMqttTopicKey, TxtMqttTopicCmdResult, TxtMqttTopicFileContent,
            };
            foreach (var box in publishTopics)
            {
                string v = box.Text.Trim();
                if (v.Length == 0 || v.IndexOfAny(new[] { ' ', '\t', '+', '#' }) >= 0)
                    return L("MqttHint_Topic");
            }

            return null;
        }

        // ---- Build integration ----------------------------------------------

        /// <summary>
        /// Builds the <see cref="MqttOptions"/> to pass to the build, reading the
        /// selected PEM files. Returns true (with mqttOpts null) when the bridge is
        /// off; true with a populated value when enabled and valid; false after
        /// showing a popup when a file can't be read or Core validation fails —
        /// in which case the caller must abort the build.
        /// </summary>
        private bool TryBuildMqttOptions(out MqttOptions? mqttOpts)
        {
            mqttOpts = null;
            if (!MqttEnabled) return true;

            string? caPem = null, certPem = null, keyPem = null;
            if (!TryReadPem(_mqttCaPath, out caPem)) return false;
            if (!TryReadPem(_mqttCertPath, out certPem)) return false;
            if (!TryReadPem(_mqttKeyPath, out keyPem)) return false;

            int port = int.TryParse(TxtMqttPort.Text.Trim(), out int p) ? p : 1883;
            // The host-IP override only applies to a hostname broker; ignore any stale
            // value when the host is an IP (matches MqttInstaller's own handling).
            string hostTrim = TxtMqttHost.Text.Trim();
            bool hostIsName = hostTrim.Length > 0 && !IPAddress.TryParse(hostTrim, out _);
            string? hostIp = hostIsName ? NullIfEmpty(TxtMqttHostIp.Text.Trim()) : null;

            var opts = new MqttOptions(
                hostTrim,
                port,
                NullIfEmpty(TxtMqttUser.Text.Trim()),
                NullIfEmpty(_mqttPass?.Value ?? ""),
                caPem, certPem, keyPem,
                HostIpForHosts: hostIp,
                AllowRemoteShell: ChkMqttRemoteShell.IsChecked == true)
            {
                // Topics are prefilled with the record's defaults, so an untouched
                // panel reproduces those exactly; a customized one overrides them.
                TopicRx = TxtMqttTopicRx.Text.Trim(),
                TopicDump = TxtMqttTopicDump.Text.Trim(),
                TopicStartDate = TxtMqttTopicStartDate.Text.Trim(),
                TopicLastWill = TxtMqttTopicLastWill.Text.Trim(),
                TopicKey = TxtMqttTopicKey.Text.Trim(),
                TopicCmdResult = TxtMqttTopicCmdResult.Text.Trim(),
                TopicFileContent = TxtMqttTopicFileContent.Text.Trim(),
            };

            // Surface the Core validator's exact (localized) message as a clean
            // popup before the build starts. The build path validates again, so a
            // slip here is caught either way — this just gives a clearer failure.
            try
            {
                MqttInstaller.Validate(opts);
            }
            catch (ArgumentException ex)
            {
                MessageBox.Show(this, SafeMessage(ex), L("Cap_MqttInvalid"),
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            mqttOpts = opts;
            return true;
        }

        private bool TryReadPem(string? path, out string? pem)
        {
            pem = null;
            if (path == null) return true;
            try { pem = File.ReadAllText(path); return true; }
            catch (Exception ex)
            {
                MessageBox.Show(this, LF("Fmt_Msg_MqttReadPem", SafeMessage(ex)),
                    L("Cap_MqttReadPem"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
        }

        private static string? NullIfEmpty(string s) => s.Length == 0 ? null : s;
    }
}
