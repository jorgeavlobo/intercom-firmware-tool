using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using IntercomFirmwareTool.Core;
using Microsoft.Win32;
using MQTTnet;
using MQTTnet.Client;

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

        // True while a "Test connection" is in flight, so the visibility pass can't
        // re-enable the Test button under it (a field edit would otherwise re-enable
        // it and allow a second, concurrent test).
        private bool _mqttTesting;

        private bool MqttEnabled => ChkMqtt.IsChecked == true;

        /// <summary>Wire up the MQTT masked password field + topic defaults. Called
        /// from the ctor after InitializeComponent (so the controls exist) and before
        /// the first UpdateBuildEnabled (so the gate can read the fields).</summary>
        private void InitMqttUi()
        {
            _mqttPass = new MaskedPasswordField(TxtMqttPass);
            _mqttPass.Changed += ClearMqttTestStatus;   // a changed password invalidates a prior test
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

        /// <summary>Any MQTT text field changed — clear a stale test result and
        /// re-evaluate the Build gate/cues. (Also refreshes the host-IP row and
        /// remote-shell enablement via the UpdateBuildEnabled → UpdateMqttVisibility
        /// cascade.)</summary>
        private void MqttField_TextChanged(object sender, TextChangedEventArgs e)
        {
            ClearMqttTestStatus();
            UpdateBuildEnabled();
        }

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
            ClearMqttTestStatus();   // TLS material changed → prior test no longer valid
            UpdateBuildEnabled();
        }

        private void MqttPemClear_Click(object sender, RoutedEventArgs e)
        {
            if (sender == BtnClearMqttCa) _mqttCaPath = null;
            else if (sender == BtnClearMqttCert) _mqttCertPath = null;
            else _mqttKeyPath = null;
            RefreshMqttPlaceholders();
            ClearMqttTestStatus();
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

            // Lock the whole MQTT section during a build/verify op (like the other
            // build inputs) so the visible config can't drift from the mqttOpts
            // snapshot captured for the running build.
            ChkMqtt.IsEnabled = _uiEnabled;
            MqttPanel.IsEnabled = _uiEnabled;

            BtnClearMqttCa.IsEnabled = _uiEnabled && _mqttCaPath != null;
            BtnClearMqttCert.IsEnabled = _uiEnabled && _mqttCertPath != null;
            BtnClearMqttKey.IsEnabled = _uiEnabled && _mqttKeyPath != null;
            BtnMqttTest.IsEnabled = _uiEnabled && !_mqttTesting;

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

        // ---- Test connection (real MQTT CONNECT via MQTTnet) ----------------

        private async void BtnMqttTest_Click(object sender, RoutedEventArgs e)
        {
            string host = TxtMqttHost.Text.Trim();
            if (host.Length == 0 || !IsValidPortText(TxtMqttPort.Text))
            {
                SetMqttTestStatus(L("MqttTest_NeedHostPort"), error: true);
                return;
            }
            // Only test a config that would actually build — otherwise the test could
            // connect anonymously (user without password) or with partial TLS and
            // report a success the build would reject. Surface the same cue.
            if (MqttStructuralError() is string structuralError)
            {
                SetMqttTestStatus(structuralError, error: true);
                return;
            }
            int port = int.Parse(TxtMqttPort.Text.Trim());

            // Read the auth + TLS material the same way the build does, so the test
            // exercises exactly what will be installed.
            string? user = NullIfEmpty(TxtMqttUser.Text.Trim());
            string? pass = NullIfEmpty(_mqttPass?.Value ?? "");
            if (!TryReadPem(_mqttCaPath, out string? caPem)) return;
            if (!TryReadPem(_mqttCertPath, out string? certPem)) return;
            if (!TryReadPem(_mqttKeyPath, out string? keyPem)) return;

            _mqttTesting = true;
            BtnMqttTest.IsEnabled = false;
            SetMqttTestStatus(L("MqttTest_Testing"), error: false);
            bool ok = false;
            string? err = null;
            try
            {
                ok = await MqttTestConnectAsync(host, port, user, pass, caPem, certPem, keyPem);
            }
            catch (OperationCanceledException) { err = L("MqttTest_Timeout"); }
            catch (Exception ex) { err = SafeMessage(ex); }
            finally { _mqttTesting = false; }

            BtnMqttTest.IsEnabled = _uiEnabled;
            SetMqttTestStatus(
                ok ? LF("Fmt_MqttTest_Ok", host, port)
                   : LF("Fmt_MqttTest_Fail", err ?? L("MqttTest_Refused")),
                error: !ok);
        }

        /// <summary>
        /// Opens a real MQTT connection with the configured credentials and TLS,
        /// then disconnects. Returns true on a successful CONNACK; throws with a
        /// broker/TLS reason otherwise. This exercises auth and TLS — not just
        /// reachability — so a bad password or an untrusted certificate is caught
        /// here rather than only at runtime on the device.
        /// </summary>
        private static async Task<bool> MqttTestConnectAsync(
            string host, int port, string? user, string? pass,
            string? caPem, string? certPem, string? keyPem)
        {
            var factory = new MqttFactory();
            using var client = factory.CreateMqttClient();

            // The mutual-TLS client cert must stay alive through ConnectAsync (the
            // handshake uses it) and be disposed afterwards — X509Certificate2 holds
            // a native key handle. Tracked here, disposed in the finally below.
            X509Certificate2? clientCert = null;
            try
            {
                var builder = new MqttClientOptionsBuilder()
                    .WithTcpServer(host, port)
                    // Unique per test so two app instances testing the same broker
                    // don't collide on client ID (which would disconnect one another).
                    .WithClientId("intercom-fw-tool-conn-test-" + Guid.NewGuid().ToString("N"))
                    .WithCleanSession(true)
                    .WithTimeout(TimeSpan.FromSeconds(6));

                if (user != null && pass != null)
                    builder = builder.WithCredentials(user, pass);

                bool wantTls = caPem != null || (certPem != null && keyPem != null);
                if (wantTls)
                {
                    var tls = new MqttClientTlsOptionsBuilder().UseTls(true);

                    if (caPem != null)
                    {
                        // Validate the broker certificate against the supplied CA as a
                        // custom trust root (the CA is provided precisely because it is
                        // not in the machine store). Everything is built and disposed
                        // inside the handler (per handshake) so no certificate handle
                        // leaks across repeated tests.
                        tls = tls.WithCertificateValidationHandler(ctx =>
                        {
                            // A missing or name-mismatched server cert is a TLS failure
                            // that chain building does NOT cover — reject it outright so
                            // the test is a meaningful TLS check, then require the chain
                            // to build to the supplied CA.
                            if ((ctx.SslPolicyErrors & (SslPolicyErrors.RemoteCertificateNotAvailable
                                    | SslPolicyErrors.RemoteCertificateNameMismatch)) != 0)
                                return false;
                            using var ca = X509Certificate2.CreateFromPem(caPem);
                            using var chain = new X509Chain();
                            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                            chain.ChainPolicy.CustomTrustStore.Add(ca);
                            using var server = new X509Certificate2(ctx.Certificate);
                            return chain.Build(server);
                        });
                    }

                    if (certPem != null && keyPem != null)
                    {
                        // A PEM-loaded cert must be round-tripped through PKCS#12 or the
                        // private key is unusable for the handshake on Windows SChannel.
                        using var ephemeral = X509Certificate2.CreateFromPem(certPem, keyPem);
                        clientCert = new X509Certificate2(ephemeral.Export(X509ContentType.Pkcs12));
                        tls = tls.WithClientCertificates(new X509Certificate2Collection { clientCert });
                    }

                    builder = builder.WithTlsOptions(tls.Build());
                }

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
                MqttClientConnectResult res = await client.ConnectAsync(builder.Build(), cts.Token);
                bool ok = res.ResultCode == MqttClientConnectResultCode.Success;

                if (client.IsConnected)
                {
                    try { await client.DisconnectAsync(); } catch { /* best-effort close */ }
                }

                if (!ok)
                {
                    string reason = string.IsNullOrEmpty(res.ReasonString)
                        ? res.ResultCode.ToString()
                        : $"{res.ResultCode}: {res.ReasonString}";
                    throw new Exception(reason);
                }
                return true;
            }
            finally
            {
                // The client cert outlives the handshake; release its native key
                // handle now that ConnectAsync has returned (success or throw).
                clientCert?.Dispose();
            }
        }

        private void SetMqttTestStatus(string text, bool error)
        {
            TxtMqttTestStatus.Text = text;
            TxtMqttTestStatus.Foreground = error ? ErrorBrush : ReadyBrush;
            TxtMqttTestStatus.Visibility = Visibility.Visible;
            // LiveSetting alone is inert in WPF; raise the notification so screen
            // readers actually announce the test result (mirrors RenderStatus).
            AnnounceLiveRegion(TxtMqttTestStatus);
        }

        /// <summary>Hide a stale test result. Called when a connection-affecting field
        /// changes, so a green "Connected" from a previous config can't be mistaken
        /// for validation of the current (untested) one.</summary>
        private void ClearMqttTestStatus()
        {
            TxtMqttTestStatus.Text = "";
            TxtMqttTestStatus.Visibility = Visibility.Collapsed;
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

            // Host-IP override (only used when the broker is a hostname) must be a
            // valid IPv4 if supplied — Core requires it, so mirror that here rather
            // than let Build enable and then abort with a validation popup.
            string hostTrim = TxtMqttHost.Text.Trim();
            if (hostTrim.Length > 0 && !IPAddress.TryParse(hostTrim, out _))
            {
                string hip = TxtMqttHostIp.Text.Trim();
                if (hip.Length > 0 &&
                    !(IPAddress.TryParse(hip, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork))
                    return L("MqttHint_HostIp");
            }

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

            // Topic sanity — mirror the Core validator (do NOT be stricter, or the
            // UI blocks a config Core would accept): reject an empty topic, and a
            // '+'/'#' wildcard on a publish topic. Spaces are allowed (the .conf
            // quotes values). The subtler rules (a valid TopicRx subscription filter;
            // TopicRx not matching a publish topic) stay with the Core popup.
            if (TxtMqttTopicRx.Text.Trim().Length == 0) return L("MqttHint_Topic");
            var publishTopics = new[]
            {
                TxtMqttTopicDump, TxtMqttTopicStartDate, TxtMqttTopicLastWill,
                TxtMqttTopicKey, TxtMqttTopicCmdResult, TxtMqttTopicFileContent,
            };
            foreach (var box in publishTopics)
            {
                string v = box.Text.Trim();
                if (v.Length == 0 || v.IndexOfAny(new[] { '+', '#' }) >= 0)
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
