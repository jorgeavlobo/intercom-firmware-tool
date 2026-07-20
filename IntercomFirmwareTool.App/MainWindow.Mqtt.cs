using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;              // Oid (serverAuth EKU on the TLS probe chain)
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Automation;   // AutomationProperties.SetName (per-file using; not shared across partials)
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using IntercomFirmwareTool.Core;
using Microsoft.Win32;
using MQTTnet;
using MQTTnet.Formatter;             // MqttProtocolVersion.V311 (pin the test to the device's 3.1.1)

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

        // Bumped every time a connection-affecting field changes (via
        // ClearMqttTestStatus). A test captures it before connecting and only writes
        // its result if the value is unchanged — so a slow CONNECT that finishes after
        // the user has edited the config can't repaint a stale ✓/✗ for settings that
        // are no longer on screen.
        private int _mqttTestGen;

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

            // HA auto-discovery defaults set here (not in XAML) for the same reason
            // as the port above: their Checked/TextChanged handlers call
            // UpdateBuildEnabled, which reads the masked password fields — those must
            // already be constructed, which they are by the time InitMqttUi runs.
            // On by default (plug-and-play; read-only entities); node id prefilled.
            TxtMqttHaNodeId.Text = d.HaNodeId;
            ChkMqttHaDiscovery.IsChecked = true;

            RefreshMqttPlaceholders();
        }

        // ---- Enable toggle + field-change plumbing --------------------------

        /// <summary>Show/hide the config panel with the enable box, then re-gate.</summary>
        private void ChkMqtt_Toggled(object sender, RoutedEventArgs e)
        {
            // Toggling the bridge on/off is a config change: invalidate any in-flight
            // test (via the generation bump) and hide a prior result, so a stale ✓/✗
            // can't linger for a config that is no longer enabled.
            ClearMqttTestStatus();
            UpdateBuildEnabled();
        }

        /// <summary>Any MQTT text field changed — clear a stale test result and
        /// re-evaluate the Build gate/cues. (Also refreshes the host-IP row and
        /// remote-shell enablement via the UpdateBuildEnabled → UpdateMqttVisibility
        /// cascade.)</summary>
        private void MqttField_TextChanged(object sender, TextChangedEventArgs e)
        {
            ClearMqttTestStatus();
            UpdateBuildEnabled();
        }

        /// <summary>Normalize the broker username when the field commits, so the value
        /// shown always matches the (trimmed) value used at test/build time — no silent
        /// discrepancy between display and use. The username is trimmed like an email in
        /// a sign-in form; the password is deliberately left verbatim, since leading or
        /// trailing whitespace can be significant there.</summary>
        private void MqttUser_LostFocus(object sender, RoutedEventArgs e)
        {
            string trimmed = TxtMqttUser.Text.Trim();
            // Only reassign when it actually changes: an equal value raises no
            // TextChanged, so this won't clear a fresh test result on a plain tab-out.
            if (trimmed != TxtMqttUser.Text) TxtMqttUser.Text = trimmed;
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

            // The three "clear file" buttons share one glyph, so give each a distinct,
            // localized accessible name ("Clear the <field> file") — otherwise a screen
            // reader announces all three identically. Set here (not in XAML) so the
            // names follow a language switch, which re-runs this method.
            AutomationProperties.SetName(BtnClearMqttCa, ClearFileName("Field_MqttCa"));
            AutomationProperties.SetName(BtnClearMqttCert, ClearFileName("Field_MqttClientCert"));
            AutomationProperties.SetName(BtnClearMqttKey, ClearFileName("Field_MqttClientKey"));
        }

        // "Clear the <field label> file" with the label's trailing colon trimmed.
        private string ClearFileName(string fieldKey) =>
            LF("Fmt_Aria_MqttClearFile", L(fieldKey).TrimEnd(':', '：', ' '));

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

            // Mirror the device: for a hostname broker with a host-IP override, connect
            // to that IPv4 (the address bt_hosts pins on the device) so the test hits
            // the same endpoint the firmware will — while still validating the broker
            // certificate against the hostname (TLS target host below).
            bool hostIsName = !IPAddress.TryParse(host, out _);
            string? hostIp = hostIsName ? NullIfEmpty(TxtMqttHostIp.Text.Trim()) : null;
            string connectHost = hostIp ?? host;

            // Read the auth + TLS material the same way the build does, so the test
            // exercises exactly what will be installed. A read failure shows its own
            // popup and aborts the test — clear any prior ✓/✗ first so a stale
            // "Connected" can't linger for a config whose retest never ran.
            string? user = NullIfEmpty(TxtMqttUser.Text.Trim());
            string? pass = NullIfEmpty(_mqttPass?.Value ?? "");
            if (!TryReadPem(_mqttCaPath, out string? caPem)) { ClearMqttTestStatus(); return; }
            if (!TryReadPem(_mqttCertPath, out string? certPem)) { ClearMqttTestStatus(); return; }
            if (!TryReadPem(_mqttKeyPath, out string? keyPem)) { ClearMqttTestStatus(); return; }

            _mqttTesting = true;
            BtnMqttTest.IsEnabled = false;
            SetMqttTestStatus(L("MqttTest_Testing"), error: false);
            int gen = _mqttTestGen;   // config snapshot; a later edit invalidates this result
            bool ok = false;
            string? err = null;
            try
            {
                ok = await MqttTestConnectAsync(connectHost, host, port, user, pass, caPem, certPem, keyPem);
            }
            catch (OperationCanceledException) { err = L("MqttTest_Timeout"); }
            catch (Exception ex) { err = SafeMessage(ex); }
            finally { _mqttTesting = false; }

            BtnMqttTest.IsEnabled = _uiEnabled;
            // If a connection-affecting field changed while the CONNECT was in flight,
            // its result no longer describes the visible config — the edit already
            // cleared the status line, so leave it hidden rather than repaint a stale one.
            if (gen != _mqttTestGen) return;
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
            string host, string tlsHost, int port, string? user, string? pass,
            string? caPem, string? certPem, string? keyPem)
        {
            var factory = new MqttClientFactory();
            using var client = factory.CreateMqttClient();

            // The mutual-TLS client cert must stay alive through ConnectAsync (the
            // handshake uses it) and be disposed afterwards — X509Certificate2 holds
            // a native key handle. Tracked here, disposed in the finally below.
            X509Certificate2? clientCert = null;
            try
            {
                var builder = new MqttClientOptionsBuilder()
                    .WithTcpServer(host, port)
                    // Mirror the on-device bridge, which speaks MQTT 3.1.1 through the
                    // bundled mosquitto_pub/_sub. MQTTnet 5.x flipped its CONNECT default
                    // to 5.0 (a documented breaking change vs the 4.3.x this replaced, which
                    // defaulted to 3.1.1), so pin 3.1.1 explicitly: otherwise this pre-flight
                    // test could fail against an older broker that accepts the device's 3.1.1
                    // client but not a 5.0 CONNECT — a false negative for a broker the device
                    // would actually reach. Keeps the test a faithful proxy for the device.
                    .WithProtocolVersion(MqttProtocolVersion.V311)
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
                    // Validate (and SNI) against the hostname even when the TCP endpoint
                    // is a host-IP override — otherwise the broker cert's name wouldn't
                    // match the IP we dialed and the handshake would fail spuriously.
                    var tls = new MqttClientTlsOptionsBuilder().UseTls(true).WithTargetHost(tlsHost);

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

                            // The CA PEM may be a bundle (root + intermediates), not a
                            // single cert — CreateFromPem would read only the first and
                            // reject a broker whose chain needs the intermediates.
                            var caCerts = new X509Certificate2Collection();
                            caCerts.ImportFromPem(caPem);
                            using var chain = new X509Chain();
                            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                            // Enforce the serverAuth EKU, as SslStream would: a cert that
                            // chains to the CA and matches the host but isn't valid for TLS
                            // server authentication (e.g. clientAuth-only) must fail here
                            // too — otherwise the test goes green for a broker the device's
                            // mosquitto client would reject during certificate-purpose
                            // validation.
                            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1")); // id-kp-serverAuth
                            // Every cert in the user's CA PEM is a trust anchor — matching
                            // mosquitto/OpenSSL `--cafile`, which trusts each cert in the
                            // file directly, self-signed or not. (Anchoring only the
                            // self-issued ones would false-negative a broker whose --cafile
                            // is an intermediate.) CustomRootTrust terminates the chain at
                            // the first of these it reaches.
                            foreach (var c in caCerts)
                                chain.ChainPolicy.CustomTrustStore.Add(c);
                            // Also offer the intermediates the broker sent in its own
                            // handshake (on ctx.Chain): with a root-only CA file, a
                            // leaf+intermediate chain must still build — exactly as the
                            // device's MQTT client would validate it. These certs are
                            // owned by ctx.Chain, so they are referenced, not disposed.
                            if (ctx.Chain != null)
                                foreach (var el in ctx.Chain.ChainElements)
                                    chain.ChainPolicy.ExtraStore.Add(el.Certificate);
                            try
                            {
                                using var server = new X509Certificate2(ctx.Certificate);
                                return chain.Build(server);
                            }
                            finally
                            {
                                foreach (var c in caCerts) c.Dispose();
                            }
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
            _mqttTestGen++;   // invalidate any in-flight test result for the old config
            TxtMqttTestStatus.Text = "";
            TxtMqttTestStatus.Visibility = Visibility.Collapsed;
        }

        // ---- Validation (mirror of MqttInstaller.Validate for inline cues) --

        private static bool IsValidPortText(string s) =>
            int.TryParse(s.Trim(), out int p) && p >= 1 && p <= 65535;

        /// <summary>A valid broker host: an IP address, or a hostname of 1..253 chars
        /// whose dot-separated labels are 1..63 chars of [A-Za-z0-9-] and don't start
        /// or end with '-'. Kept in lockstep with MqttInstaller.IsValidHost so the
        /// inline gate never enables Build for a host Core would reject.</summary>
        private static bool IsValidMqttHost(string host)
        {
            if (IPAddress.TryParse(host, out _)) return true;
            if (host.Length == 0 || host.Length > 253) return false;
            foreach (var label in host.Split('.'))
            {
                if (label.Length == 0 || label.Length > 63) return false;
                if (label[0] == '-' || label[^1] == '-') return false;
                foreach (char c in label)
                    if (!(char.IsAsciiLetterOrDigit(c) || c == '-')) return false;
            }
            return true;
        }

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

            // Broker host must be a valid IP or hostname (mirror MqttInstaller's
            // IsValidHost) — otherwise Build would enable and then abort with a Core
            // validation popup. The empty-host case is the "still needed" list's job.
            string hostTrim = TxtMqttHost.Text.Trim();
            if (hostTrim.Length > 0 && !IsValidMqttHost(hostTrim)) return L("MqttHint_Host");

            // Host-IP override (only used when the broker is a hostname) must be a
            // valid IPv4 if supplied — Core requires it, so mirror that here rather
            // than let Build enable and then abort with a validation popup.
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

            // Credentials are sourced into the shell-quoted .conf; a CR/LF would make a
            // multi-line value and break auth, so Core requires each single-line —
            // mirror that (a pasted multi-line value would otherwise pass the gate).
            if (TxtMqttUser.Text.Trim().IndexOfAny(NewlineChars) >= 0 ||
                (_mqttPass?.Value.IndexOfAny(NewlineChars) ?? -1) >= 0)
                return L("MqttHint_CredentialNewline");

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
            // UI blocks a config Core would accept): every topic must be non-empty and
            // single-line, and a publish topic must not carry a '+'/'#' wildcard.
            // Spaces are allowed (the .conf quotes values). The subtler rules (a valid
            // TopicRx subscription filter; TopicRx not matching a publish topic) stay
            // with the Core popup.
            var allTopics = new[]
            {
                TxtMqttTopicRx, TxtMqttTopicDump, TxtMqttTopicStartDate, TxtMqttTopicLastWill,
                TxtMqttTopicKey, TxtMqttTopicCmdResult, TxtMqttTopicFileContent,
            };
            foreach (var box in allTopics)
            {
                // Mirror Core verbatim (do NOT Trim): reject only a whitespace-only
                // topic or one with a CR/LF, preserving the value exactly as typed —
                // Core quotes it in the .conf, so leading/trailing/internal spaces are
                // kept, and the gate stays a faithful mirror of what will be installed.
                string v = box.Text;
                if (string.IsNullOrWhiteSpace(v) || v.IndexOfAny(NewlineChars) >= 0) return L("MqttHint_Topic");
            }
            var publishTopics = new[]
            {
                TxtMqttTopicDump, TxtMqttTopicStartDate, TxtMqttTopicLastWill,
                TxtMqttTopicKey, TxtMqttTopicCmdResult, TxtMqttTopicFileContent,
            };
            foreach (var box in publishTopics)
                if (box.Text.IndexOfAny(new[] { '+', '#' }) >= 0) return L("MqttHint_Topic");

            return null;
        }

        // CR/LF: values sourced into the shell .conf must be single-line (see Core).
        private static readonly char[] NewlineChars = { '\r', '\n' };

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

            // Parse the TLS material now — the same load the Test path does — so a
            // wrong/corrupt CA, cert or key fails here with a clear popup instead of
            // building a valid-looking FWZ whose mosquitto TLS silently fails at boot
            // (Core only checks presence/pairing, not that the PEM actually loads).
            if (!TryValidatePems(caPem, certPem, keyPem)) return false;

            // The gate blocks an invalid port before Build; if we somehow reach here
            // with unparseable text, fail closed with 0 so Core's Validate rejects it
            // (a clean popup) rather than silently installing the 1883 default.
            int port = int.TryParse(TxtMqttPort.Text.Trim(), out int p) ? p : 0;
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
                AllowRemoteShell: ChkMqttRemoteShell.IsChecked == true,
                // Unchecked (default) = the low-footprint OpenWebNet socket monitor;
                // checked = force the faithful tcpdump + filter.py capture back-end.
                UseTcpdumpCapture: ChkMqttTcpdump.IsChecked == true,
                // Publish HA discovery configs so entities appear automatically. ON
                // by default when the bridge is installed (plug-and-play); read-only
                // entities, so secure-by-default holds.
                EnableHaDiscovery: ChkMqttHaDiscovery.IsChecked == true)
            {
                // Topics are prefilled with the record's defaults, so an untouched
                // panel reproduces those exactly; a customized one overrides them.
                // Passed VERBATIM (no Trim) so the installed topic is exactly what the
                // user typed — Core does not trim (it quotes the value in the .conf and
                // rejects only whitespace-only/newlines), so trimming here would have
                // the UI silently drop leading/trailing spaces Core would keep.
                TopicRx = TxtMqttTopicRx.Text,
                TopicDump = TxtMqttTopicDump.Text,
                TopicStartDate = TxtMqttTopicStartDate.Text,
                TopicLastWill = TxtMqttTopicLastWill.Text,
                TopicKey = TxtMqttTopicKey.Text,
                TopicCmdResult = TxtMqttTopicCmdResult.Text,
                TopicFileContent = TxtMqttTopicFileContent.Text,
                // HA device/node id — distinct per unit lets several bridges coexist
                // on one broker. Fall back to the record default if the field was
                // cleared, so an empty box doesn't force a validation error.
                HaNodeId = NullIfEmpty(TxtMqttHaNodeId.Text.Trim()) ?? new MqttOptions("x").HaNodeId,
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
            string text;
            try { text = File.ReadAllText(path); }
            catch (Exception ex)
            {
                // Name the file (path is non-null here) plus the reason, so with
                // several PEMs configured the user knows which one failed to read.
                MessageBox.Show(this, LF("Fmt_Msg_MqttReadPem", path, SafeMessage(ex)),
                    L("Cap_MqttReadPem"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            // A selected file that reads empty must fail, not silently drop TLS: an
            // empty CA makes MqttOptions.HasTls false, so the build would install a
            // plaintext config even though the UI still shows a chosen file. Guard both
            // the Test and Build paths here.
            if (string.IsNullOrWhiteSpace(text))
            {
                MessageBox.Show(this, LF("Fmt_Msg_MqttEmptyPem", path),
                    L("Cap_MqttReadPem"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            pem = text;
            return true;
        }

        /// <summary>
        /// Parses the selected TLS material the same way the Test path does, so a
        /// wrong/corrupt CA, client cert or key is rejected at Build time (clean popup)
        /// rather than baked into a firmware whose mosquitto TLS fails at boot. The CA
        /// must yield at least one certificate; the client cert + key must load together
        /// (which also verifies the key matches the certificate). Returns true when the
        /// material is absent or valid; false after a popup when it won't parse.
        /// </summary>
        private bool TryValidatePems(string? caPem, string? certPem, string? keyPem)
        {
            // The CA and client-CERTIFICATE fields are installed as WORLD-READABLE
            // files on the device (ca.crt / client.crt, mode 0644). A private key in
            // either — e.g. an accidentally-picked combined cert+key bundle — would be
            // copied there in the clear, leaking it. Reject it up front; the private
            // key belongs only in the client-key field (installed 0600).
            if (caPem != null && ContainsPrivateKey(caPem))
                return PemInvalid(LF("Fmt_Msg_MqttKeyInCert", _mqttCaPath ?? ""));
            if (certPem != null && ContainsPrivateKey(certPem))
                return PemInvalid(LF("Fmt_Msg_MqttKeyInCert", _mqttCertPath ?? ""));

            if (caPem != null)
            {
                bool ok = false;
                try
                {
                    var ca = new X509Certificate2Collection();
                    ca.ImportFromPem(caPem);
                    ok = ca.Count > 0;
                    foreach (var c in ca) c.Dispose();
                }
                catch { ok = false; }
                // Only the CA file is involved here, so name it specifically.
                if (!ok) return PemInvalid(LF("Fmt_Msg_MqttBadPem", _mqttCaPath ?? ""));
            }

            if (certPem != null && keyPem != null)
            {
                // The load uses BOTH files (and verifies they pair up), so a failure
                // can be the cert, the key, or a mismatch — name both, not just the cert.
                try { using var cert = X509Certificate2.CreateFromPem(certPem, keyPem); }
                catch { return PemInvalid(LF("Fmt_Msg_MqttBadCertKey", _mqttCertPath ?? "", _mqttKeyPath ?? "")); }
            }
            return true;
        }

        // Any PEM private-key block: -----BEGIN [RSA|EC|ENCRYPTED] PRIVATE KEY----- all
        // end in "PRIVATE KEY-----", and a certificate's base64 body never does.
        private static bool ContainsPrivateKey(string pem) =>
            pem.Contains("PRIVATE KEY-----", StringComparison.Ordinal);

        private bool PemInvalid(string message)
        {
            MessageBox.Show(this, message, L("Cap_MqttReadPem"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        private static string? NullIfEmpty(string s) => s.Length == 0 ? null : s;
    }
}
