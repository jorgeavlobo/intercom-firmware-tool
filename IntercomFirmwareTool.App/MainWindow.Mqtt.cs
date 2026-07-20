using System;
using System.IO;
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

        private bool MqttEnabled => ChkMqtt.IsChecked == true;

        /// <summary>Wire up the MQTT masked password field. Called from the ctor
        /// after InitializeComponent (so TxtMqttPass exists) and before the first
        /// UpdateBuildEnabled (so the gate can read the field).</summary>
        private void InitMqttUi()
        {
            _mqttPass = new MaskedPasswordField(TxtMqttPass);
            _mqttPass.Changed += UpdateBuildEnabled;
            // Default the port here (not in XAML) so its TextChanged handler — which
            // calls UpdateBuildEnabled — can never fire during InitializeComponent,
            // before the password fields it reads are constructed.
            TxtMqttPort.Text = "1883";
            RefreshMqttPlaceholders();
        }

        // ---- Enable toggle + field-change plumbing --------------------------

        /// <summary>Show/hide the config panel with the enable box, then re-gate.</summary>
        private void ChkMqtt_Toggled(object sender, RoutedEventArgs e) => UpdateBuildEnabled();

        /// <summary>Any MQTT text field changed — re-evaluate the Build gate/cues.</summary>
        private void MqttField_TextChanged(object sender, TextChangedEventArgs e) => UpdateBuildEnabled();

        /// <summary>An MQTT checkbox (remote-shell) changed — re-evaluate the gate.</summary>
        private void MqttOption_Changed(object sender, RoutedEventArgs e) => UpdateBuildEnabled();

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
            var opts = new MqttOptions(
                TxtMqttHost.Text.Trim(),
                port,
                NullIfEmpty(TxtMqttUser.Text.Trim()),
                NullIfEmpty(_mqttPass?.Value ?? ""),
                caPem, certPem, keyPem,
                HostIpForHosts: null,
                AllowRemoteShell: ChkMqttRemoteShell.IsChecked == true);

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
