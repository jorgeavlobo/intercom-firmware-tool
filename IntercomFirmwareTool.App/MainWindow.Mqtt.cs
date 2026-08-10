using System;
using System.Collections.Generic;                // IReadOnlyList<BrokerCandidate>
using System.IO;
using System.Linq;                               // FirstOrDefault over discovery candidates
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;            // SendARP P/Invoke (broker-MAC capture)
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

        // The broker's MAC address, captured by ARP on a successful "Test connection"
        // (issue #43). It is the plaintext trust anchor for rediscovery: with no TLS,
        // the device only adopts a rescanned broker whose ARP MAC matches this. Null
        // until captured; dropped when the broker endpoint changes to a different
        // machine (see MqttBrokerField_TextChanged / BrokerStillAtCapturedMac).
        private string? _mqttBrokerMac;
        // The IPv4 the MAC was captured for — used to decide, on a later host/host-IP
        // edit, whether the anchor still describes the configured broker.
        private string? _mqttMacIp;
        // The reverse-DNS name (lowercased) offered for _mqttMacIp when the broker was
        // typed as a bare IP, so following that suggestion preserves the MAC.
        private string? _mqttMacSuggestedHost;
        // True while the async ARP + reverse-DNS capture runs after a good connect. The
        // Build gate reads it (MqttOkToBuild) so a build snapshot can't be taken with a
        // half-filled MAC; cleared in the capture's finally.
        private bool _mqttCapturing;

        // Guards the programmatic IP→hostname auto-promotion (host + host-IP written
        // together after a good plaintext test) from being seen as a user edit — which
        // would clear the just-captured MAC and the green test result. The endpoint is
        // unchanged (the hostname is pinned to the tested IP), so both must survive.
        private bool _suppressMqttBrokerInvalidation;

        // Guards a PROGRAMMATIC write to a generic MQTT field (via MqttField_TextChanged) so it
        // isn't treated as a user edit — used when the locked "go2rtc / HA host" field is auto-filled
        // to mirror the broker host (issue #111), so mirroring never clears the broker test result.
        private bool _suppressMqttFieldChange;

        // Active LAN broker discovery (#43, follow-up 2). mDNS runs in the background at
        // startup; the /24 scan is a heavier fallback run at most once, when the bridge is
        // enabled and mDNS found nothing. The pre-fill happens at most once and never
        // overwrites a broker the user already typed.
        private MqttBrokerDiscovery? _brokerDiscovery;
        private CancellationTokenSource? _discoveryCts;      // cancels all discovery on window close
        private CancellationTokenSource? _discoveryScanCts;  // cancels an in-flight /24 scan (bridge off)
        private Task? _mdnsTask;                              // the background mDNS run (awaited before a scan)
        private readonly List<BrokerCandidate> _lastScanResults = new();  // cached so a re-enable re-evaluates
        private bool _discoveryScanDone;
        // Home Assistant host fallback (issue #52): brokers port-confirmed on a discovered HA host,
        // cached like the scan results so a re-enable re-evaluates without re-probing. _haProbeDone
        // is the one-shot guard for that probe.
        private readonly List<BrokerCandidate> _haResults = new();
        private bool _haProbeDone;
        private bool _discoveryPrefillDone;                  // set ONLY after fields are actually pre-filled
        private bool _discoveryPrefillInFlight;              // one prefill/scan at a time (reentrancy gate)
        private bool _discoveryPrefillRerun;                 // an enable arrived while a prefill was in flight

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
            // Same reason for the camera fan-out ports (they also use MqttField_TextChanged):
            // set the defaults here, NOT via XAML Text=, so no handler runs mid-InitializeComponent.
            TxtMqttCameraVideoPort.Text = "40000";
            TxtMqttCameraAudioPort.Text = "40002";

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
            // Structured JSON bus payloads: on by default (the modern, HA-friendly format);
            // untick for raw frames. Set here (not in XAML) for the same reason as above.
            ChkMqttJsonPayload.IsChecked = true;
            // Broker rediscovery: on by default (#43/#44). It self-gates on the device
            // (needs a hostname config + a TLS trust anchor), so on-by-default is safe.
            ChkMqttRediscovery.IsChecked = true;

            RefreshMqttPlaceholders();

            // Kick off passive LAN discovery (mDNS) in the background so a candidate is
            // usually ready by the time the user enables the bridge. Best-effort and
            // non-throwing; cancelled when the window closes.
            _brokerDiscovery = new MqttBrokerDiscovery();
            _discoveryCts = new CancellationTokenSource();
            Closed += (_, _) => StopBrokerDiscovery();
            _mdnsTask = _brokerDiscovery.RunMdnsAsync(TimeSpan.FromSeconds(3), _discoveryCts.Token);
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

            // Enabling the bridge is the moment to pre-fill the broker from LAN discovery;
            // disabling it cancels an in-flight /24 scan and hides the discovery note.
            if (MqttEnabled) _ = TryPrefillBrokerFromDiscoveryAsync();
            else { try { _discoveryScanCts?.Cancel(); } catch { } SetMqttDiscoveryInfo(null); }
        }

        /// <summary>Pre-fill the broker fields from LAN discovery when the bridge is enabled:
        /// use an mDNS candidate found at startup, else run a one-time /24 scan. Fills the
        /// hostname + pinned IP (or just the IP) — the same canonical shape the Test-connection
        /// capture produces — then lets the user Test to capture the MAC. Never overwrites a
        /// broker the user already typed, and runs the heavy scan at most once.</summary>
        private async Task TryPrefillBrokerFromDiscoveryAsync()
        {
            // One-at-a-time gate. This is fire-and-forget from the toggle handler and reentrant
            // across awaits: a rapid off→on→off→on could otherwise start a second prefill (and a
            // second /24 scan) while the first is suspended at an await, and the two would
            // cancel/dispose each other's scan CTS. Every entry and await-continuation here runs
            // on the UI thread (no ConfigureAwait(false) in this method), so a plain bool suffices.
            // A re-enable that arrives while a pass is in flight is NOT dropped: it latches a rerun
            // so the finally can start a fresh pass — otherwise an off→on during a scan's
            // cancellation would leave the bridge enabled with no scan (the in-flight task exits
            // via the cancelled path and this second entry was rejected).
            if (_discoveryPrefillInFlight) { _discoveryPrefillRerun = true; return; }
            _discoveryPrefillInFlight = true;
            // Wrap the whole body: this runs fire-and-forget from the toggle handler, so it must
            // never fault (an unobserved exception would surface via UnobservedTaskException).
            try
            {
                if (_brokerDiscovery == null || _discoveryPrefillDone) return;
                if (TxtMqttHost.Text.Trim().Length > 0) return;   // user already entered a broker

                // Candidate pool = live mDNS candidates + the last scan's results (cached, so a
                // disable→re-enable re-evaluates without re-scanning). Only a PLAINTEXT broker can
                // be auto-configured: a TLS broker also needs a CA the discovery can't supply, so
                // pre-filling one would build a plaintext config against a TLS listener.
                var pool = BuildDiscoveryPool();

                // Nothing at all yet, and the background mDNS is still running (the user
                // enabled the bridge within its window)? Give it its full window to answer before
                // the heavier scan — a candidate may still be arriving. Then re-read.
                Task? mdns = _mdnsTask;
                if (pool.Count == 0 && mdns is { IsCompleted: false })
                {
                    SetMqttDiscoveryInfo(L("MqttDiscovering"));
                    try { await mdns.WaitAsync(TimeSpan.FromSeconds(4)); } catch { /* window/timeout */ }
                    if (!MqttEnabled || TxtMqttHost.Text.Trim().Length > 0) { SetMqttDiscoveryInfo(null); return; }
                    pool = BuildDiscoveryPool();
                }

                // Home Assistant host fallback (issue #52), BETWEEN direct MQTT mDNS and the /24
                // scan: the broker is very commonly co-hosted with HA, but the Mosquitto add-on does
                // NOT advertise _mqtt._tcp by default, while HA always advertises itself. So when the
                // MQTT mDNS layer found nothing, probe the configured MQTT port(s) on the discovered
                // HA host(s) — a candidate is cached ONLY once a broker actually answers there (a
                // port-confirming probe, never a blind pick) — before the heavier scan. Reuses the
                // in-flight-discovery CTS so a bridge-off cancels it, like the scan.
                if (pool.Count == 0 && !_haProbeDone && _brokerDiscovery.HaHostIps.Count > 0)
                {
                    SetMqttDiscoveryInfo(L("MqttDiscovering"));
                    _discoveryScanCts?.Cancel();
                    _discoveryScanCts?.Dispose();
                    var haCts = _discoveryScanCts = CancellationTokenSource.CreateLinkedTokenSource(
                        _discoveryCts?.Token ?? CancellationToken.None);
                    IReadOnlyList<BrokerCandidate> ha;
                    bool haCancelled;
                    try { ha = await Task.Run(() => _brokerDiscovery.ProbeHomeAssistantHostsAsync(haCts.Token), haCts.Token); }
                    catch { ha = System.Array.Empty<BrokerCandidate>(); }
                    finally
                    {
                        haCancelled = haCts.IsCancellationRequested;
                        if (ReferenceEquals(_discoveryScanCts, haCts)) _discoveryScanCts = null;
                        haCts.Dispose();
                    }
                    if (haCancelled) { SetMqttDiscoveryInfo(null); return; }   // retryable — don't burn the flag
                    _haProbeDone = true;
                    _haResults.Clear();
                    _haResults.AddRange(ha);
                    if (!MqttEnabled || TxtMqttHost.Text.Trim().Length > 0) { SetMqttDiscoveryInfo(null); return; }
                    pool = BuildDiscoveryPool();
                }

                // mDNS + HA found NOTHING → the /24 scan, once, cancellable when the bridge is
                // turned off (via _discoveryScanCts). mDNS advertises only plaintext _mqtt._tcp,
                // so any mDNS hit is a plaintext broker that is pre-filled below without a scan.
                if (pool.Count == 0 && !_discoveryScanDone)
                {
                    SetMqttDiscoveryInfo(L("MqttDiscovering"));
                    _discoveryScanCts?.Cancel();
                    _discoveryScanCts?.Dispose();   // release the previous linked CTS (no leak on repeat)
                    var scanCts = _discoveryScanCts = CancellationTokenSource.CreateLinkedTokenSource(
                        _discoveryCts?.Token ?? CancellationToken.None);
                    IReadOnlyList<BrokerCandidate> scan;
                    bool cancelled;
                    // Offload the whole /24 sweep to a background thread. ScanSubnetAsync uses
                    // ConfigureAwait(false) internally, but its SYNCHRONOUS prologue — enumerating
                    // the LAN interfaces and starting the bounded parallel probe loop — plus any
                    // probe whose connect completes synchronously would otherwise run on THIS
                    // (UI/dispatcher) thread, since we're awaiting it directly from a UI-thread
                    // method. That froze scrolling for the duration of the scan. Task.Run pushes all
                    // of it to the thread pool; the await below still resumes on the UI thread, so the
                    // rest of this method keeps its single-threaded (lock-free) invariant.
                    // scanCts.Token is passed to Task.Run too so that if the scan is ALREADY
                    // cancelled when we get here (bridge toggled off / window closing before the work
                    // is queued), the delegate is never scheduled — cancellation surfaces at once
                    // instead of running the prologue only to observe the cancelled token inside
                    // ScanSubnetAsync. Early-stop uses a separate child CTS, so it never trips this.
                    try { scan = await Task.Run(() => _brokerDiscovery.ScanSubnetAsync(scanCts.Token), scanCts.Token); }
                    catch { scan = System.Array.Empty<BrokerCandidate>(); }
                    finally
                    {
                        cancelled = scanCts.IsCancellationRequested;
                        // Dispose this scan's CTS; clear the field if it's still the current one
                        // (the toggle handler's ?.Cancel() then no-ops on null).
                        if (ReferenceEquals(_discoveryScanCts, scanCts)) _discoveryScanCts = null;
                        scanCts.Dispose();
                    }
                    // A cancelled scan (bridge disabled mid-scan, or window closing) stays
                    // RETRYABLE — don't burn the one-shot flag on it.
                    if (cancelled) { SetMqttDiscoveryInfo(null); return; }
                    _discoveryScanDone = true;   // a full sweep ran — the heavy scan won't repeat
                    _lastScanResults.Clear();
                    _lastScanResults.AddRange(scan);   // cache for a later re-enable
                    // The user may have typed a broker while we scanned.
                    if (!MqttEnabled || TxtMqttHost.Text.Trim().Length > 0) { SetMqttDiscoveryInfo(null); return; }
                    pool = BuildDiscoveryPool();
                }

                // A plaintext broker → pre-fill and mark ready (terminal: fields are now set). If it
                // came from the HA-host fallback, label it as HA-derived so the user knows to verify.
                if (pool.FirstOrDefault(c => !c.IsTls) is BrokerCandidate plain)
                {
                    PrefillBrokerFields(plain);
                    _discoveryPrefillDone = true;   // set ONLY after the fields are actually written
                    string key = _haResults.Contains(plain) ? "Fmt_MqttDiscoveredViaHa" : "Fmt_MqttDiscovered";
                    SetMqttDiscoveryInfo(LF(key, plain.Hostname ?? plain.Ip));
                    return;
                }
                // Only a TLS broker found → surface it but DON'T pre-fill (it needs a CA the
                // user must add; a plaintext pre-fill would build a broken config). An HA-host TLS
                // find is labelled as HA-derived too.
                if (pool.FirstOrDefault() is BrokerCandidate tls)
                {
                    // NOTE: do NOT set _discoveryPrefillDone here — nothing was pre-filled.
                    // Leaving it clear lets a later disable→re-enable re-surface this guidance
                    // (and re-evaluate if a plaintext candidate has since appeared).
                    string key = _haResults.Contains(tls) ? "Fmt_MqttDiscoveredViaHaTls" : "Fmt_MqttDiscoveredTls";
                    SetMqttDiscoveryInfo(LF(key, tls.Hostname ?? tls.Ip, tls.Port));
                    return;
                }
                SetMqttDiscoveryInfo(null);
            }
            catch { /* discovery pre-fill is best-effort; never fault the fire-and-forget task */ }
            finally
            {
                _discoveryPrefillInFlight = false;
                // A re-enable arrived while this pass ran (e.g. off→on during a scan's
                // cancellation, so this pass exited via the cancelled path). Run one more pass so
                // the re-enable isn't silently dropped — but only if discovery is still wanted.
                // Bounded: it re-runs only on an explicit latch, and a completed scan/prefill
                // (_discoveryScanDone / _discoveryPrefillDone) makes the next pass a quick no-op.
                if (_discoveryPrefillRerun && MqttEnabled
                    && TxtMqttHost.Text.Trim().Length == 0 && !_discoveryPrefillDone)
                {
                    _discoveryPrefillRerun = false;
                    _ = TryPrefillBrokerFromDiscoveryAsync();
                }
                else
                {
                    _discoveryPrefillRerun = false;
                }
            }
        }

        /// <summary>The current candidate pool: live mDNS answers, plus brokers port-confirmed on a
        /// Home Assistant host (<see cref="_haResults"/>, issue #52), plus the last /24 scan's results
        /// (<see cref="_lastScanResults"/>). Rebuilt on each read so a disable→re-enable, or a
        /// late-arriving mDNS answer, re-evaluates without re-probing. Only one of the fallback
        /// sources is ever populated per outage (each runs only when the pool is still empty), so a
        /// candidate here maps back to exactly one source — which is how the caller labels it.</summary>
        private List<BrokerCandidate> BuildDiscoveryPool()
        {
            var pool = new List<BrokerCandidate>(_brokerDiscovery!.MdnsCandidates);
            pool.AddRange(_haResults);
            pool.AddRange(_lastScanResults);
            return pool;
        }

        /// <summary>Cancel and release every discovery CTS on window close — mirrors
        /// <see cref="StopFirmwareScan"/> so neither the background mDNS nor an in-flight /24
        /// scan leaks its WaitHandle for the window's lifetime. Capture-then-null so a scan
        /// completing concurrently disposes its own linked CTS at most once.</summary>
        private void StopBrokerDiscovery()
        {
            var scan = _discoveryScanCts; _discoveryScanCts = null;
            var root = _discoveryCts;     _discoveryCts = null;
            try { scan?.Cancel(); } catch { /* nothing registered can throw; be safe */ }
            try { root?.Cancel(); } catch { /* shutting down */ }
            scan?.Dispose();
            root?.Dispose();
        }

        /// <summary>Seed the broker/Host IP/port fields from a discovered candidate — a
        /// hostname pinned to its IP (or a bare IP). Guarded like the auto-promotion so the
        /// programmatic writes aren't treated as user edits.</summary>
        private void PrefillBrokerFields(BrokerCandidate c)
        {
            _suppressMqttBrokerInvalidation = true;
            try
            {
                if (c.Hostname != null) { TxtMqttHostIp.Text = c.Ip; TxtMqttHost.Text = c.Hostname; }
                else { TxtMqttHostIp.Text = ""; TxtMqttHost.Text = c.Ip; }
            }
            finally { _suppressMqttBrokerInvalidation = false; }
            TxtMqttPort.Text = c.Port.ToString();
            // The suppressed writes above bypass MqttBrokerField_TextChanged's anchor check, so a
            // MAC captured for an EARLIER manually-tested endpoint (host later cleared while its
            // Host IP lingered) could otherwise carry onto this freshly-discovered broker and get
            // embedded as the wrong anchor. Apply the same rule here: drop it unless the discovered
            // endpoint IS the captured one.
            if (_mqttBrokerMac != null && !BrokerStillAtCapturedMac())
                ClearBrokerMac();
            // Keep the locked camera target following the freshly-discovered broker host (issue #111).
            ApplyCameraTargetLock();
            UpdateBuildEnabled();
        }

        /// <summary>Show (or, with null/empty, hide) the LAN-discovery note above the broker
        /// fields. Announced to screen readers like the other MQTT live regions.</summary>
        private void SetMqttDiscoveryInfo(string? text)
        {
            if (string.IsNullOrEmpty(text))
            {
                TxtMqttDiscovery.Text = "";
                TxtMqttDiscovery.Visibility = Visibility.Collapsed;
                return;
            }
            TxtMqttDiscovery.Text = text;
            TxtMqttDiscovery.Visibility = Visibility.Visible;
            AnnounceLiveRegion(TxtMqttDiscovery);
        }

        /// <summary>Any MQTT text field changed — clear a stale test result and
        /// re-evaluate the Build gate/cues. (Also refreshes the host-IP row and
        /// remote-shell enablement via the UpdateBuildEnabled → UpdateMqttVisibility
        /// cascade.)</summary>
        private void MqttField_TextChanged(object sender, TextChangedEventArgs e)
        {
            // A guarded programmatic write (e.g. mirroring the broker host into the locked camera
            // target — issue #111) is not a user edit, so it must not clear the broker test result.
            if (_suppressMqttFieldChange) { UpdateBuildEnabled(); return; }
            ClearMqttTestStatus();
            UpdateBuildEnabled();
        }

        /// <summary>The broker host or host-IP override changed. These two fields alone
        /// determine which machine the MAC anchor belongs to, so a captured MAC is
        /// dropped here UNLESS the new endpoint still resolves to the captured IP — the
        /// user typed that IP, pinned it via the host-IP override, or followed the
        /// reverse-DNS hostname suggestion. Port/auth/TLS edits go through
        /// <see cref="MqttField_TextChanged"/> and never touch the MAC: it is an L2 fact
        /// about the host, independent of port or credentials.</summary>
        private void MqttBrokerField_TextChanged(object sender, TextChangedEventArgs e)
        {
            // Programmatic IP→hostname promotion (see CaptureBrokerMacAsync): the endpoint
            // is unchanged, so keep the captured MAC AND the green test result — only
            // refresh visibility/gate. The promotion sets the anchor note itself.
            if (_suppressMqttBrokerInvalidation) { UpdateBuildEnabled(); return; }

            if (_mqttBrokerMac != null && !BrokerStillAtCapturedMac())
                ClearBrokerMac();               // different endpoint → anchor no longer applies
            else
                RefreshMqttRediscoveryInfo();    // kept: adjust the note to the current host form
            ClearMqttTestStatus();
            UpdateBuildEnabled();
        }

        /// <summary>Whether the currently-configured broker endpoint still points at the
        /// IP the MAC was captured for — the condition under which the anchor stays
        /// valid across a host/host-IP edit.</summary>
        private bool BrokerStillAtCapturedMac()
        {
            if (_mqttMacIp == null || !IPAddress.TryParse(_mqttMacIp, out var capturedIp)) return false;
            string host = TxtMqttHost.Text.Trim();
            // Broker typed as an IP: it targets that address directly — hold the anchor
            // only if it is the captured one. Compare as IPAddress values, not strings,
            // so a different textual form of the same IPv4 still matches.
            if (IPAddress.TryParse(host, out var hostIp)) return hostIp.Equals(capturedIp);
            // Hostname broker: the build pins the name to the host-IP override when one
            // is given (it becomes HostIpForHosts), so a non-empty override is
            // AUTHORITATIVE for what the MAC must match. If it isn't the captured IP the
            // build targets a different machine — drop the anchor, whatever the name is.
            string hipText = TxtMqttHostIp.Text.Trim();
            if (hipText.Length > 0)
                return IPAddress.TryParse(hipText, out var overrideIp) && overrideIp.Equals(capturedIp);
            // No override: the name is resolved at build time. Preserve only when it is
            // the reverse-DNS name captured for this IP (which resolves back to it).
            return _mqttMacSuggestedHost != null &&
                   host.Equals(_mqttMacSuggestedHost, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Forget the captured MAC anchor and hide its note.</summary>
        private void ClearBrokerMac()
        {
            _mqttBrokerMac = null;
            _mqttMacIp = null;
            _mqttMacSuggestedHost = null;
            SetMqttRediscoveryInfo(null);
        }

        /// <summary>Write the Host IP override (and optionally the broker hostname) as part
        /// of the post-test canonicalization, guarded so the resulting TextChanged events
        /// are not treated as user edits (which would drop the captured MAC / test result).
        /// Pass <paramref name="hostName"/> null to set only the Host IP.</summary>
        private void SetBrokerFieldsSuppressed(string? hostName, string hostIp)
        {
            _suppressMqttBrokerInvalidation = true;
            try
            {
                TxtMqttHostIp.Text = hostIp;            // row becomes visible when host is a name
                if (hostName != null) TxtMqttHost.Text = hostName;
            }
            finally { _suppressMqttBrokerInvalidation = false; }
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
            // The captured-MAC note is meaningful only while rediscovery is on (the
            // anchor's sole consumer): show it when re-enabled, hide it when disabled.
            if (sender == ChkMqttRediscovery)
                RefreshMqttRediscoveryInfo();
            UpdateBuildEnabled();
        }

        /// <summary>Show/hide the collapsible topics panel (prefilled with defaults).</summary>
        private void ChkMqttTopics_Toggled(object sender, RoutedEventArgs e) =>
            MqttTopicsPanel.Visibility = ChkMqttTopics.IsChecked == true
                ? Visibility.Visible : Visibility.Collapsed;

        /// <summary>"Has exterior light": reveal the WHERE field + learn hint. A blank WHERE with
        /// the box ticked means the unit will LEARN the WHERE at runtime.</summary>
        private void ChkMqttHasLight_Toggled(object sender, RoutedEventArgs e)
        {
            var vis = ChkMqttHasLight.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            LightTypePanel.Visibility = vis;
            LightWherePanel.Visibility = vis;
            LblMqttLightLearnHint.Visibility = vis;
            UpdateBuildEnabled();
        }

        /// <summary>"Expose the entrance camera": reveal the go2rtc fan-out target/ports and the
        /// video-quality choice. The camera fields feed CAMERA_* in the generated .conf (issue #103).</summary>
        private void ChkMqttCamera_Toggled(object sender, RoutedEventArgs e)
        {
            CameraPanel.Visibility = ChkMqttCamera.IsChecked == true
                ? Visibility.Visible : Visibility.Collapsed;
            RefreshCameraModelGating();
            ApplyCameraTargetLock();
            UpdateBuildEnabled();
        }

        /// <summary>"Use a different go2rtc host": unlock the target field for a manual (IPv4) entry.
        /// Unchecked (the default) re-locks it and re-mirrors the broker/HA host (issue #111).</summary>
        private void ChkMqttCameraHostOverride_Toggled(object sender, RoutedEventArgs e)
        {
            ApplyCameraTargetLock();
            UpdateBuildEnabled();
        }

        /// <summary>Lock (default) or unlock the "go2rtc / HA host" field per the override checkbox.
        /// The daemon re-resolves <c>CAMERA_TARGET_HOST</c> every camera session (<c>av.rs::arm</c>),
        /// so leaving it as the broker/HA host makes the fan-out follow Home Assistant to a new IP
        /// automatically — no reflash (issue #111). While locked the field is read-only and mirrors
        /// the broker host (name preferred) for display, and the build leaves the target blank so the
        /// device defaults to that host; the override unlocks it for a distinct IPv4 go2rtc host.</summary>
        private void ApplyCameraTargetLock()
        {
            // Guard against calls before InitializeComponent has created the controls.
            if (TxtMqttCameraTarget is null || ChkMqttCameraHostOverride is null) return;

            bool overridden = ChkMqttCameraHostOverride.IsChecked == true;
            TxtMqttCameraTarget.IsReadOnly = !overridden;
            if (LblMqttCameraTargetHint is not null)
                LblMqttCameraTargetHint.Visibility = overridden ? Visibility.Collapsed : Visibility.Visible;

            // Locked: mirror the broker/HA host into the read-only field (display only — the build
            // ignores it while locked). Only while the camera panel is on, and via the suppress guard
            // so the mirror never clears the broker test result.
            if (!overridden && ChkMqttCamera.IsChecked == true)
            {
                string host = TxtMqttHost.Text.Trim();
                if (TxtMqttCameraTarget.Text != host)
                {
                    _suppressMqttFieldChange = true;
                    try { TxtMqttCameraTarget.Text = host; }
                    finally { _suppressMqttFieldChange = false; }
                }
            }
        }

        /// <summary>Whether the SELECTED firmware exposes the hi-res camera branch. Enabled ONLY for a
        /// recognized Classe 300X — its `bt_av_media` has the hi-res `multiudpsink`. Every other case
        /// (the Classe 100X, which has no hi-res branch, AND unrecognized firmware) defaults to
        /// Standard (low-res, branch 1), which works on every model. Fail-safe: we offer hi-res only
        /// when we can positively assert the model supports it, never on an unknown (CodeRabbit). Every
        /// customizable firmware is either "Classe 100X" or "Classe 300X", so this never restricts a
        /// real 300X.</summary>
        private bool CameraModelSupportsHiRes =>
            string.Equals(_fwzMatch?.Line, "Classe 300X", StringComparison.Ordinal);

        /// <summary>Gate the hi-res camera option to a model that supports it (a recognized Classe
        /// 300X): for every other model — the Classe 100X and unrecognized firmware — the option is
        /// disabled and Standard (low-res) is forced. Called whenever the firmware selection or the
        /// camera toggle changes, so switching away from a 300X after ticking hi-res can't persist it.</summary>
        private void RefreshCameraModelGating()
        {
            if (RbMqttCameraHiRes is null) return; // guard against calls before InitializeComponent
            bool hiRes = CameraModelSupportsHiRes;
            RbMqttCameraHiRes.IsEnabled = hiRes;
            if (!hiRes) RbMqttCameraLowRes.IsChecked = true; // no hi-res branch — force Standard
        }

        /// <summary>Build the ready-to-paste go2rtc config for the current camera settings and show it
        /// (also copied to the clipboard). Pure text via <see cref="Go2RtcConfig"/> — no I/O to the
        /// device; the user pastes it into their go2rtc / Home Assistant host.</summary>
        private void BtnMqttCameraGo2Rtc_Click(object sender, RoutedEventArgs e)
        {
            // Reject invalid or equal ports BEFORE generating the guide — otherwise it would
            // describe a configuration (default 40000/40002, or an unusable equal-port SDP) that
            // doesn't match the camera form (CodeRabbit). Surface the same messages the Build gate uses.
            if (!TryParsePort(TxtMqttCameraVideoPort.Text, out int vp)
                || !TryParsePort(TxtMqttCameraAudioPort.Text, out int ap))
            {
                MessageBox.Show(this, L("MqttHint_CameraPort"), L("Cap_MqttInvalid"),
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (vp == ap)
            {
                MessageBox.Show(this, L("MqttHint_CameraPortsDiffer"), L("Cap_MqttInvalid"),
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            // The generator only reads the camera target + ports; MqttHost seeds the target default
            // (go2rtc usually runs with HA). A blank host is stubbed so the guide still renders.
            string host = TxtMqttHost.Text.Trim();
            var opts = new MqttOptions(host.Length == 0 ? "your-ha-host" : host)
            {
                // Locked (default) ⇒ blank so the device defaults to the broker/HA host (and follows
                // it on an IP change); overridden ⇒ the user's distinct go2rtc host (issue #111).
                CameraTargetHost = ChkMqttCameraHostOverride.IsChecked == true
                    ? NullIfEmpty(TxtMqttCameraTarget.Text.Trim()) : null,
                CameraVideoPort = vp,
                CameraAudioPort = ap,
            };
            // The stream name follows the HA node id (sanitized inside the generator), so the SDP
            // filename, go2rtc key and camera entity agree; fall back to "doorbell".
            string streamName = NullIfEmpty(TxtMqttHaNodeId.Text.Trim()) ?? "doorbell";
            string guide = Go2RtcConfig.BuildSetupGuide(opts, streamName);
            try { Clipboard.SetText(guide); } catch { /* clipboard may be busy; still show the text */ }
            MessageBox.Show(this, guide, L("Cap_MqttGo2Rtc"),
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        /// <summary>Parse a UDP port: a trimmed integer in 1..65535. Mirrors the Core camera-port
        /// validator so the Build gate and the Core popup agree.</summary>
        private static bool TryParsePort(string text, out int port)
        {
            port = 0;
            if (!int.TryParse(text.Trim(), out int v) || v < 1 || v > 65535) return false;
            port = v;
            return true;
        }

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
            BtnMqttTest.IsEnabled = _uiEnabled && !_downloading && !_mqttTesting && !_mqttCapturing;

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
            if (_downloading) return; // don't run a broker test concurrently with a firmware download
            await RunMqttConnectionTestAsync();
        }

        /// <summary>Runs one real MQTT CONNECT against the current config and paints the
        /// result. On a successful connect with rediscovery on, it also captures the broker
        /// MAC and canonicalizes the fields to hostname + pinned IP (see
        /// CaptureBrokerMacAsync). When a bare-IP broker would be promoted to its hostname
        /// under TLS, the hostname is first re-validated against the certificate
        /// (ValidateThenPromoteHostnameAsync) and only adopted if it passes — so an
        /// unvalidated hostname config is never left buildable.</summary>
        private async Task RunMqttConnectionTestAsync()
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
            UpdateBuildEnabled();   // lock Build for the whole test (gate reads _mqttTesting)
            int gen = _mqttTestGen;   // config snapshot; a later edit invalidates this result

            // For a hostname broker with no explicit Host IP, pin the CONNECT to the FIRST
            // IPv4 — the address the firmware build's ResolveHostIp picks and the one the MAC
            // capture will ARP. Otherwise the OS resolver could hand MQTTnet a different A
            // record (or IPv6) than the IPv4 chosen here, giving a ✓ for one endpoint while
            // the anchor/pin describes another. On resolve failure fall back to the hostname.
            // Inside the _mqttTesting window, so Build stays locked across the resolve too.
            if (hostIsName && hostIp == null)
            {
                try
                {
                    var addrs = await Dns.GetHostAddressesAsync(host).WaitAsync(DnsCaptureTimeout);
                    if (Array.Find(addrs, a => a.AddressFamily == AddressFamily.InterNetwork) is IPAddress v4)
                        connectHost = v4.ToString();
                }
                catch { /* unresolved here — let MQTTnet resolve the hostname itself */ }
            }

            bool ok = false;
            string? err = null;
            try
            {
                ok = await MqttTestConnectAsync(connectHost, host, port, user, pass, caPem, certPem, keyPem);
            }
            catch (OperationCanceledException) { err = L("MqttTest_Timeout"); }
            catch (Exception ex) { err = SafeMessage(ex); }
            finally { _mqttTesting = false; }

            // If a connection-affecting field changed while the CONNECT was in flight,
            // its result no longer describes the visible config — the edit already
            // cleared the status line, so leave it hidden rather than repaint a stale one.
            if (gen != _mqttTestGen) { BtnMqttTest.IsEnabled = _uiEnabled; UpdateBuildEnabled(); return; }
            SetMqttTestStatus(
                ok ? LF("Fmt_MqttTest_Ok", host, port)
                   : LF("Fmt_MqttTest_Fail", err ?? L("MqttTest_Refused")),
                error: !ok);

            // On a good connect with rediscovery on, capture the broker's MAC and
            // canonicalize the config to a hostname + pinned IP (see CaptureBrokerMacAsync).
            // For a bare-IP broker under TLS the promotion is DEFERRED: CaptureBrokerMacAsync
            // returns the candidate hostname and we re-validate the certificate against it
            // (dialing the pinned IP) BEFORE touching the fields, adopting the hostname only
            // if it passes — so a certificate that covers only the IP can never leave a
            // hostname config that just tested against the IP silently buildable.
            if (ok && ChkMqttRediscovery.IsChecked == true)
            {
                string? tlsPromoteName = await CaptureBrokerMacAsync(host, connectHost, gen);
                if (tlsPromoteName != null)
                    await ValidateThenPromoteHostnameAsync(
                        tlsPromoteName, connectHost, port, user, pass, caPem, certPem, keyPem, gen);
            }

            BtnMqttTest.IsEnabled = _uiEnabled;
            UpdateBuildEnabled();   // test done: re-open Build now that _mqttTesting is clear
        }

        /// <summary>Under TLS, before adopting a reverse-DNS hostname for a bare-IP broker,
        /// re-validate the certificate against that hostname — dialing the already-tested
        /// (pinned) IP. Promotes the fields (hostname + Host IP) only on success; on failure
        /// the broker stays the IP, which already tested OK. Build is blocked (via
        /// <c>_mqttCapturing</c>) throughout, so a not-yet-validated hostname config is never
        /// buildable.</summary>
        private async Task ValidateThenPromoteHostnameAsync(
            string hostname, string ip, int port, string? user, string? pass,
            string? caPem, string? certPem, string? keyPem, int gen)
        {
            _mqttCapturing = true;
            BtnMqttTest.IsEnabled = false;
            SetMqttTestStatus(L("MqttTest_Testing"), error: false);
            UpdateBuildEnabled();   // keep Build locked while the hostname is unvalidated
            bool ok = false;
            try { ok = await MqttTestConnectAsync(ip, hostname, port, user, pass, caPem, certPem, keyPem); }
            catch { ok = false; }   // any failure → don't adopt the hostname
            finally { _mqttCapturing = false; }

            if (gen != _mqttTestGen) { BtnMqttTest.IsEnabled = _uiEnabled; UpdateBuildEnabled(); return; }

            // Rediscovery turned off during the re-validation → abandon the hostname switch;
            // the broker stays the IP (unchanged, still the tested endpoint), so restore its ✓.
            if (ChkMqttRediscovery.IsChecked != true)
            {
                SetMqttTestStatus(LF("Fmt_MqttTest_Ok", ip, port), error: false);
                BtnMqttTest.IsEnabled = _uiEnabled;
                UpdateBuildEnabled();
                return;
            }

            if (ok)
            {
                // Certificate validates against the hostname → adopt it now (validated).
                SetBrokerFieldsSuppressed(hostname, ip);
                SetMqttTestStatus(LF("Fmt_MqttTest_Ok", hostname, port), error: false);
                if (_mqttBrokerMac != null)
                    SetMqttRediscoveryInfo(LF("Fmt_MqttAnchorPromoted", _mqttBrokerMac, ip, hostname));
            }
            else
            {
                // The hostname didn't validate → keep the IP (which tested OK) and say so.
                SetMqttTestStatus(LF("Fmt_MqttTest_Ok", ip, port), error: false);
                if (_mqttBrokerMac != null)
                    SetMqttRediscoveryInfo(LF("Fmt_MqttAnchorHostnameFail", _mqttBrokerMac, ip, hostname));
            }
            BtnMqttTest.IsEnabled = _uiEnabled;
            UpdateBuildEnabled();
        }

        /// <summary>
        /// After a successful test, resolve the broker to an on-link IPv4 and ARP it for
        /// the broker's MAC (the plaintext rediscovery anchor, issue #43), then canonicalize
        /// the config toward the most robust firmware form — broker stored as a HOSTNAME,
        /// pinned to the tested IP in the device hosts file:
        /// <list type="bullet">
        /// <item>a bare-IP broker with a reverse-DNS name is promoted (name → broker field,
        /// IP → Host IP); under TLS the test result is cleared so the certificate is
        /// re-validated against the hostname;</item>
        /// <item>a hostname broker with an empty Host IP gets the resolved IP filled in.</item>
        /// </list>
        /// The whole method is best-effort and never throws: a broker on another subnet
        /// (ARP can't reach it) simply yields no anchor, with a note saying so.
        /// </summary>
        /// <returns>The candidate hostname when a bare-IP broker under TLS should be
        /// promoted — but only AFTER the caller re-validates the certificate against it
        /// (the fields are deliberately left unchanged here). Null in every other case
        /// (plaintext promotion, hostname pin, and no-op are all applied in place).</returns>
        private async Task<string?> CaptureBrokerMacAsync(string host, string connectHost, int gen)
        {
            _mqttCapturing = true;
            UpdateBuildEnabled();   // lock Build while ARP/reverse-DNS run
            try
            {
                // Resolve the endpoint to an IPv4: connectHost is already an IPv4 for an
                // IP host or a host-IP override; a bare hostname needs DNS. ARP is IPv4
                // only, so a v6-only resolution yields no anchor.
                IPAddress? ip = null;
                if (IPAddress.TryParse(connectHost, out var direct) &&
                    direct.AddressFamily == AddressFamily.InterNetwork)
                    ip = direct;
                else
                {
                    try
                    {
                        // Bound the lookup: a stalled resolver must not leave _mqttCapturing
                        // set (Build/Test disabled) indefinitely. On timeout WaitAsync throws
                        // and the catch falls back to no anchor; the finally still runs.
                        var addrs = await Dns.GetHostAddressesAsync(connectHost)
                            .WaitAsync(DnsCaptureTimeout);
                        ip = Array.Find(addrs, a => a.AddressFamily == AddressFamily.InterNetwork);
                    }
                    catch { ip = null; }
                }

                // SendARP can briefly block; keep it off the UI thread.
                string? mac = ip != null ? await Task.Run(() => TryGetMacViaArp(ip)) : null;

                // Reverse-DNS only when the broker was typed as a bare IP: a hostname
                // config already has a name for rediscovery to repoint. The name (if any)
                // is a non-destructive SUGGESTION — surfaced, never written to the host
                // field. Compute it into a local before committing, so every await is done
                // by the time we touch the shared MAC state below.
                string? suggested = null;
                if (mac != null && IPAddress.TryParse(host, out _))
                {
                    try
                    {
                        // GetHostEntryAsync has no CancellationToken overload, so bound it the
                        // same way — a hung reverse lookup would otherwise pin _mqttCapturing.
                        var entry = await Dns.GetHostEntryAsync(ip!).WaitAsync(DnsCaptureTimeout);
                        // Trim a trailing FQDN dot; accept only a name Core would (not an IP,
                        // passes the host charset) so promotion can't write a host Build rejects.
                        string name = (entry.HostName ?? "").TrimEnd('.');
                        if (name.Length > 0 && !IPAddress.TryParse(name, out _) && IsValidMqttHost(name))
                            suggested = name.ToLowerInvariant();
                    }
                    catch { /* no PTR record / timeout — a MAC-only anchor is fine */ }
                }

                // Single commit point AFTER all awaits. Drop the whole capture if a
                // connection-affecting edit landed (generation moved on) OR the user turned
                // rediscovery off while ARP/DNS ran — the anchor is its only consumer, so a
                // disabled option must not store a MAC, mutate fields, or show anchor text.
                if (gen != _mqttTestGen || ChkMqttRediscovery.IsChecked != true) return null;

                if (mac == null)
                {
                    // Reachable but no MAC (broker off-subnet, or an ARP race): forget any
                    // stale anchor and say so, so the user knows plaintext rediscovery has
                    // no anchor for this broker (TLS would still anchor it).
                    ClearBrokerMac();
                    SetMqttRediscoveryInfo(L("MqttHint_AnchorNoMac"));
                    return null;
                }

                _mqttBrokerMac = mac;
                _mqttMacIp = ip!.ToString();
                _mqttMacSuggestedHost = suggested;

                // Canonicalize toward the most robust firmware config: broker stored as a
                // HOSTNAME (MQTT_HOST), pinned to the tested IPv4 in the device hosts file
                // (HostIpForHosts), so rediscovery can repoint the name if the IP changes,
                // with the MAC as the anchor. The field writes go through
                // SetBrokerFieldsSuppressed so they aren't seen as a user edit — the MAC and
                // (usually) the green test result survive, since the endpoint is unchanged.
                bool hostIsIp = IPAddress.TryParse(host, out _);
                bool hasTls = _mqttCaPath != null || (_mqttCertPath != null && _mqttKeyPath != null);

                if (hostIsIp && suggested != null)
                {
                    if (hasTls)
                    {
                        // Under TLS the certificate was validated against the IP; adopting the
                        // hostname changes the TLS identity. DON'T promote here — hand the
                        // hostname back so the caller can re-validate the cert against it and
                        // promote only on success. Fields (and the ✓) stay as the IP for now.
                        return suggested;
                    }
                    // Plaintext: same endpoint, promote now and keep the ✓.
                    SetBrokerFieldsSuppressed(suggested, _mqttMacIp);
                    SetMqttRediscoveryInfo(LF("Fmt_MqttAnchorPromoted", mac, _mqttMacIp, suggested));
                }
                else if (!hostIsIp && TxtMqttHostIp.Text.Trim().Length == 0)
                {
                    // Hostname broker with no Host IP yet → fill in the resolved IP so the pin
                    // is explicit and visible. The TLS target (the hostname) is unchanged, so
                    // the ✓ still holds whether or not TLS is configured.
                    SetBrokerFieldsSuppressed(null, _mqttMacIp);
                    SetMqttRediscoveryInfo(LF("Fmt_MqttAnchorPinned", mac, _mqttMacIp, host));
                }
                else
                {
                    RefreshMqttRediscoveryInfo();
                }
                return null;
            }
            finally
            {
                _mqttCapturing = false;
                UpdateBuildEnabled();   // re-enable Build; the gate re-reads the MAC state
            }
        }

        // Upper bound on each DNS lookup during MAC capture, so a stalled resolver can't
        // hold the capture (and thus Build/Test) locked. A few seconds is plenty for a LAN
        // lookup; independent of the MQTT connect timeout in MqttTestConnectAsync.
        private static readonly TimeSpan DnsCaptureTimeout = TimeSpan.FromSeconds(5);

        // Windows iphlpapi ARP resolution. Fills macAddr for an on-link IPv4; a non-zero
        // return, or an all-zero/short address, means "no entry" (e.g. off-subnet).
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int macAddrLen);

        /// <summary>Best-effort ARP lookup of an on-link IPv4's MAC, returned as the
        /// canonical lowercase <c>aa:bb:cc:dd:ee:ff</c> btmqttd's parse_mac accepts, or
        /// null when it can't be resolved (off-link address, SendARP failure, or an
        /// all-zero / short result).</summary>
        private static string? TryGetMacViaArp(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return null;
            byte[] b = ip.GetAddressBytes();   // a.b.c.d, most-significant octet first
            // SendARP wants the destination as a uint whose LEAST-significant byte is the
            // first address octet (i.e. the 4 raw bytes read little-endian). Build it with
            // explicit shifts so the order is unambiguous on any host endianness.
            uint dest = (uint)(b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24));
            // SendARP documents pMacAddr as at least two ULONGs (8 bytes). Allocate 8 and
            // pass the buffer's ACTUAL size as the in/out length (per the WinAPI contract:
            // input = buffer size, output = bytes written). On return, require at least a
            // full 6-byte MAC to have been written; only the first six bytes are used.
            byte[] mac = new byte[8];
            int len = mac.Length;
            try
            {
                if (SendARP(dest, 0, mac, ref len) != 0 || len < 6) return null;
            }
            // Best-effort: ANY interop failure means "no MAC", never a crash of the
            // async-void Test-connection handler — a missing iphlpapi / non-Windows host
            // (DllNotFoundException, EntryPointNotFoundException) or a native fault
            // surfaced as SEHException/other. Swallow them all and report no anchor.
            catch (Exception) { return null; }
            // An all-zero address is an incomplete ARP row, not a real MAC.
            bool allZero = true;
            for (int i = 0; i < 6; i++) if (mac[i] != 0) { allZero = false; break; }
            if (allZero) return null;
            return $"{mac[0]:x2}:{mac[1]:x2}:{mac[2]:x2}:{mac[3]:x2}:{mac[4]:x2}:{mac[5]:x2}";
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
                        clientCert = X509CertificateLoader.LoadPkcs12(
                            ephemeral.Export(X509ContentType.Pkcs12), null);
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

        /// <summary>Show (or, with null/empty text, hide) the rediscovery-anchor note
        /// under the checkbox. Announced to screen readers like the test-status line.</summary>
        private void SetMqttRediscoveryInfo(string? text)
        {
            if (string.IsNullOrEmpty(text))
            {
                TxtMqttRediscoveryInfo.Text = "";
                TxtMqttRediscoveryInfo.Visibility = Visibility.Collapsed;
                return;
            }
            TxtMqttRediscoveryInfo.Text = text;
            TxtMqttRediscoveryInfo.Visibility = Visibility.Visible;
            AnnounceLiveRegion(TxtMqttRediscoveryInfo);
        }

        /// <summary>Recompute the anchor note from the current state. Hidden when
        /// rediscovery is off or no MAC is captured. Otherwise one of three honest
        /// cases, because device-side rediscovery repoints a HOSTNAME (a bare-IP broker
        /// has no name to repoint, so a MAC alone doesn't make it recoverable):
        /// <list type="bullet">
        /// <item>broker is a hostname → the anchor is effective (name + MAC);</item>
        /// <item>broker is a bare IP with a reverse-DNS name → suggest adopting it;</item>
        /// <item>broker is a bare IP with no name → note that a hostname is needed.</item>
        /// </list>
        /// The distinct "connected but no MAC" hint is set directly by the capture and
        /// left until the next relevant event.</summary>
        private void RefreshMqttRediscoveryInfo()
        {
            if (ChkMqttRediscovery.IsChecked != true || _mqttBrokerMac == null)
            {
                SetMqttRediscoveryInfo(null);
                return;
            }
            string mac = _mqttBrokerMac, ip = _mqttMacIp ?? "";
            if (!IPAddress.TryParse(TxtMqttHost.Text.Trim(), out _))
                SetMqttRediscoveryInfo(LF("Fmt_MqttAnchorMac", mac, ip));         // hostname → effective
            else if (_mqttMacSuggestedHost != null)
                SetMqttRediscoveryInfo(LF("Fmt_MqttAnchorHostname", mac, ip, _mqttMacSuggestedHost));
            else
                SetMqttRediscoveryInfo(LF("Fmt_MqttAnchorIpOnly", mac, ip));      // bare IP, no name
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
            // A "Test connection" is in flight — either the CONNECT itself (_mqttTesting)
            // or the follow-on broker-MAC capture / hostname re-validation (_mqttCapturing).
            // Block Build for the WHOLE window so the mqttOpts snapshot can't be taken with a
            // null MAC (or an about-to-change host) that the finishing test would have filled.
            if (_mqttTesting || _mqttCapturing) return false;
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

            // HA discovery node id — mirror MqttInstaller.Validate, which validates it
            // UNCONDITIONALLY (not only when discovery is enabled): the manifest is
            // generated and btmqttd reconciles it even when disabled, to CLEAR the
            // retained configs, so a bad node id would fail the build with discovery
            // off too. The node becomes a discovery-topic level and unique_id, so it
            // must be the HA charset [A-Za-z0-9_-]. An empty field falls back to the
            // valid default in TryBuildMqttOptions, so only a non-empty out-of-charset
            // value is rejected — fail here rather than later in the Core popup.
            {
                string node = TxtMqttHaNodeId.Text.Trim();
                if (node.Length > 0)
                    foreach (char c in node)
                        if (!(char.IsAsciiLetterOrDigit(c) || c == '_' || c == '-'))
                            return L("MqttHint_HaNodeId");
            }

            // Stair-light WHERE — mirror the Core validator (Mqtt_InvalidLightWhere): only when
            // "has exterior light" is ticked (else the field is hidden and ignored). A BLANK
            // WHERE is valid (learn it at runtime); a non-empty value must be digits only (it
            // becomes the *8*21*<WHERE>## actuator address). Fail here rather than let Build
            // enable and then abort with the Core popup.
            if (ChkMqttHasLight.IsChecked == true)
            {
                string where = TxtMqttLightWhere.Text.Trim();
                if (where.Length > 0 && !where.All(char.IsAsciiDigit))
                    return L("MqttHint_LightWhere");
            }

            // Live camera — mirror the Core validator (only when enabled). Both fan-out ports must be
            // numeric and in 1..65535, and DISTINCT (video and audio are separate RTP streams). The
            // target may be blank (it defaults to the broker host device-side), so it isn't gated here.
            if (ChkMqttCamera.IsChecked == true)
            {
                // The target is only user-entered when "use a different go2rtc host" is on; while
                // locked it mirrors the broker host and the build blanks it (issue #111), so validate
                // it only when overridden — otherwise there's nothing the user can get wrong here.
                if (ChkMqttCameraHostOverride.IsChecked == true)
                {
                    // Reject a CR/LF in the target before Core is reached: the value is sourced into the
                    // shell-quoted .conf, so it must be single-line (mirrors the credential/topic checks).
                    // A blank target is fine — Core defaults it to the broker host. Format (hostname vs.
                    // IPv4-vs-IPv6) is left to Core's Validate, which surfaces a clear popup (CodeRabbit).
                    if (TxtMqttCameraTarget.Text.IndexOfAny(NewlineChars) >= 0)
                        return L("MqttHint_CameraTarget");
                    // Mirror Core's device-resolvability rule: a target that differs from the broker host
                    // must be an IPv4 literal — the intercom resolves only /etc/hosts + public DNS, never
                    // LAN/mDNS names, so any other hostname would never arm the camera. Blank ⇒ broker.
                    string camTarget = TxtMqttCameraTarget.Text.Trim();
                    if (camTarget.Length > 0
                        && !string.Equals(camTarget, TxtMqttHost.Text.Trim(), StringComparison.OrdinalIgnoreCase)
                        && !(IPAddress.TryParse(camTarget, out var camIp)
                             && camIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork))
                        return L("MqttHint_CameraTargetIp");
                }
                if (!TryParsePort(TxtMqttCameraVideoPort.Text, out int vp)
                    || !TryParsePort(TxtMqttCameraAudioPort.Text, out int ap))
                    return L("MqttHint_CameraPort");
                if (vp == ap) return L("MqttHint_CameraPortsDiffer");
            }

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

            // Camera fan-out ports (issue #103). When DISABLED, ALWAYS write the record defaults —
            // the field is irrelevant then, and reading it could serialize an out-of-range value
            // (e.g. 70000, or 0) that would strand a later manual CAMERA_ENABLED=1 (Copilot). When
            // ENABLED, parse the field, failing closed to 0 on an unparseable value so Core's Validate
            // rejects it with a clean popup (the Build gate already blocks it earlier).
            bool cameraOn = ChkMqttCamera.IsChecked == true;
            int camVideoPort = cameraOn
                ? (int.TryParse(TxtMqttCameraVideoPort.Text.Trim(), out int cvp) ? cvp : 0)
                : 40000;
            int camAudioPort = cameraOn
                ? (int.TryParse(TxtMqttCameraAudioPort.Text.Trim(), out int cap) ? cap : 0)
                : 40002;

            var opts = new MqttOptions(
                hostTrim,
                port,
                NullIfEmpty(TxtMqttUser.Text.Trim()),
                NullIfEmpty(_mqttPass?.Value ?? ""),
                caPem, certPem, keyPem,
                HostIpForHosts: hostIp,
                AllowRemoteShell: ChkMqttRemoteShell.IsChecked == true,
                // Publish HA discovery configs so entities appear automatically. ON
                // by default when the bridge is installed (plug-and-play). Creates the
                // read-only sensors AND the volume/gate CONTROL entities (issues #40/#41),
                // which publish commands to the intercom — the broker ACL on the command
                // topic is the trust boundary. The tooltip (Tip_MqttHaDiscovery) discloses
                // the controls, including the gate button.
                EnableHaDiscovery: ChkMqttHaDiscovery.IsChecked == true,
                // Checked (default) = one structured JSON object per frame on TOPIC_DUMP
                // (modern, HA-friendly); unchecked = raw OpenWebNet frames.
                UseJsonPayload: ChkMqttJsonPayload.IsChecked == true,
                // Broker rediscovery (#43/#44), on by default. Device-side it self-gates
                // (hostname config + TLS), so it is inert unless those hold.
                MqttRediscovery: ChkMqttRediscovery.IsChecked == true,
                // Plaintext rediscovery anchor (#43): the broker MAC captured on Test
                // connection. Only embedded when rediscovery is on (its only consumer);
                // the field is already null unless it matches the current endpoint, so a
                // stale anchor can't reach the build.
                MqttBrokerMac: ChkMqttRediscovery.IsChecked == true ? _mqttBrokerMac : null)
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
                // HA device/node id — distinct per unit gives each bridge its own HA
                // device/entities on one broker (multi-unit also needs distinct MQTT
                // topics; see the HaNodeId doc). Fall back to the record default if the
                // field was cleared, so an empty box doesn't force a validation error.
                // HaDiscoveryPrefix is deliberately NOT surfaced in the UI: it stays at
                // the HA standard ("homeassistant"), which virtually no one changes, so
                // exposing it would only add clutter. Library callers can still set it.
                HaNodeId = NullIfEmpty(TxtMqttHaNodeId.Text.Trim()) ?? new MqttOptions("x").HaNodeId,
                // Friendly HA device name from the selected firmware's model (BTicino Classe
                // 100X/300X); the record default is a model-neutral fallback. The node id
                // above is the machine id (auto-filled from the same model, editable).
                HaDeviceName = _fwzMatch?.HaDeviceName ?? new MqttOptions("x").HaDeviceName,
                // Exterior light (opt-in). "Has exterior light" ships the switch + resync + learn
                // entities; the WHERE (digits) is installation-specific — captured as
                // `*8*21*<WHERE>##`. A BLANK WHERE with the box ticked means LEARN it at runtime.
                HasExteriorLight = ChkMqttHasLight.IsChecked == true,
                LightWhere = NullIfEmpty(TxtMqttLightWhere.Text.Trim()),
                // Light type: momentary (staircase-timer auto-off → press button, no state) vs the
                // default bistable (tracked on/off switch + resync).
                LightMomentary = RbMqttLightMomentary.IsChecked == true,
                // Secondary lock (opt-in): create its HA entity only when a second gate is wired.
                HasSecondaryLock = ChkMqttSecondaryLock.IsChecked == true,
                // Live doorbell camera (opt-in, #103): siphon the panel's A/V and fan the RTP to the
                // go2rtc/HA host. A blank target defaults to the broker host device-side; low-res is
                // the universal video branch (hi-res is 300X-only).
                CameraEnabled = ChkMqttCamera.IsChecked == true,
                // Locked (default) ⇒ blank so the device defaults to the broker/HA host and follows
                // it on an IP change; overridden ⇒ the user's distinct IPv4 go2rtc host (issue #111).
                CameraTargetHost = ChkMqttCameraHostOverride.IsChecked == true
                    ? NullIfEmpty(TxtMqttCameraTarget.Text.Trim()) : null,
                CameraVideoPort = camVideoPort,
                CameraAudioPort = camAudioPort,
                // Never persist hi-res for a model that lacks the branch (the Classe 100X): even if the
                // radio were somehow checked, force low-res so the build can't produce a black camera.
                CameraHiRes = RbMqttCameraHiRes.IsChecked == true && CameraModelSupportsHiRes,
                // On-demand viewing (#104): only meaningful with the camera on (the checkbox lives
                // inside the camera panel); Core also coerces it off when the camera is disabled.
                CameraOnDemand = ChkMqttCamera.IsChecked == true && ChkMqttCameraOnDemand.IsChecked == true,
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
