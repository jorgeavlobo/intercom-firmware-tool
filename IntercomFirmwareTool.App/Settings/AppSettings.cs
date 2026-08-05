using System;
using System.IO;
using System.Text.Json;

namespace IntercomFirmwareTool.App.Settings
{
    /// <summary>
    /// The persisted user settings, stored as JSON at
    /// <c>%AppData%\IntercomFirmwareTool\settings.json</c>. One flat model for the whole app so a
    /// write of one setting preserves the others (the earlier language-only writer overwrote the
    /// file wholesale — see <see cref="AppSettings"/>).
    /// </summary>
    internal sealed class AppSettingsData
    {
        /// <summary>Selected UI language code (e.g. <c>"pt"</c>), or null to follow the system.</summary>
        public string? Language { get; set; }

        /// <summary>Whether the startup update check runs (issue #85). Default ON; the user can opt
        /// out (privacy / air-gapped), which suppresses the network call entirely.</summary>
        public bool UpdateCheckEnabled { get; set; } = true;

        /// <summary>The newest "update available" version the user dismissed, so a routine nudge
        /// nags once per version; a newer release re-appears. Never set for the mandatory banner.</summary>
        public string? LastDismissedUpdateVersion { get; set; }
    }

    /// <summary>
    /// Load/modify/save for <see cref="AppSettingsData"/>. All access is best-effort and never
    /// throws to callers: a missing or corrupt file yields defaults, and a failed write is silently
    /// ignored (the choice simply isn't remembered). <see cref="Update"/> does a locked
    /// read-modify-write so concurrent setting changes don't clobber each other.
    /// </summary>
    internal static class AppSettings
    {
        private static readonly object Gate = new();

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,   // reads/writes "language", "updateCheckEnabled", …
            PropertyNameCaseInsensitive = true,
            WriteIndented = true,
        };

        private static string FilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "IntercomFirmwareTool", "settings.json");

        /// <summary>Reads the current settings (defaults if the file is missing/corrupt).</summary>
        public static AppSettingsData Load()
        {
            lock (Gate) return LoadUnlocked();
        }

        private static AppSettingsData LoadUnlocked()
        {
            try
            {
                string path = FilePath;
                if (File.Exists(path))
                {
                    var data = JsonSerializer.Deserialize<AppSettingsData>(File.ReadAllText(path), JsonOptions);
                    if (data is not null) return data;
                }
            }
            catch { /* missing/corrupt settings — fall back to defaults */ }
            return new AppSettingsData();
        }

        /// <summary>
        /// Atomically load → mutate → persist, preserving every other setting (read-modify-write
        /// under a lock). Best-effort: a failed write is swallowed.
        /// </summary>
        public static void Update(Action<AppSettingsData> mutate)
        {
            lock (Gate)
            {
                string? tmp = null;
                try
                {
                    // Load → mutate → persist all inside the try: a throwing mutator (or any I/O
                    // failure) must never escape — Update is best-effort and documented not to throw
                    // to callers (it runs from UI event handlers). A mutator that throws simply
                    // leaves the on-disk settings unchanged.
                    var data = LoadUnlocked();
                    mutate(data);

                    string path = FilePath;
                    string dir = Path.GetDirectoryName(path)!;
                    Directory.CreateDirectory(dir);
                    // Write to a UNIQUE temp file in the SAME directory, then atomically move it over
                    // the target. File.WriteAllText truncates the destination in place, so a crash
                    // mid-write would leave partial JSON that Load treats as corrupt and resets to
                    // defaults — silently re-enabling the update check after the user opted out. A
                    // unique name avoids colliding with another instance or a crashed run's leftover.
                    tmp = Path.Combine(dir, $"settings.{Guid.NewGuid():N}.tmp");
                    File.WriteAllText(tmp, JsonSerializer.Serialize(data, JsonOptions));
                    File.Move(tmp, path, overwrite: true);
                }
                catch { /* best-effort; a failed save just means the choice isn't remembered */ }
                finally
                {
                    // Don't leave a temp behind if the move never happened.
                    if (tmp is not null && File.Exists(tmp)) { try { File.Delete(tmp); } catch { /* ignore */ } }
                }
            }
        }
    }
}
