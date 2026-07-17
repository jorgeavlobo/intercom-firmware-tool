using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Resources;
using System.Text.Json;
using System.Threading;

namespace IntercomFirmwareTool.App.Localization
{
    /// <summary>One selectable UI language: its two-letter code and its own native name.</summary>
    public sealed record LanguageOption(string Code, string NativeName);

    /// <summary>
    /// Runtime-switchable UI language for the whole app.
    ///
    /// XAML binds through the indexer via the <c>{loc:Loc Key}</c> markup extension;
    /// code-behind and Core read the same strings by key. Changing the language raises
    /// the indexer's change notification, so every <c>{loc:Loc}</c> binding re-reads
    /// its text live (no restart) — imperatively-set text is refreshed by handling
    /// <see cref="LanguageChanged"/>.
    ///
    /// The chosen language also flows to <see cref="CultureInfo.DefaultThreadCurrentUICulture"/>
    /// so background work (Task.Run in the build/verify paths) and the Core library,
    /// which read <see cref="CultureInfo.CurrentUICulture"/>, produce messages in the
    /// same language.
    /// </summary>
    public sealed class LocalizationManager : INotifyPropertyChanged
    {
        public static LocalizationManager Instance { get; } = new LocalizationManager();

        /// <summary>
        /// The offered languages, labelled by NATIVE name only (no flags): a flag is a
        /// country, not a language, and several of these span many countries.
        /// </summary>
        public static IReadOnlyList<LanguageOption> Languages { get; } = new[]
        {
            new LanguageOption("en", "English"),
            new LanguageOption("it", "Italiano"),
            new LanguageOption("es", "Español"),
            new LanguageOption("fr", "Français"),
            new LanguageOption("de", "Deutsch"),
            // Neutral "pt" on purpose: the text is European Portuguese, but a neutral
            // culture also serves pt-BR (and any Portuguese UI) — Portuguese beats
            // falling back to English for those users.
            new LanguageOption("pt", "Português"),
        };

        private readonly ResourceManager _rm = new ResourceManager(
            "IntercomFirmwareTool.App.Resources.Strings", typeof(LocalizationManager).Assembly);

        private CultureInfo _culture = CultureInfo.GetCultureInfo("en");

        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>Raised after the language changes so views can re-apply imperative text.</summary>
        public event EventHandler? LanguageChanged;

        private LocalizationManager() { }

        public CultureInfo CurrentCulture => _culture;
        public string CurrentCode => _culture.TwoLetterISOLanguageName;

        /// <summary>Binding entry point used by <c>{loc:Loc Key}</c>. Falls back to the key.</summary>
        public string this[string key] => _rm.GetString(key, _culture) ?? key;

        /// <summary>Look up a string by key (code-behind convenience).</summary>
        public string Get(string key) => this[key];

        /// <summary>Look up a format string by key and fill it in the current culture.</summary>
        public string Format(string key, params object?[] args) => string.Format(_culture, this[key], args);

        /// <summary>
        /// Picks the initial language on startup: the saved choice if any, otherwise the
        /// system UI language when it is one we ship, otherwise English. Does not persist.
        /// </summary>
        public void Initialize()
        {
            string code = LoadSavedCode() ?? SystemDefaultCode();
            Apply(code, persist: false);
        }

        /// <summary>Switches the language at runtime and remembers the choice.</summary>
        public void SetLanguage(string code) => Apply(code, persist: true);

        private void Apply(string code, bool persist)
        {
            if (!Languages.Any(l => l.Code == code)) code = "en";
            _culture = CultureInfo.GetCultureInfo(code);

            // Current thread + the default for every other thread (so Task.Run work and
            // the Core library, which read CurrentUICulture, use the chosen language).
            Thread.CurrentThread.CurrentCulture = _culture;
            Thread.CurrentThread.CurrentUICulture = _culture;
            CultureInfo.DefaultThreadCurrentCulture = _culture;
            CultureInfo.DefaultThreadCurrentUICulture = _culture;

            // Refresh every {loc:Loc} binding, then let views re-apply imperative text.
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
            LanguageChanged?.Invoke(this, EventArgs.Empty);

            if (persist) SaveCode(code);
        }

        private static string SystemDefaultCode()
        {
            // Prefer the user's current display/UI language over the OS install
            // language — e.g. a French display on English-installed Windows should
            // start in French. Fall back to the installed language, then English.
            foreach (var culture in new[] { CultureInfo.CurrentUICulture, CultureInfo.InstalledUICulture })
            {
                string code = culture.TwoLetterISOLanguageName;
                if (Languages.Any(l => l.Code == code)) return code;
            }
            return "en";
        }

        // Persistence: %AppData%\IntercomFirmwareTool\settings.json
        private static string SettingsPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "IntercomFirmwareTool", "settings.json");

        private static string? LoadSavedCode()
        {
            try
            {
                if (!File.Exists(SettingsPath)) return null;
                using var doc = JsonDocument.Parse(File.ReadAllText(SettingsPath));
                if (doc.RootElement.TryGetProperty("language", out var el))
                {
                    string? code = el.GetString();
                    if (!string.IsNullOrWhiteSpace(code) && Languages.Any(l => l.Code == code))
                        return code;
                }
            }
            catch { /* missing/corrupt settings — fall back to the system language */ }
            return null;
        }

        private static void SaveCode(string code)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
                File.WriteAllText(SettingsPath, JsonSerializer.Serialize(new { language = code }));
            }
            catch { /* best-effort; a failed save just means we ask the OS next launch */ }
        }
    }
}
