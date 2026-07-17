using System.Globalization;
using System.Resources;

namespace IntercomFirmwareTool.Core.Localization
{
    /// <summary>
    /// Localized user-facing messages for the Core library (verify/describe results and
    /// the prose exception messages that surface in the app's dialogs and Result box).
    ///
    /// Reads the ambient <see cref="CultureInfo.CurrentUICulture"/>, which the app sets —
    /// including <see cref="CultureInfo.DefaultThreadCurrentUICulture"/> — so a message
    /// built on any thread (Core work runs under Task.Run) uses the user's chosen
    /// language. A missing resource falls back to the key so nothing is ever blank.
    ///
    /// Technical output stays in English by design: exception stack traces, the terse
    /// Linux-path PASS/FAIL check names, and crypto self-test vectors are diagnostic and
    /// identical in every language, so they are NOT routed through here.
    /// </summary>
    public static class CoreStrings
    {
        private static readonly ResourceManager Rm = new ResourceManager(
            "IntercomFirmwareTool.Core.Resources.CoreStrings", typeof(CoreStrings).Assembly);

        public static string Get(string key) =>
            Rm.GetString(key, CultureInfo.CurrentUICulture) ?? key;

        public static string Format(string key, params object?[] args) =>
            string.Format(CultureInfo.CurrentUICulture, Get(key), args);
    }
}
