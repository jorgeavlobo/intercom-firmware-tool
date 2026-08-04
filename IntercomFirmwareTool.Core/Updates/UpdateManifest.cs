using System.Text.Json;

namespace IntercomFirmwareTool.Core.Updates;

/// <summary>
/// The parsed update manifest (issue #85), served raw from
/// <c>.well-known/updates.json</c> on the repository's default branch:
/// <code>
/// { "schemaVersion": 1, "latestVersion": "1.3.0", "minimumSupportedVersion": "1.1.0" }
/// </code>
/// <para>
/// <see cref="LatestVersion"/> drives the informational "update available" nudge and is bumped
/// automatically by the release workflow; <see cref="MinimumSupportedVersion"/> is bumped
/// manually, only to retroactively flag an old build unsafe. Both are kept as raw strings here —
/// <see cref="UpdateChecker"/> parses and sanity-checks them so a malformed field simply fails
/// open (no nag, no block) instead of throwing.
/// </para>
/// </summary>
public sealed record UpdateManifest(
    int SchemaVersion,
    string? LatestVersion,
    string? MinimumSupportedVersion)
{
    /// <summary>The manifest schema this app understands. A higher schema is treated
    /// conservatively (informational only, never blocking) by <see cref="UpdateChecker"/>.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>
    /// Parses the manifest JSON defensively. Returns false for anything that is not a JSON object
    /// or throws while reading — the caller then shows no banner and leaves the app fully usable.
    /// Missing/oddly-typed fields yield a manifest with <c>null</c> versions (still safe: the
    /// checker fails open on them), never an exception.
    /// </summary>
    public static bool TryParse(string? json, out UpdateManifest? manifest)
    {
        manifest = null;
        if (string.IsNullOrWhiteSpace(json))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return false;

            int schema = 0;
            if (root.TryGetProperty("schemaVersion", out var sv) &&
                sv.ValueKind == JsonValueKind.Number &&
                sv.TryGetInt32(out int parsedSchema))
            {
                schema = parsedSchema;
            }

            manifest = new UpdateManifest(
                schema,
                ReadString(root, "latestVersion"),
                ReadString(root, "minimumSupportedVersion"));
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string? ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String
            ? el.GetString()
            : null;
}
