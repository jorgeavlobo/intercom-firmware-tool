namespace IntercomFirmwareTool.Core.Updates;

/// <summary>The outcome of an update check (issue #85).</summary>
public enum UpdateStatusKind
{
    /// <summary>Running the latest (or ahead of it): no banner, all controls enabled.</summary>
    UpToDate,

    /// <summary>A newer normal release exists: informational, dismissible banner; controls stay
    /// enabled.</summary>
    UpdateAvailable,

    /// <summary>The running version is below the maintainer-flagged minimum-supported version on a
    /// clear, valid signal: red mandatory banner, actions disabled.</summary>
    Unsupported,

    /// <summary>The check could not produce a confident answer (dev build, offline, timeout,
    /// malformed/absent manifest, unknown schema with no nudge): treated exactly like
    /// <see cref="UpToDate"/> — no banner, app fully usable.</summary>
    Unknown,
}

/// <summary>The result of <see cref="UpdateChecker.Evaluate"/>: a kind plus, where relevant, the
/// version to surface (the newer release, or the minimum-supported version).</summary>
public sealed record UpdateStatus(UpdateStatusKind Kind, SemanticVersion? Version = null)
{
    /// <summary>Shared up-to-date result.</summary>
    public static readonly UpdateStatus UpToDate = new(UpdateStatusKind.UpToDate);

    /// <summary>Shared unknown/fail-open result.</summary>
    public static readonly UpdateStatus Unknown = new(UpdateStatusKind.Unknown);

    /// <summary>A newer release <paramref name="version"/> is available.</summary>
    public static UpdateStatus Available(SemanticVersion version) =>
        new(UpdateStatusKind.UpdateAvailable, version);

    /// <summary>The running build is below the minimum-supported <paramref name="version"/>.</summary>
    public static UpdateStatus Unsupported(SemanticVersion version) =>
        new(UpdateStatusKind.Unsupported, version);
}

/// <summary>
/// The pure decision logic for the startup update check (issue #85). No I/O — the app fetches the
/// manifest over HTTP and passes it (plus the running version) here. Every ambiguous or malformed
/// input resolves to <see cref="UpdateStatusKind.Unknown"/> or <see cref="UpdateStatusKind.UpToDate"/>
/// (never a block), so a dead network or one bad manifest edit can neither nag nor brick anyone.
/// </summary>
public static class UpdateChecker
{
    /// <summary>
    /// Decides the update status from the running <paramref name="current"/> version and the fetched
    /// <paramref name="manifest"/>.
    /// <list type="bullet">
    /// <item><description><paramref name="current"/> null (dev/untagged build) or
    /// <paramref name="manifest"/> null/malformed ⇒ <see cref="UpdateStatusKind.Unknown"/>.</description></item>
    /// <item><description>Block (<see cref="UpdateStatusKind.Unsupported"/>) ONLY on a clear, sane
    /// signal: the manifest schema is exactly understood, <c>minimumSupportedVersion</c> and
    /// <c>latestVersion</c> both parse, <c>current &lt; minimumSupportedVersion</c>, and
    /// <c>minimumSupportedVersion &lt;= latestVersion</c>. Anything missing/absurd ⇒ no block.</description></item>
    /// <item><description>Otherwise a newer <c>latestVersion</c> ⇒ <see cref="UpdateStatusKind.UpdateAvailable"/>;
    /// a pre-release <c>latestVersion</c> is ignored unless <paramref name="includePrereleases"/> is set.</description></item>
    /// </list>
    /// </summary>
    public static UpdateStatus Evaluate(
        SemanticVersion? current,
        UpdateManifest? manifest,
        bool includePrereleases = false)
    {
        // Dev/untagged build, or no usable manifest ⇒ stay silent.
        if (current is null || manifest is null)
            return UpdateStatus.Unknown;

        // A schema older than 1 is malformed; a schema newer than we understand is honoured only
        // for the informational nudge, never for the block decision (conservative forward-compat).
        if (manifest.SchemaVersion < UpdateManifest.CurrentSchemaVersion)
            return UpdateStatus.Unknown;
        bool blockingAllowed = manifest.SchemaVersion == UpdateManifest.CurrentSchemaVersion;

        SemanticVersion.TryParse(manifest.LatestVersion, out SemanticVersion? latest);
        SemanticVersion.TryParse(manifest.MinimumSupportedVersion, out SemanticVersion? minimum);

        // Block only on the full, sane signal — including the minimum <= latest sanity gate, which
        // needs a valid latest to compare against.
        if (blockingAllowed &&
            minimum is not null &&
            latest is not null &&
            current.CompareTo(minimum) < 0 &&
            minimum.CompareTo(latest) <= 0)
        {
            return UpdateStatus.Unsupported(minimum);
        }

        // We can only reason about "latest" when it's one we actually consider: a stable version,
        // or any version when the user opted into pre-releases. A missing/unparseable latest, or a
        // pre-release we're ignoring, leaves the latest indeterminate.
        bool haveComparableLatest = latest is not null && (includePrereleases || !latest.IsPrerelease);

        // Informational nudge: a newer release is available.
        if (haveComparableLatest && current.CompareTo(latest!) < 0)
            return UpdateStatus.Available(latest!);

        // Only claim "up to date" when we truly determined the latest; otherwise fail open as
        // Unknown, so a manual check reports it couldn't determine one instead of a false "you're
        // on the latest" (matters when latestVersion is missing/unparseable or an ignored
        // pre-release — the automatic check treats Unknown and UpToDate identically anyway).
        return haveComparableLatest ? UpdateStatus.UpToDate : UpdateStatus.Unknown;
    }
}
