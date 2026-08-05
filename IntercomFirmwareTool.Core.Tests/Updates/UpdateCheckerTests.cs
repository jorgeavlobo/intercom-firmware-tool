using IntercomFirmwareTool.Core.Updates;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests.Updates;

public class UpdateCheckerTests
{
    private static SemanticVersion V(string s)
    {
        Assert.True(SemanticVersion.TryParse(s, out var v));
        return v!;
    }

    private static UpdateManifest M(string? latest, string? minimum = null, int schema = 1) =>
        new(schema, latest, minimum);

    // ---- Unknown / fail-open on missing inputs -------------------------------------------------

    [Fact]
    public void Null_current_version_is_Unknown()  // dev/untagged build ⇒ don't nag
        => Assert.Equal(UpdateStatusKind.Unknown, UpdateChecker.Evaluate(null, M("9.9.9")).Kind);

    [Fact]
    public void Null_manifest_is_Unknown()
        => Assert.Equal(UpdateStatusKind.Unknown, UpdateChecker.Evaluate(V("1.0.0"), null).Kind);

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Schema_below_current_is_Unknown(int schema)
        => Assert.Equal(UpdateStatusKind.Unknown,
            UpdateChecker.Evaluate(V("1.0.0"), M("2.0.0", schema: schema)).Kind);

    // ---- Update-available (informational) ------------------------------------------------------

    [Fact]
    public void Newer_latest_is_UpdateAvailable()
    {
        var s = UpdateChecker.Evaluate(V("1.0.0"), M("1.3.0"));
        Assert.Equal(UpdateStatusKind.UpdateAvailable, s.Kind);
        Assert.Equal(V("1.3.0"), s.Version);
    }

    [Fact]
    public void Equal_version_is_UpToDate()
        => Assert.Equal(UpdateStatusKind.UpToDate, UpdateChecker.Evaluate(V("1.3.0"), M("1.3.0")).Kind);

    [Fact]
    public void Ahead_of_latest_is_UpToDate()   // local build newer than published
        => Assert.Equal(UpdateStatusKind.UpToDate, UpdateChecker.Evaluate(V("2.0.0"), M("1.3.0")).Kind);

    [Fact]
    public void Prerelease_of_same_version_gets_the_stable_update()
    {
        var s = UpdateChecker.Evaluate(V("1.2.0-rc.1"), M("1.2.0"));
        Assert.Equal(UpdateStatusKind.UpdateAvailable, s.Kind);
    }

    [Fact]
    public void Prerelease_latest_is_ignored_by_default()  // ignored ⇒ latest indeterminate ⇒ Unknown
        => Assert.Equal(UpdateStatusKind.Unknown, UpdateChecker.Evaluate(V("1.2.0"), M("1.3.0-rc.1")).Kind);

    [Fact]
    public void Prerelease_latest_surfaces_when_opted_in()
    {
        var s = UpdateChecker.Evaluate(V("1.2.0"), M("1.3.0-rc.1"), includePrereleases: true);
        Assert.Equal(UpdateStatusKind.UpdateAvailable, s.Kind);
        Assert.Equal(V("1.3.0-rc.1"), s.Version);
    }

    [Fact]
    public void Unparseable_latest_is_Unknown()  // can't determine the latest ⇒ fail open, no nag
        => Assert.Equal(UpdateStatusKind.Unknown, UpdateChecker.Evaluate(V("1.2.0"), M("not-a-version")).Kind);

    // ---- Block (Unsupported) — only on the full, sane signal -----------------------------------

    [Fact]
    public void Below_minimum_with_sane_signal_is_Unsupported()
    {
        var s = UpdateChecker.Evaluate(V("1.0.0"), M("1.3.0", minimum: "1.1.0"));
        Assert.Equal(UpdateStatusKind.Unsupported, s.Kind);
        Assert.Equal(V("1.1.0"), s.Version);
    }

    [Fact]
    public void At_or_above_minimum_is_not_blocked()
    {
        Assert.Equal(UpdateStatusKind.UpdateAvailable,
            UpdateChecker.Evaluate(V("1.1.0"), M("1.3.0", minimum: "1.1.0")).Kind);
        Assert.Equal(UpdateStatusKind.UpToDate,
            UpdateChecker.Evaluate(V("1.3.0"), M("1.3.0", minimum: "1.1.0")).Kind);
    }

    [Fact]
    public void Minimum_greater_than_latest_is_absurd_no_block()
    {
        // min > latest ⇒ ignore the block; still surface the (newer) latest as info.
        var s = UpdateChecker.Evaluate(V("1.0.0"), M("1.3.0", minimum: "2.0.0"));
        Assert.Equal(UpdateStatusKind.UpdateAvailable, s.Kind);
    }

    [Fact]
    public void Unparseable_minimum_never_blocks()
    {
        var s = UpdateChecker.Evaluate(V("1.0.0"), M("1.3.0", minimum: "garbage"));
        Assert.Equal(UpdateStatusKind.UpdateAvailable, s.Kind);
    }

    [Fact]
    public void Minimum_without_parseable_latest_never_blocks()
    {
        // No sane 'latest' to gate against ⇒ do not block; and with no latest to compare, the
        // result is Unknown rather than a false "up to date".
        var s = UpdateChecker.Evaluate(V("1.0.0"), M(null, minimum: "1.1.0"));
        Assert.NotEqual(UpdateStatusKind.Unsupported, s.Kind);
        Assert.Equal(UpdateStatusKind.Unknown, s.Kind);
    }

    [Fact]
    public void Unknown_future_schema_never_blocks_but_still_informs()
    {
        // schema 2: we don't understand it fully ⇒ never block, but the newer latest still nudges.
        var s = UpdateChecker.Evaluate(V("1.0.0"), M("1.3.0", minimum: "1.1.0", schema: 2));
        Assert.Equal(UpdateStatusKind.UpdateAvailable, s.Kind);
    }
}
