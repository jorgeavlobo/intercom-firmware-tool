using IntercomFirmwareTool.Core.Updates;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests.Updates;

public class SemanticVersionTests
{
    [Theory]
    [InlineData("1.2.3", 1, 2, 3, false)]
    [InlineData("v1.2.3", 1, 2, 3, false)]       // a leading 'v' is tolerated
    [InlineData("0.0.0", 0, 0, 0, false)]
    [InlineData("10.20.30", 10, 20, 30, false)]
    [InlineData("1.2.3-rc.1", 1, 2, 3, true)]
    [InlineData("1.2.3-alpha-beta", 1, 2, 3, true)]   // internal hyphen inside an identifier
    [InlineData("1.2.3+build.5", 1, 2, 3, false)]     // build metadata ignored
    [InlineData("1.2.3-rc.1+build.5", 1, 2, 3, true)]
    public void TryParse_accepts_valid(string input, int major, int minor, int patch, bool isPre)
    {
        Assert.True(SemanticVersion.TryParse(input, out var v));
        Assert.NotNull(v);
        Assert.Equal(major, v!.Major);
        Assert.Equal(minor, v.Minor);
        Assert.Equal(patch, v.Patch);
        Assert.Equal(isPre, v.IsPrerelease);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("1")]
    [InlineData("1.2")]
    [InlineData("1.2.3.4")]
    [InlineData("1.2.x")]
    [InlineData("01.2.3")]        // leading zero in numeric core
    [InlineData("1.2.3-")]        // trailing dash, no identifiers
    [InlineData("1.2.3-rc..1")]   // empty identifier
    [InlineData("1.2.3-rc.01")]   // numeric identifier with leading zero
    [InlineData("1.2.3-rc!1")]    // illegal character
    [InlineData("1.2.3+")]        // empty build metadata
    [InlineData("1.2.3+bad!")]    // illegal character in build metadata
    [InlineData("1.2.3+a..b")]    // empty build-metadata identifier
    [InlineData("2147483648.0.0")] // numeric core overflows int
    [InlineData("abc")]
    public void TryParse_rejects_invalid(string? input)
    {
        Assert.False(SemanticVersion.TryParse(input, out var v));
        Assert.Null(v);
    }

    [Fact]
    public void Core_precedence_is_numeric()
    {
        Assert.True(Cmp("1.0.0", "2.0.0") < 0);
        Assert.True(Cmp("2.0.0", "2.1.0") < 0);
        Assert.True(Cmp("2.1.0", "2.1.1") < 0);
        Assert.True(Cmp("2.1.1", "2.1.1") == 0);
        // numeric, not lexical: 2 < 11
        Assert.True(Cmp("1.2.0", "1.11.0") < 0);
    }

    [Fact]
    public void Prerelease_ranks_below_release()
    {
        Assert.True(Cmp("1.0.0-alpha", "1.0.0") < 0);
        Assert.True(Cmp("1.0.0", "1.0.0-alpha") > 0);
    }

    [Fact]
    public void Prerelease_ordering_matches_spec_example()
    {
        // https://semver.org/#spec-item-11
        string[] ordered =
        {
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",   // numeric identifiers compared numerically: 2 < 11
            "1.0.0-rc.1",
            "1.0.0",
        };
        for (int i = 0; i < ordered.Length - 1; i++)
            Assert.True(Cmp(ordered[i], ordered[i + 1]) < 0, $"{ordered[i]} should be < {ordered[i + 1]}");
    }

    [Fact]
    public void Build_metadata_does_not_affect_precedence_or_equality()
    {
        Assert.Equal(0, Cmp("1.2.3+a", "1.2.3+b"));
        Assert.True(SemanticVersion.TryParse("1.2.3+a", out var a));
        Assert.True(SemanticVersion.TryParse("1.2.3+b", out var b));
        Assert.Equal(a, b); // record equality: metadata is not stored
    }

    [Fact]
    public void ToString_roundtrips_canonical_form()
    {
        Assert.True(SemanticVersion.TryParse("1.2.3-rc.1+meta", out var v));
        Assert.Equal("1.2.3-rc.1", v!.ToString());
    }

    private static int Sign(int x) => x < 0 ? -1 : x > 0 ? 1 : 0;

    private static int Cmp(string a, string b)
    {
        Assert.True(SemanticVersion.TryParse(a, out var va));
        Assert.True(SemanticVersion.TryParse(b, out var vb));
        return Sign(va!.CompareTo(vb));
    }
}
