using IntercomFirmwareTool.Core.Updates;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests.Updates;

public class UpdateManifestTests
{
    [Fact]
    public void TryParse_reads_all_fields()
    {
        const string json = """
            { "schemaVersion": 1, "latestVersion": "1.3.0", "minimumSupportedVersion": "1.1.0" }
            """;
        Assert.True(UpdateManifest.TryParse(json, out var m));
        Assert.NotNull(m);
        Assert.Equal(1, m!.SchemaVersion);
        Assert.Equal("1.3.0", m.LatestVersion);
        Assert.Equal("1.1.0", m.MinimumSupportedVersion);
    }

    [Fact]
    public void TryParse_tolerates_missing_optional_fields()
    {
        Assert.True(UpdateManifest.TryParse("""{ "schemaVersion": 1 }""", out var m));
        Assert.NotNull(m);
        Assert.Equal(1, m!.SchemaVersion);
        Assert.Null(m.LatestVersion);
        Assert.Null(m.MinimumSupportedVersion);
    }

    [Fact]
    public void TryParse_defaults_missing_or_nonnumeric_schema_to_zero()
    {
        Assert.True(UpdateManifest.TryParse("""{ "latestVersion": "1.3.0" }""", out var m1));
        Assert.Equal(0, m1!.SchemaVersion);

        Assert.True(UpdateManifest.TryParse("""{ "schemaVersion": "1" }""", out var m2));
        Assert.Equal(0, m2!.SchemaVersion); // string, not a number → ignored
    }

    [Fact]
    public void TryParse_ignores_extra_and_wrongly_typed_fields()
    {
        const string json = """
            { "schemaVersion": 1, "latestVersion": 130, "extra": true, "note": "hi" }
            """;
        Assert.True(UpdateManifest.TryParse(json, out var m));
        Assert.Null(m!.LatestVersion); // number, not a string → null (fails open downstream)
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[1,2,3]")]        // array, not an object
    [InlineData("\"a string\"")]  // JSON string, not an object
    [InlineData("{ \"schemaVersion\": 1, ")] // truncated
    public void TryParse_rejects_non_object_or_malformed(string? json)
    {
        Assert.False(UpdateManifest.TryParse(json, out var m));
        Assert.Null(m);
    }
}
