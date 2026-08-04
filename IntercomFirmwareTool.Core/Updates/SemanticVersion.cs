using System.Globalization;
using System.Numerics;

namespace IntercomFirmwareTool.Core.Updates;

/// <summary>
/// A minimal, dependency-free Semantic Versioning 2.0.0 value with correct precedence
/// (<see href="https://semver.org/#spec-item-11"/>), used by the startup update check (#85)
/// to compare the running build against the versions in the update manifest.
///
/// Only what this feature needs: parse <c>MAJOR.MINOR.PATCH</c> with an optional
/// <c>-prerelease</c> and an (ignored) <c>+build</c> metadata suffix, and compare. A single
/// leading <c>v</c>/<c>V</c> is tolerated so a tag-shaped string still parses. Build metadata
/// does NOT affect precedence, per the spec.
/// </summary>
public sealed record SemanticVersion : IComparable<SemanticVersion>
{
    /// <summary>Major.Minor.Patch — the numeric core.</summary>
    public int Major { get; }

    /// <inheritdoc cref="Major"/>
    public int Minor { get; }

    /// <inheritdoc cref="Major"/>
    public int Patch { get; }

    /// <summary>
    /// The dot-separated pre-release identifiers (e.g. <c>["rc", "1"]</c> for <c>-rc.1</c>),
    /// or <c>null</c> for a normal release. An empty list is never produced.
    /// </summary>
    public IReadOnlyList<string>? Prerelease { get; }

    /// <summary>True when this is a pre-release (e.g. <c>1.2.0-rc.1</c>), which ranks below the
    /// matching normal release <c>1.2.0</c>.</summary>
    public bool IsPrerelease => Prerelease is { Count: > 0 };

    private SemanticVersion(int major, int minor, int patch, IReadOnlyList<string>? prerelease)
    {
        Major = major;
        Minor = minor;
        Patch = patch;
        Prerelease = prerelease is { Count: > 0 } ? prerelease : null;
    }

    /// <summary>
    /// Parses a strict <c>MAJOR.MINOR.PATCH[-prerelease][+build]</c> string. Returns false (and a
    /// null result) for anything malformed — callers treat an unparseable version as "unknown"
    /// and fail open (no nag, no block).
    /// </summary>
    public static bool TryParse(string? value, out SemanticVersion? version)
    {
        version = null;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        string s = value.Trim();
        // Tolerate a single leading 'v' (e.g. a raw tag name) — but nothing else exotic.
        if (s.Length > 0 && (s[0] == 'v' || s[0] == 'V'))
            s = s[1..];

        // Strip build metadata (ignored for precedence); it must be the last '+'-delimited part.
        int plus = s.IndexOf('+');
        if (plus >= 0)
            s = s[..plus];

        // Split off the pre-release part (everything after the first '-').
        string core;
        string? pre = null;
        int dash = s.IndexOf('-');
        if (dash >= 0)
        {
            core = s[..dash];
            pre = s[(dash + 1)..];
        }
        else
        {
            core = s;
        }

        string[] nums = core.Split('.');
        if (nums.Length != 3)
            return false;
        if (!TryParseNumericCore(nums[0], out int major) ||
            !TryParseNumericCore(nums[1], out int minor) ||
            !TryParseNumericCore(nums[2], out int patch))
            return false;

        IReadOnlyList<string>? prerelease = null;
        if (pre is not null)
        {
            if (pre.Length == 0)
                return false; // a trailing '-' with no identifiers is malformed
            string[] ids = pre.Split('.');
            foreach (string id in ids)
            {
                if (id.Length == 0)
                    return false; // empty identifier (e.g. "rc..1")
                // Identifiers are alphanumerics + hyphen; numeric ones must not have leading zeros.
                foreach (char c in id)
                {
                    if (!(char.IsAsciiLetterOrDigit(c) || c == '-'))
                        return false;
                }
                if (IsAllDigits(id) && id.Length > 1 && id[0] == '0')
                    return false; // numeric identifier with a leading zero
            }
            prerelease = ids;
        }

        version = new SemanticVersion(major, minor, patch, prerelease);
        return true;
    }

    private static bool TryParseNumericCore(string s, out int value)
    {
        value = 0;
        if (s.Length == 0)
            return false;
        if (s.Length > 1 && s[0] == '0')
            return false; // no leading zeros in the numeric core
        foreach (char c in s)
        {
            if (!char.IsAsciiDigit(c))
                return false;
        }
        return int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    private static bool IsAllDigits(string s)
    {
        foreach (char c in s)
        {
            if (!char.IsAsciiDigit(c))
                return false;
        }
        return s.Length > 0;
    }

    /// <summary>
    /// Semantic-version precedence per spec item 11. Build metadata is ignored; a pre-release
    /// ranks below its matching normal release; pre-release identifiers compare numerically when
    /// both are numeric, otherwise lexically (ASCII), with numeric ranking below alphanumeric,
    /// and a longer identifier set winning when all shared identifiers are equal.
    /// </summary>
    public int CompareTo(SemanticVersion? other)
    {
        if (other is null)
            return 1;

        int c = Major.CompareTo(other.Major);
        if (c != 0) return c;
        c = Minor.CompareTo(other.Minor);
        if (c != 0) return c;
        c = Patch.CompareTo(other.Patch);
        if (c != 0) return c;

        bool thisPre = IsPrerelease;
        bool otherPre = other.IsPrerelease;
        if (!thisPre && !otherPre) return 0;
        if (!thisPre) return 1;   // normal release > pre-release
        if (!otherPre) return -1;

        IReadOnlyList<string> a = Prerelease!;
        IReadOnlyList<string> b = other.Prerelease!;
        int shared = Math.Min(a.Count, b.Count);
        for (int i = 0; i < shared; i++)
        {
            int idc = CompareIdentifier(a[i], b[i]);
            if (idc != 0) return idc;
        }
        return a.Count.CompareTo(b.Count);
    }

    private static int CompareIdentifier(string a, string b)
    {
        bool aNum = IsAllDigits(a);
        bool bNum = IsAllDigits(b);
        if (aNum && bNum)
            return BigInteger.Parse(a, CultureInfo.InvariantCulture)
                .CompareTo(BigInteger.Parse(b, CultureInfo.InvariantCulture));
        if (aNum) return -1; // numeric identifiers have lower precedence than alphanumeric
        if (bNum) return 1;
        return string.CompareOrdinal(a, b);
    }

    /// <summary>
    /// Value equality by precedence: build metadata is ignored and pre-release identifiers are
    /// compared structurally, so two parses of the same string are equal. This deliberately
    /// replaces the record's default field-by-field equality, which would compare the pre-release
    /// list by reference (making equal versions from separate parses compare unequal).
    /// </summary>
    public bool Equals(SemanticVersion? other) => other is not null && CompareTo(other) == 0;

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(Major, Minor, Patch, IsPrerelease ? string.Join('.', Prerelease!) : null);

    /// <summary>Renders back to a canonical <c>MAJOR.MINOR.PATCH[-prerelease]</c> string.</summary>
    public override string ToString()
    {
        string core = $"{Major}.{Minor}.{Patch}";
        return IsPrerelease ? $"{core}-{string.Join('.', Prerelease!)}" : core;
    }
}
