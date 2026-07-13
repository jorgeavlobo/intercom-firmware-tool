namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// Filesystem path identity. Decides whether two paths point to the same file
    /// by canonicalising each (resolving symlinks/junctions on the final component
    /// AND every parent directory in the chain) and comparing the results, so an
    /// aliased path is not mistaken for a different file. Shared by the build guard
    /// (never overwrite the input <c>.fwz</c>) and the UI's path-collision checks so
    /// both apply the same rule. Note: this catches symlink/junction aliases but
    /// NOT hard links (which share data with no reparse point); the build's
    /// temp-file-then-move commit makes a hard-linked target non-destructive anyway
    /// (removing one hard link leaves the data reachable via the other).
    /// </summary>
    public static class PathIdentity
    {
        /// <summary>
        /// True if two paths resolve to the same file. Comparison is
        /// case-insensitive on Windows and case-sensitive elsewhere, matching the
        /// host filesystem. Never throws — returns false if a path cannot be
        /// resolved (an unusable path is handled as a hard failure by the caller).
        /// </summary>
        public static bool SamePath(string a, string b)
        {
            try
            {
                var cmp = OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal;
                return string.Equals(ResolveFinal(a), ResolveFinal(b), cmp);
            }
            catch { return false; }
        }

        /// <summary>
        /// Canonical path with symlinks/junctions resolved to their final target —
        /// the final component AND every parent directory in the chain — so an
        /// output that reaches the input through an aliased parent (e.g.
        /// <c>C:\link\fw.fwz</c> where <c>link</c> is a junction to the input's
        /// directory) maps to the same path as the input. Walked component by
        /// component from the root; each component that does not exist or is not a
        /// link is used as-is (so a not-yet-created output still resolves through
        /// its existing parent chain), and any failure degrades to the plain full
        /// path — never worse than a string comparison.
        /// </summary>
        public static string ResolveFinal(string path)
        {
            string full = Path.GetFullPath(path);
            string? root = Path.GetPathRoot(full);
            if (string.IsNullOrEmpty(root)) return full;

            string[] parts = full.Substring(root.Length).Split(
                new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                StringSplitOptions.RemoveEmptyEntries);

            string acc = root;
            for (int i = 0; i < parts.Length; i++)
            {
                acc = Path.Combine(acc, parts[i]);
                bool isLast = i == parts.Length - 1;
                try
                {
                    // A file link only makes sense on the last component; parents
                    // are resolved as directory links/junctions.
                    var target = isLast
                        ? File.ResolveLinkTarget(acc, returnFinalTarget: true)
                        : Directory.ResolveLinkTarget(acc, returnFinalTarget: true);
                    if (target != null) acc = Path.GetFullPath(target.FullName);
                }
                catch { /* missing / not a link / unsupported — keep this component */ }
            }
            return acc;
        }
    }
}
