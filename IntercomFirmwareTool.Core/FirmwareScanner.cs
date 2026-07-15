using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// Background locator for unmodified original firmware on the machine, so the
    /// file picker can open where the most recent one lives instead of some stale
    /// last-used folder.
    ///
    /// <para>Strategy: scan the most-likely user folders first (Downloads, Desktop,
    /// Documents) so a good answer is ready almost immediately, then sweep the rest
    /// of the fixed drives — skipping folders a firmware would never be saved in:
    /// system/noise directories the user should not write to (Windows, Program Files,
    /// …) and other users' profiles the user cannot write to. A cheap size pre-filter
    /// (against the registry's known sizes) rejects the vast majority of files
    /// instantly; only an exact size match is hashed to confirm it is a genuine
    /// unmodified original.</para>
    ///
    /// <para>Best folder = the one holding the most recent verified original. If
    /// several folders tie on that exact same newest timestamp, the one containing
    /// more unmodified originals wins (the likelier "firmware stash").</para>
    ///
    /// <para>Thread-safe and cancellable: run it on a background thread and cancel
    /// the token once a firmware is chosen or the window closes. It also caps itself
    /// at <see cref="BudgetSeconds"/> seconds so the whole-drive sweep can never run
    /// forever on a huge disk.</para>
    /// </summary>
    public sealed class FirmwareScanner
    {
        /// <summary>Overall wall-clock cap for a scan (whichever comes first: this,
        /// a chosen firmware, or the window closing).</summary>
        private const int BudgetSeconds = 60;

        private readonly object _lock = new();

        /// <summary>Running tally of verified originals per folder.</summary>
        private sealed class FolderStat
        {
            public int Count;
            public DateTime LatestUtc = DateTime.MinValue;
        }

        private readonly Dictionary<string, FolderStat> _folders =
            new(StringComparer.OrdinalIgnoreCase);
        // Paths already counted, so a file can never be tallied twice.
        private readonly HashSet<string> _counted =
            new(StringComparer.OrdinalIgnoreCase);
        private string? _bestFolder;

        /// <summary>
        /// The best folder found so far (newest verified original; ties broken by how
        /// many originals the folder holds), or <c>null</c> until one is located.
        /// Safe to read from any thread.
        /// </summary>
        public string? BestFolder { get { lock (_lock) return _bestFolder; } }

        // Cheap pre-filter: the exact byte sizes of every known original. A .fwz
        // whose size isn't here can't be an unmodified original, so it never hashes.
        private static readonly HashSet<long> KnownSizes =
            FirmwareRegistry.Known.Select(k => k.SizeBytes).ToHashSet();

        // Directory leaf names skipped during the whole-computer sweep — folders the
        // user should NOT be writing files to (so a firmware they saved is never
        // here), and descending them just wastes time (and hits access denials).
        private static readonly HashSet<string> ExcludedDirs =
            new(StringComparer.OrdinalIgnoreCase)
            {
                "Windows", "Program Files", "Program Files (x86)", "ProgramData",
                "AppData", "$Recycle.Bin", "System Volume Information", "Recovery",
                "$WinREAgent", "Config.Msi", "Windows.old",
            };

        // The current user's profile and its parent ("…\Users"), used to skip OTHER
        // users' profiles during the sweep — folders this user cannot write to, so a
        // firmware they saved is never there. "Public" is shared/writable, so keep it.
        private static readonly string CurrentProfile =
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        private static readonly string? UsersRoot =
            Directory.GetParent(CurrentProfile)?.FullName;
        private static readonly HashSet<string> UsersRootKeep =
            new(StringComparer.OrdinalIgnoreCase) { "Public" };

        /// <summary>
        /// True when <paramref name="dir"/> is another user's profile (a direct child
        /// of the Users root that is neither this user's own profile nor the shared
        /// "Public" folder) — a place this user cannot write to.
        /// </summary>
        private static bool IsOtherUserProfile(string dir)
        {
            if (UsersRoot == null) return false;
            string? parent;
            try { parent = Directory.GetParent(dir)?.FullName; }
            catch { return false; }
            if (parent == null ||
                !string.Equals(parent, UsersRoot, StringComparison.OrdinalIgnoreCase))
                return false; // not directly under "…\Users"
            if (string.Equals(dir, CurrentProfile, StringComparison.OrdinalIgnoreCase))
                return false; // our own profile — keep
            return !UsersRootKeep.Contains(Path.GetFileName(dir));
        }

        /// <summary>
        /// Runs the scan to completion (or until <paramref name="ct"/> is cancelled),
        /// updating <see cref="BestFolder"/> as better matches are found. Never throws
        /// for I/O or cancellation — it is meant to be fire-and-forget.
        /// </summary>
        public void Scan(CancellationToken ct)
        {
            // Cap the whole scan at BudgetSeconds so it can't run forever on a large
            // disk. The linked token trips on whichever comes first: the caller's ct
            // (a firmware was chosen / the window closed) or the budget timer.
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
            budget.CancelAfter(TimeSpan.FromSeconds(BudgetSeconds));
            var token = budget.Token;
            try
            {
                // Phase 1 — the folders a firmware download almost always lands in,
                // in order of likelihood. Deduplicated and existing only.
                var priority = PriorityFolders();
                foreach (var folder in priority)
                    ScanTree(folder, _ => true, token);

                // Phase 2 — the whole computer (fixed drives), skipping: the priority
                // folders already covered above; system/noise dirs the user should not
                // write to (ExcludedDirs); and other users' profiles the user cannot
                // write to (IsOtherUserProfile).
                var prioritySet = new HashSet<string>(priority, StringComparer.OrdinalIgnoreCase);
                foreach (var drive in FixedDriveRoots())
                    ScanTree(drive,
                        dir => !prioritySet.Contains(dir)
                            && !ExcludedDirs.Contains(Path.GetFileName(dir))
                            && !IsOtherUserProfile(dir),
                        token);
            }
            catch (OperationCanceledException)
            {
                // A firmware was chosen, the window closed, or the time budget elapsed.
            }
            catch
            {
                // Best-effort locator: an unexpected error (I/O, security, etc.) must
                // never fault the fire-and-forget Task or the app. The picker simply
                // falls back to its default start folder.
            }
        }

        /// <summary>Existing, de-duplicated Downloads → Desktop → Documents folders.</summary>
        private static List<string> PriorityFolders()
        {
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var candidates = new[]
            {
                Path.Combine(profile, "Downloads"), // no SpecialFolder for Downloads
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            };
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new List<string>();
            foreach (var c in candidates)
                if (!string.IsNullOrEmpty(c) && Directory.Exists(c) && seen.Add(c))
                    result.Add(c);
            return result;
        }

        /// <summary>Root paths of all ready, fixed (non-removable/network) drives.</summary>
        private static IEnumerable<string> FixedDriveRoots()
        {
            DriveInfo[] drives;
            try { drives = DriveInfo.GetDrives(); }
            catch { yield break; }
            foreach (var d in drives)
            {
                bool ok;
                try { ok = d.IsReady && d.DriveType == DriveType.Fixed; }
                catch { ok = false; }
                if (ok) yield return d.RootDirectory.FullName;
            }
        }

        /// <summary>
        /// Iterative (stack-based) directory walk that yields *.fwz files, prunes
        /// subtrees via <paramref name="descend"/>, skips reparse points (symlink/
        /// junction cycles), tolerates access errors, and checks cancellation often.
        /// </summary>
        private int _dirsVisited;

        private void ScanTree(string root, Func<string, bool> descend, CancellationToken ct)
        {
            var stack = new Stack<string>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                // Politeness: briefly yield every 64 directories so this background
                // sweep backs off under contention instead of monopolising the disk
                // while the app is in use. Negligible effect on how quickly a good
                // BestFolder becomes available (the priority folders come first).
                if ((++_dirsVisited & 0x3F) == 0) Thread.Sleep(1);
                string dir = stack.Pop();

                string[] files;
                try { files = Directory.GetFiles(dir, "*.fwz"); }
                catch { files = Array.Empty<string>(); } // access denied / gone
                foreach (var f in files)
                    Consider(f, ct);

                string[] subs;
                try { subs = Directory.GetDirectories(dir); }
                catch { subs = Array.Empty<string>(); }
                foreach (var s in subs)
                {
                    if (IsReparsePoint(s) || !descend(s)) continue;
                    stack.Push(s);
                }
            }
        }

        /// <summary>
        /// Considers one .fwz: rejects on size (cheap), then verifies (size + SHA-256)
        /// and, if it is an unmodified original, tallies it against its folder and
        /// recomputes the best folder.
        /// </summary>
        private void Consider(string path, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();

            long size;
            DateTime writeUtc;
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) return;
                size = fi.Length;
                writeUtc = fi.LastWriteTimeUtc;
            }
            catch { return; }

            if (!KnownSizes.Contains(size)) return; // not an original — no hashing

            FirmwareCheckResult res;
            try { res = FirmwareRegistry.Verify(path); }
            catch { return; }
            if (!res.Ok) return;

            string? folder = Path.GetDirectoryName(path);
            if (folder == null) return;

            lock (_lock)
            {
                if (!_counted.Add(path)) return; // already tallied this exact file
                if (!_folders.TryGetValue(folder, out var stat))
                    _folders[folder] = stat = new FolderStat();
                stat.Count++;
                if (writeUtc > stat.LatestUtc) stat.LatestUtc = writeUtc;
                RecomputeBest();
            }
        }

        /// <summary>
        /// Picks the best folder under the lock: newest verified original wins; a tie
        /// on that exact timestamp is broken by the number of originals in the folder.
        /// The folder set is tiny (only folders that actually hold firmware).
        /// </summary>
        private void RecomputeBest()
        {
            string? best = null;
            DateTime bestLatest = DateTime.MinValue;
            int bestCount = 0;
            foreach (var (folder, stat) in _folders)
            {
                if (stat.LatestUtc > bestLatest ||
                    (stat.LatestUtc == bestLatest && stat.Count > bestCount))
                {
                    best = folder;
                    bestLatest = stat.LatestUtc;
                    bestCount = stat.Count;
                }
            }
            _bestFolder = best;
        }

        private static bool IsReparsePoint(string dir)
        {
            try { return (new DirectoryInfo(dir).Attributes & FileAttributes.ReparsePoint) != 0; }
            catch { return true; } // if we can't tell, don't descend
        }
    }
}
