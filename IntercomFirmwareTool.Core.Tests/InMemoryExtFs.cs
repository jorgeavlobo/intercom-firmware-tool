using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using IntercomFirmwareTool.Core;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// An in-memory <see cref="IExtFs"/> for exercising the MQTT installer's image I/O paths
/// (<see cref="MqttInstaller.PatchFactoryFirewallWaitForLock"/> / <see cref="MqttInstaller.CheckFactoryFirewall"/>)
/// WITHOUT the native SharpExt4 <c>ExtFileSystem</c> or an ext4 image fixture — so they run on any CI, not just
/// Windows/x64. It models regular files (bytes + mode + owner), directories, and symlinks, mirroring the real
/// filesystem's key quirks: <see cref="FileExists"/> is symlink-blind, and <see cref="ReadSymLink"/> THROWS when
/// the path is not a symlink (the installer relies on that throw to tell "not a symlink" from a real target).
/// </summary>
internal sealed class InMemoryExtFs : IExtFs
{
    // Octal file modes as the low 12 bits GetMode returns (type bits live above 0xFFF and don't affect the
    // installer, which only masks perms/execute bits).
    internal const uint Mode0644 = 0x1A4;   // rw-r--r--
    internal const uint Mode0755 = 0x1ED;   // rwxr-xr-x
    internal const uint Mode0777 = 0x1FF;   // rwxrwxrwx
    private const uint SIfReg = 0x8000, SIfDir = 0x4000, SIfLnk = 0xA000;

    private sealed class Entry
    {
        public byte[] Bytes = Array.Empty<byte>();
        public uint Mode;   // full mode: type bits | permission bits
        public uint Uid;
        public uint Gid;
    }

    private readonly Dictionary<string, Entry> _files = new(StringComparer.Ordinal);
    private readonly HashSet<string> _dirs = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _symlinks = new(StringComparer.Ordinal);

    // ---- test seeding / inspection ----

    public InMemoryExtFs AddFile(string path, string text, uint mode = Mode0644, uint uid = 0, uint gid = 0) =>
        AddFile(path, Encoding.UTF8.GetBytes(text), mode, uid, gid);

    public InMemoryExtFs AddFile(string path, byte[] bytes, uint mode = Mode0644, uint uid = 0, uint gid = 0)
    {
        _files[path] = new Entry { Bytes = bytes, Mode = SIfReg | (mode & 0xFFF), Uid = uid, Gid = gid };
        return this;
    }

    /// <summary>A minimal executable regular file (mode 0755) standing in for an interpreter binary. The
    /// content is never parsed by the installer — only existence + the execute bit matter.</summary>
    public InMemoryExtFs AddExecutable(string path) => AddFile(path, "exe", Mode0755);

    public InMemoryExtFs AddDir(string path) { _dirs.Add(path); return this; }
    public InMemoryExtFs AddSymlink(string path, string target) { _symlinks[path] = target; return this; }

    public bool HasFile(string path) => _files.ContainsKey(path);
    public string? ReadText(string path) =>
        _files.TryGetValue(path, out var e) ? Encoding.UTF8.GetString(e.Bytes) : null;
    public uint ModeOf(string path) => _files.TryGetValue(path, out var e) ? (e.Mode & 0xFFF) : 0;
    public (uint uid, uint gid)? OwnerOf(string path) =>
        _files.TryGetValue(path, out var e) ? (e.Uid, e.Gid) : null;

    // ---- IExtFs ----

    public bool FileExists(string path) => _files.ContainsKey(path);          // regular files only (symlink-blind)
    public bool DirectoryExists(string path) => _dirs.Contains(path);

    public uint GetMode(string path)
    {
        if (_files.TryGetValue(path, out var e)) return e.Mode;
        if (_symlinks.ContainsKey(path)) return SIfLnk | Mode0777;
        if (_dirs.Contains(path)) return SIfDir | Mode0755;
        throw new FileNotFoundException(path);
    }

    public void SetMode(string path, uint mode)
    {
        if (_files.TryGetValue(path, out var e)) e.Mode = (e.Mode & ~0xFFFu) | (mode & 0xFFF);
    }

    public Tuple<uint, uint>? GetOwner(string path) =>
        _files.TryGetValue(path, out var e) ? Tuple.Create(e.Uid, e.Gid) : null;

    public void SetOwner(string path, uint uid, uint gid)
    {
        if (_files.TryGetValue(path, out var e)) { e.Uid = uid; e.Gid = gid; }
    }

    public string ReadSymLink(string path) =>
        _symlinks.TryGetValue(path, out var target)
            ? target
            : throw new IOException($"not a symlink: {path}");   // matches ExtFileSystem: throws when not a link

    public void CreateSymLink(string linkTarget, string linkPath) => _symlinks[linkPath] = linkTarget;
    public void CreateDirectory(string path) => _dirs.Add(path);

    public Stream OpenFile(string path, FileMode mode, FileAccess access)
    {
        if (mode == FileMode.Open)
        {
            if (!_files.TryGetValue(path, out var e)) throw new FileNotFoundException(path);
            return new MemoryStream(e.Bytes, writable: false);
        }
        // FileMode.Create — truncate/replace AND DROP the mode/owner back to a fresh-file default (mode 0644,
        // root-owned). This models a raw write that does not itself preserve metadata — which is exactly why
        // RewritePreservingMeta captures mode/owner beforehand and re-applies them afterwards. Resetting here
        // makes the "mode/owner preserved" assertions meaningful: if the installer ever stopped restoring, the
        // rewritten file would be left at these defaults and the tests would catch it.
        if (!_files.TryGetValue(path, out var ent))
        {
            ent = new Entry();
            _files[path] = ent;
        }
        ent.Mode = SIfReg | Mode0644;
        ent.Uid = 0;
        ent.Gid = 0;
        ent.Bytes = Array.Empty<byte>();
        return new WriteBackStream(bytes => ent.Bytes = bytes);
    }

    public void RenameFile(string sourcePath, string destPath)
    {
        if (!_files.TryGetValue(sourcePath, out var e)) throw new FileNotFoundException(sourcePath);
        // ExtFileSystem.RenameFile (lwext4 ext4_frename) refuses to overwrite an existing destination OF ANY
        // KIND — regular file, directory, or symlink — so model all three, not just the regular-file map. A
        // fake that only rejected a colliding regular file could let a test pass where the real image throws.
        if (_files.ContainsKey(destPath) || _dirs.Contains(destPath) || _symlinks.ContainsKey(destPath))
            throw new IOException($"'{destPath}' already exists.");
        _files.Remove(sourcePath);
        _files[destPath] = e;   // move the whole entry: bytes, mode and owner travel with the inode
    }

    public void DeleteFile(string path)
    {
        if (!_files.Remove(path)) throw new FileNotFoundException(path);
    }

    /// <summary>A writable stream that flushes its bytes back into the owning entry when disposed — models
    /// SharpExt4's ExtFileStream, which persists into the image on close.</summary>
    private sealed class WriteBackStream : MemoryStream
    {
        private readonly Action<byte[]> _onClose;
        private bool _flushed;
        public WriteBackStream(Action<byte[]> onClose) => _onClose = onClose;
        protected override void Dispose(bool disposing)
        {
            if (!_flushed) { _flushed = true; _onClose(ToArray()); }
            base.Dispose(disposing);
        }
    }
}

/// <summary>
/// An <see cref="IExtFs"/> decorator that forwards everything to an inner filesystem but can THROW from
/// <see cref="OpenFile"/> (on a create-write) and/or <see cref="RenameFile"/> when the target matches an
/// injected predicate — used to fault-inject the safe-replace (issue #151) and prove it never damages the
/// original file: a mid-write failure leaves the original intact, and a failed swap rolls it back.
/// </summary>
internal sealed class FaultyExtFs : IExtFs
{
    private readonly IExtFs _inner;
    private readonly Func<string, bool>? _failCreate;
    private readonly Func<string, string, bool>? _failRename;

    public FaultyExtFs(IExtFs inner,
                       Func<string, bool>? failCreate = null,
                       Func<string, string, bool>? failRename = null)
    {
        _inner = inner;
        _failCreate = failCreate;
        _failRename = failRename;
    }

    public Stream OpenFile(string path, FileMode mode, FileAccess access)
    {
        if (mode == FileMode.Create && _failCreate?.Invoke(path) == true)
            throw new IOException($"injected write failure for {path}");
        return _inner.OpenFile(path, mode, access);
    }

    public void RenameFile(string sourcePath, string destPath)
    {
        if (_failRename?.Invoke(sourcePath, destPath) == true)
            throw new IOException($"injected rename failure for {sourcePath} -> {destPath}");
        _inner.RenameFile(sourcePath, destPath);
    }

    public bool FileExists(string path) => _inner.FileExists(path);
    public bool DirectoryExists(string path) => _inner.DirectoryExists(path);
    public uint GetMode(string path) => _inner.GetMode(path);
    public void SetMode(string path, uint mode) => _inner.SetMode(path, mode);
    public Tuple<uint, uint>? GetOwner(string path) => _inner.GetOwner(path);
    public void SetOwner(string path, uint uid, uint gid) => _inner.SetOwner(path, uid, gid);
    public string ReadSymLink(string path) => _inner.ReadSymLink(path);
    public void CreateSymLink(string linkTarget, string linkPath) => _inner.CreateSymLink(linkTarget, linkPath);
    public void CreateDirectory(string path) => _inner.CreateDirectory(path);
    public void DeleteFile(string path) => _inner.DeleteFile(path);
}
