using System;
using System.IO;
using SharpExt4;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// The narrow slice of ext-filesystem operations the MQTT installer/validator needs, behind an interface
    /// so the install and validation LOGIC (which fs calls, in which order, with which guards) can be exercised
    /// by an in-memory fake in unit tests — no native <see cref="ExtFileSystem"/> (SharpExt4, x64/Windows-only)
    /// and no ext4 image fixture. Production wraps the real filesystem in <see cref="ExtFsAdapter"/>; tests
    /// supply their own implementation. Every method mirrors the same-named <see cref="ExtFileSystem"/> member.
    /// </summary>
    internal interface IExtFs
    {
        /// <summary>True iff <paramref name="path"/> exists as a REGULAR file. Symlink-blind, exactly like
        /// <see cref="ExtFileSystem.FileExists"/> (a symlink at the path reads false).</summary>
        bool FileExists(string path);

        /// <summary>True iff <paramref name="path"/> exists as a directory.</summary>
        bool DirectoryExists(string path);

        /// <summary>The raw Unix mode bits (type + permission), as <see cref="ExtFileSystem.GetMode"/> returns.</summary>
        uint GetMode(string path);

        /// <summary>Sets the Unix mode bits on <paramref name="path"/>.</summary>
        void SetMode(string path, uint mode);

        /// <summary><c>(uid, gid)</c> owner of <paramref name="path"/>, or null if unavailable.</summary>
        Tuple<uint, uint>? GetOwner(string path);

        /// <summary>Sets the owner uid/gid on <paramref name="path"/>.</summary>
        void SetOwner(string path, uint uid, uint gid);

        /// <summary>The target of the symlink at <paramref name="path"/>. THROWS if it is not a symlink (or is
        /// absent), matching <see cref="ExtFileSystem.ReadSymLink"/> — callers rely on the throw to distinguish
        /// "not a symlink" from a real target.</summary>
        string ReadSymLink(string path);

        /// <summary>Creates a symlink at <paramref name="linkPath"/> pointing at <paramref name="linkTarget"/>.</summary>
        void CreateSymLink(string linkTarget, string linkPath);

        /// <summary>Creates a directory at <paramref name="path"/>.</summary>
        void CreateDirectory(string path);

        /// <summary>Opens <paramref name="path"/> as a stream. The returned stream is disposed by the caller.</summary>
        Stream OpenFile(string path, FileMode mode, FileAccess access);

        /// <summary>Renames <paramref name="sourcePath"/> to <paramref name="destPath"/>. Mirrors
        /// <see cref="ExtFileSystem.RenameFile"/>, which maps to lwext4's <c>ext4_frename</c> and THROWS if
        /// <paramref name="destPath"/> already exists (it will not overwrite) — so a replace-in-place must delete
        /// the destination first.</summary>
        void RenameFile(string sourcePath, string destPath);

        /// <summary>Deletes the regular file at <paramref name="path"/>, mirroring
        /// <see cref="ExtFileSystem.DeleteFile"/>.</summary>
        void DeleteFile(string path);
    }

    /// <summary>
    /// Production <see cref="IExtFs"/> that forwards to a real SharpExt4 <see cref="ExtFileSystem"/>. Pure
    /// delegation — every member is a one-liner to the same-named <see cref="ExtFileSystem"/> method — so the
    /// installer's behavior is identical to calling the filesystem directly; the seam exists only for testing.
    /// </summary>
    internal sealed class ExtFsAdapter : IExtFs
    {
        private readonly ExtFileSystem _fs;

        internal ExtFsAdapter(ExtFileSystem fs) => _fs = fs;

        public bool FileExists(string path) => _fs.FileExists(path);
        public bool DirectoryExists(string path) => _fs.DirectoryExists(path);
        public uint GetMode(string path) => _fs.GetMode(path);
        public void SetMode(string path, uint mode) => _fs.SetMode(path, mode);
        public Tuple<uint, uint>? GetOwner(string path) => _fs.GetOwner(path);
        public void SetOwner(string path, uint uid, uint gid) => _fs.SetOwner(path, uid, gid);
        public string ReadSymLink(string path) => _fs.ReadSymLink(path);
        public void CreateSymLink(string linkTarget, string linkPath) => _fs.CreateSymLink(linkTarget, linkPath);
        public void CreateDirectory(string path) => _fs.CreateDirectory(path);
        public Stream OpenFile(string path, FileMode mode, FileAccess access) => _fs.OpenFile(path, mode, access);
        public void RenameFile(string sourcePath, string destPath) => _fs.RenameFile(sourcePath, destPath);
        public void DeleteFile(string path) => _fs.DeleteFile(path);
    }
}
