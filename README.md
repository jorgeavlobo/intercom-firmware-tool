# IntercomFirmwareTool

## Releases

Windows x64 builds are published on the [Releases page](../../releases). Each release `vX.Y.Z` includes:

- **`IntercomFirmwareTool-vX.Y.Z-win-x64.exe`** — self-contained single-file executable; runs on a clean Windows x64 machine with **no .NET installed**.
- **`IntercomFirmwareTool-vX.Y.Z-win-x64.zip`** — the same self-contained build as a folder, if you prefer an archive (or if antivirus flags the single-file's first-run temp-extraction).
- **`*.sha256`** — SHA-256 checksums for each asset.

**Verify your download** (PowerShell) — compare against the matching `.sha256`:

```powershell
Get-FileHash .\IntercomFirmwareTool-vX.Y.Z-win-x64.exe -Algorithm SHA256
```

Each release also carries a **SLSA build-provenance attestation** — confirm it was built by this repository's CI:

```bash
gh attestation verify IntercomFirmwareTool-vX.Y.Z-win-x64.exe --repo jorgeavlobo/intercom-firmware-tool
```

> **Note:** the `.exe` is not yet code-signed, so Windows SmartScreen may show *"Windows protected your PC"* on first run — click **More info → Run anyway**. Verify the checksum/attestation above first. (Code signing is tracked in issue #84.)

**Cutting a release** (maintainer): push a `vX.Y.Z` tag, or run the **release** workflow from the Actions tab with a version. Either produces a **draft** Release with the assets attached — review it, then click **Publish**. The `vX.Y.Z` tag is anchored to the built commit at build time (the manual dispatch creates it before the draft), so the artifact, its attestation, and the tag can never describe different commits; if you discard a dispatch draft instead of publishing, delete the matching tag too. A repo **tag-protection ruleset** on `v*` (so release tags can't be moved or deleted outside this process) is the recommended companion control.

## Download official firmware (optional)

The tool can fetch the original, unmodified firmware straight from the official
BTicino / Legrand download servers, so you do not have to hunt for it by hand.

When the app starts it quietly probes the official download links for the
supported Door Entry models and shows a **Download official firmware** panel
listing the files that are currently online (and, when the server reports a
size, only those whose size matches — a server that omits the length is still
listed, since the download itself is verified anyway). Pick a model and version,
choose a destination folder, and the tool downloads the file (fast, multipart
where the server supports it) and then **verifies it byte-for-byte** — size plus
SHA-256 — against the known-good original before it is ever used. That
download-time check is the real integrity gate; a file that fails it is
discarded.

This is a convenience only: it downloads the **same** publicly available file
you could download yourself from BTicino / Legrand. The tool does not host,
redistribute, or modify the original firmware — it simply retrieves it for you
and checks its integrity. Downloading is entirely optional; you can always pick
a firmware file you already have on disk instead.
