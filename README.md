# IntercomFirmwareTool

## Releases

Windows x64 builds are published on the [Releases page](../../releases). Each release `vX.Y.Z` includes:

- **`IntercomFirmwareTool-vX.Y.Z-win-x64-portable.exe`** — **portable** self-contained single-file executable; runs on a clean Windows x64 machine with **no .NET installed** (the required Visual C++ runtime that the disk-image library depends on is bundled app-local, so no VC++ Redistributable is needed either). This is the one most people want.
- **`IntercomFirmwareTool-vX.Y.Z-win-x64-portable.zip`** — the exact same portable `.exe`, just zipped — for browsers or antivirus that block a raw `.exe` download. Unzip and run.
- **`IntercomFirmwareTool-vX.Y.Z-win-x64.zip`** — the same app as a **loose set of files** (executable + its DLLs), if you prefer an archive or if antivirus flags the single-file's first-run temp-extraction. Extract the archive into a folder of its own, then run the `.exe` alongside the extracted DLLs.
- **`*.sha256`** — SHA-256 checksums, one per asset.

**Verify your download** (PowerShell) — compares the file's hash against its published `.sha256` and prints `True` if they match (works for any of the assets — point `$file` at the one you downloaded):

```powershell
$file = ".\IntercomFirmwareTool-vX.Y.Z-win-x64-portable.exe"
$expected = ((Get-Content "$file.sha256" -Raw) -split '\s+')[0]
(Get-FileHash $file -Algorithm SHA256).Hash -ieq $expected
```

Each release also carries a **SLSA build-provenance attestation** — confirm it was built by this repository's CI:

```bash
gh attestation verify IntercomFirmwareTool-vX.Y.Z-win-x64-portable.exe --repo jorgeavlobo/intercom-firmware-tool
```

> **Note — unsigned build:** the `.exe` is not yet code-signed (tracked in issue #84), so on a first run Windows may push back in two ways. Verify the checksum/attestation above first, then:
>
> - **SmartScreen** — *"Windows protected your PC"*: click **More info → Run anyway**.
> - **Antivirus false positive** — Defender may flag the single-file `-portable.exe` as a threat (e.g. a `…!ml` heuristic detection like `Wacatac`/`Wacapew`). This is a **known false positive** for unsigned, self-extracting .NET single-file executables — not an actual infection. The build already ships **uncompressed** to minimise it. If it still trips: use the **`…-win-x64.zip`** (loose-folder) download instead — it is the same app without the single-file packaging and is not flagged.

**Cutting a release** (maintainer): push a `vX.Y.Z` tag, or run the **release** workflow from the Actions tab with a version. Either produces a **draft** Release with the assets attached — review it, then click **Publish**. The `vX.Y.Z` tag is anchored to the built commit during the release run (the manual dispatch creates it in the draft-release step, after build + attestation, never deferred to publish). If you discard a dispatch draft instead of publishing, its `vX.Y.Z` tag remains behind — with the ruleset below active, removing it is a deliberate out-of-band action (temporarily relax the ruleset, or just bump the version); see the note.

> **Required prerequisite — tag-protection ruleset.** The build-time tag anchoring guarantees the artifact, its attestation, and the tag describe the same commit *only* while a repo **ruleset** on `refs/tags/v*` keeps that tag immutable. Create one (Settings → Rules → Rulesets → New tag ruleset) that **restricts tag updates and deletions** for `v*`, with **no bypass actor** that could move a release tag (leave tag *creation* allowed so the release workflow can anchor the tag). The atomic tag creation in the workflow prevents a *conflicting* tag; only this ruleset prevents an existing release tag from being force-*moved* between build and publish. Without it, a collaborator with tag-update permission could rebind a `vX.Y.Z` tag to a different commit than its published assets. (Because the ruleset blocks deletions, the workflow's best-effort rollback of a *failed* dispatch cannot remove the tag it anchored — delete such a leftover tag out-of-band, or bump the version.)

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
