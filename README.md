# IntercomFirmwareTool

## Releases

Windows x64 builds are published on the [Releases page](../../releases). Each release `vX.Y.Z` includes:

- **`IntercomFirmwareTool-vX.Y.Z-win-x64-portable.exe`** — **portable** self-contained single-file executable; runs on a clean Windows x64 machine with **no .NET installed** (the required Visual C++ runtime that the disk-image library depends on is bundled app-local, so no VC++ Redistributable is needed either). This is the one most people want.
- **`IntercomFirmwareTool-vX.Y.Z-win-x64-portable.zip`** — the exact same portable `.exe`, just zipped — for browsers or antivirus that block a raw `.exe` download. Unzip and run.
- **`IntercomFirmwareTool-vX.Y.Z-win-x64.zip`** — the same app as a **loose set of files** (executable + its DLLs), if you prefer an archive or if antivirus flags the single-file's first-run temp-extraction. Extract the archive into a folder of its own, then run the `.exe` alongside the extracted DLLs.
- **`*.sha256`** — SHA-256 checksums, one per **build** asset (the `.exe`/`.zip` files above). The licensing/notice documents below ship without checksum sidecars.
- **`THIRD-PARTY-NOTICES.md`, `LICENSE.txt`, `SharpExt4-LICENSE.txt`, `lwext4-LICENSE.txt`, `lwext4-BSD-3-Clause-NOTICE.txt`, `DiskPartitionInfo-LICENSE.txt`, `dotnet-runtime-LICENSE.txt`, `btmqttd-THIRD-PARTY-LICENSES.txt`, `ffmpeg-COPYING.LGPLv2.1.txt`, `musl-COPYRIGHT.txt`** — licensing and third-party notices for the bundled native components (the last three cover the embedded ARM binaries — `btmqttd` and the LGPL `ffmpeg`, which statically link musl). The disk-image library (`SharpExt4.dll`) statically embeds the **GPL-2.0** `lwext4`, so the compiled binary's applicable terms include the GNU GPL v2; these files carry the required license texts and notices. They travel **inside both `.zip` archives** (portable and loose-folder) — `THIRD-PARTY-NOTICES.md` and `LICENSE.txt` at the archive root beside the executable, the license texts under a `licenses/` subdirectory; the single-file `.exe` is accompanied by them as assets on the same release. The GPL-2.0 corresponding source for `SharpExt4.dll` (wrapper + vendored `lwext4` + build scripts) is pinned + mirrored in [`third_party/SharpExt4/`](third_party/SharpExt4) and shipped as the release asset **`SharpExt4-a9a41e1.zip`** (SHA-256 `17deba26c1dfaf04007ffa7bf337617ab9337ba1f25e8025d83d89eb57777d37`; it ships without a `.sha256` sidecar — verify against this pinned value or the copy in `third_party/SharpExt4/`). `SharpExt4`'s own upstream license is now **resolved** — it is **MIT** (© 2021-2026 nickdu088), so the source is pinned to that licensed commit; the compiled DLL remains a GPL-2.0 combined work through the linked `lwext4` — see [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) and [`CLEANROOM.md`](CLEANROOM.md) for the full position.

**Verify your download** (PowerShell) — compares the file's hash against its published `.sha256` and prints `True` if they match (works for any of the `.exe`/`.zip` build assets — point `$file` at the one you downloaded):

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
> - **Antivirus false positive** — Defender may flag the single-file `-portable.exe` as a threat (e.g. a `…!ml` heuristic detection like `Wacatac`/`Wacapew`). This is a **common false positive** for unsigned, self-extracting .NET single-file executables. Before dismissing the alert, verify the **SLSA provenance attestation** above (`gh attestation verify`) — that, not the antivirus label, is what proves the file was built by this repository's CI. (The checksum only confirms the download matches the release page, which is integrity, not origin; the attestation confirms origin and can't be forged by swapping the release's files.) The build ships **uncompressed** to reduce the flag; if it still trips, use the **`…-win-x64.zip`** (loose-folder) download instead — it's the same app as loose files rather than a self-extracting single-file bundle, so it's far less likely to trip this heuristic (it has run clean in testing).

**Cutting a release** (maintainer): push a `vX.Y.Z` tag, or run the **release** workflow from the Actions tab with a version. Either produces a **draft** Release with the assets attached — review it, then click **Publish**. The `vX.Y.Z` tag is anchored to the built commit during the release run (the manual dispatch creates it in the draft-release step, after build + attestation, never deferred to publish). If you discard a dispatch draft instead of publishing, its `vX.Y.Z` tag remains behind — with the ruleset below active, removing it is a deliberate out-of-band action (temporarily relax the ruleset, or just bump the version); see the note.

> **Required prerequisite — tag-protection ruleset.** The build-time tag anchoring guarantees the artifact, its attestation, and the tag describe the same commit *only* while a repo **ruleset** on `refs/tags/v*` keeps that tag immutable. Create one (Settings → Rules → Rulesets → New tag ruleset) that **restricts tag updates and deletions** for `v*`, with **no bypass actor** that could move a release tag (leave tag *creation* allowed so the release workflow can anchor the tag). The atomic tag creation in the workflow prevents a *conflicting* tag; only this ruleset prevents an existing release tag from being force-*moved* between build and publish. Without it, a collaborator with tag-update permission could rebind a `vX.Y.Z` tag to a different commit than its published assets. (Because the ruleset blocks deletions, the workflow's best-effort rollback of a *failed* dispatch cannot remove the tag it anchored — delete such a leftover tag out-of-band, or bump the version.)

## Automatic update check (optional)

On startup the app quietly checks whether a newer release is available and, if so, shows a small **"a newer version is available"** banner with a **Download** button that opens this repository's [Releases page](../../releases). It **never downloads or runs anything itself** — you download and verify the new build exactly as above. The banner is dismissible ("Remind me later" nags once per version); the rest of the app stays fully usable.

It is deliberately unobtrusive and **fails open**: the check is asynchronous and time-boxed, and no internet, a timeout, a rate-limit, a malformed response, or opting out simply means **no banner** — the app never blocks or waits on it, and works fully offline. Development builds (version `0.0.0`) never nag.

The one case that disables actions is a **maintainer-flagged unsafe version**: if the running build is older than a `minimumSupportedVersion` the maintainer has published (e.g. to retire a build with a serious bug), a red banner asks you to update and the firmware actions are disabled — but you can always still read the message, switch language, open **⚙️ → About**, and quit. This only ever triggers on that explicit, sanity-checked signal, never by accident.

**Privacy / opt-out.** The check makes one HTTPS request to GitHub (`raw.githubusercontent.com`), which sees your IP address and an app-identifying `User-Agent` (`IntercomFirmwareTool-UpdateCheck`). It sends no personal data and downloads nothing. To turn it off entirely, open the **⚙️ settings menu** (top-right) and untick **"Check for updates on startup"** — the choice is remembered, and with it off the app makes no network call for updates. The same menu has **"Check for updates now…"** for an on-demand check and **About** (which shows the running version).

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
