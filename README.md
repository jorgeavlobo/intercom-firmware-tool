# IntercomFirmwareTool

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
