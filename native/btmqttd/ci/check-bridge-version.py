#!/usr/bin/env python3
"""Verify the bridge daemon's SemVer is in sync between its two sources (issue #114).

``native/btmqttd/Cargo.toml``'s ``[package] version`` is the single source of truth
— the daemon compiles it in as ``CARGO_PKG_VERSION``. The C# installer mirrors it in
``PayloadBinaries.BridgeVersion`` so it can bake ``sw_version`` into the Home Assistant
discovery ``device`` block WITHOUT reading the binary. If the two drift, HA advertises a
version the running daemon isn't.

Extraction is SYNTAX-AWARE so a stale literal sitting in a comment or a string can never
be picked up and mask a real mismatch (the failure mode of a naive line grep):

  * Cargo.toml is parsed with :mod:`tomllib`, so a ``version = "…"`` line inside a
    multiline string (e.g. a ``description = \"\"\"…\"\"\"``) is never mistaken for the
    package version.
  * PayloadBinaries.cs has its ``//`` and ``/* … */`` comments removed — while string
    and char literals are preserved, so a ``//`` inside a URL string is not mistaken for
    a comment — before the ``public const string BridgeVersion = "…";`` declaration is
    matched.

Usage:
  check-bridge-version.py <Cargo.toml> <PayloadBinaries.cs>   # compare; exit 1 on drift
  check-bridge-version.py --selftest                          # run regression fixtures
"""
from __future__ import annotations

import re
import sys
import tomllib

# One declaration form only: `public const string BridgeVersion = "…";`.
_DECL = re.compile(r'\bpublic\s+const\s+string\s+BridgeVersion\s*=\s*"([^"]*)"\s*;')

# Alternation that matches, in priority order, a C# verbatim string, a regular string, a
# char literal, a line comment, or a block comment. Matching strings/chars FIRST means a
# `//` or `/*` occurring inside a literal is consumed as part of that literal (and kept),
# so only genuine comments are stripped. (Standard comment-stripping technique.)
_CS_TOKENS = re.compile(
    r'''
      @"(?:[^"]|"")*"          # verbatim string  @"…"  ("" is an escaped quote)
    | "(?:\\.|[^"\\])*"        # regular string   "…"
    | '(?:\\.|[^'\\])*'        # char literal     '…'
    | //[^\n]*                 # line comment
    | /\*.*?\*/                # block comment
    ''',
    re.DOTALL | re.VERBOSE,
)


def cargo_version(toml_text: str) -> str | None:
    """The ``[package] version`` from Cargo.toml text, or None if absent/malformed."""
    try:
        data = tomllib.loads(toml_text)
    except tomllib.TOMLDecodeError:
        return None
    pkg = data.get("package")
    if not isinstance(pkg, dict):
        return None
    version = pkg.get("version")
    return version if isinstance(version, str) else None


def _strip_cs_comments(src: str) -> str:
    def repl(match: re.Match[str]) -> str:
        token = match.group(0)
        # Drop comments; keep string/char literals verbatim.
        return " " if token.startswith("//") or token.startswith("/*") else token

    return _CS_TOKENS.sub(repl, src)


def cs_version(cs_text: str) -> str | None:
    """The ``BridgeVersion`` constant value, ignoring comments, or None if not found."""
    match = _DECL.search(_strip_cs_comments(cs_text))
    return match.group(1) if match else None


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _selftest() -> int:
    # Regression fixtures for the exact false-match vectors a naive line grep accepts: a
    # stale `version` inside a TOML multiline string, and a stale declaration inside a C#
    # block comment. The real value must win in both.
    toml_fixture = (
        '[package]\n'
        'name = "fixture"\n'
        'description = """\n'
        'version = "0.1.0"\n'
        '"""\n'
        'version = "9.9.9"\n'
    )
    cs_fixture = (
        "/*\n"
        '    public const string BridgeVersion = "0.1.0";\n'
        "*/\n"
        "// public const string BridgeVersion = \"7.7.7\";\n"
        '        public const string BridgeVersion = "9.9.9";\n'
    )
    # A URL in a string literal must NOT be treated as a comment (would corrupt parsing).
    cs_url_fixture = (
        '        public const string Docs = "https://example.test/path";\n'
        '        public const string BridgeVersion = "1.2.3";\n'
    )
    cases = [
        ("cargo/ multiline-string", cargo_version(toml_fixture), "9.9.9"),
        ("cs/ block+line comment", cs_version(cs_fixture), "9.9.9"),
        ("cs/ url-in-string", cs_version(cs_url_fixture), "1.2.3"),
    ]
    ok = True
    for name, got, want in cases:
        status = "OK" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{status}] {name}: got {got!r}, want {want!r}")
    if not ok:
        print("::error::bridge-version extractor self-test FAILED", file=sys.stderr)
        return 1
    print("bridge-version extractor self-test passed")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return _selftest()
    if len(argv) != 2:
        print(
            "usage: check-bridge-version.py <Cargo.toml> <PayloadBinaries.cs>\n"
            "       check-bridge-version.py --selftest",
            file=sys.stderr,
        )
        return 2

    cargo_ver = cargo_version(_read(argv[0]))
    cs_ver = cs_version(_read(argv[1]))
    print(f"Cargo.toml [package] version:  {cargo_ver!r}")
    print(f"PayloadBinaries.BridgeVersion: {cs_ver!r}")

    if not cargo_ver or not cs_ver:
        print(
            "::error::could not read the bridge version from Cargo.toml and/or "
            "PayloadBinaries.cs",
            file=sys.stderr,
        )
        return 1
    if cargo_ver != cs_ver:
        print(
            f"::error::bridge version drift — native/btmqttd/Cargo.toml is "
            f"'{cargo_ver}' but PayloadBinaries.BridgeVersion is '{cs_ver}'. "
            f"Bump BOTH together.",
            file=sys.stderr,
        )
        return 1
    print(f"bridge version in sync: {cargo_ver}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
