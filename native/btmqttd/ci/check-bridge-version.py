#!/usr/bin/env python3
"""Verify the bridge daemon's SemVer is in sync across its sources (issue #114).

``native/btmqttd/Cargo.toml``'s ``[package] version`` is the single source of truth
— the daemon compiles it in as ``CARGO_PKG_VERSION``. Two other files must MIRROR it:

  * ``PayloadBinaries.BridgeVersion`` (C#) — so the installer can bake ``sw_version`` into
    the Home Assistant discovery ``device`` block WITHOUT reading the binary.
``.well-known/bridge.json``'s ``latestVersion`` is the update-check manifest the panel fetches,
but it is RELEASE-DRIVEN (bumped by ``update-manifest.yml`` on release publish, mirroring
``updates.json``) and so legitimately LAGS ``master`` between releases — CI does NOT enforce it
equal to ``Cargo.toml`` (see ``.well-known/bridge.json`` and issue #115). The optional third
argument below can still compare it (handy for a local release-time sanity check), but the
provenance workflow calls this with only the two source-of-truth files.

If Cargo.toml and PayloadBinaries drift, HA would show a version the running daemon isn't.

Extraction is SYNTAX-AWARE so a stale literal sitting in a comment or a string can never
be picked up and mask a real mismatch (the failure mode of a naive line grep):

  * Cargo.toml is parsed with :mod:`tomllib`, so a ``version = "…"`` line inside a
    multiline string (e.g. a ``description = \"\"\"…\"\"\"``) is never mistaken for the
    package version.
  * PayloadBinaries.cs has its comments and the string forms that can carry UNESCAPED
    text removed — ``//`` and ``/* ... */`` comments, raw strings (\"\"\"...\"\"\") and
    verbatim strings (@\"...\") — while regular \"...\" strings and char literals are
    preserved (their inner quotes are escaped, so no decoy declaration forms there, and a
    ``//`` inside a URL string is not mistaken for a comment). It then requires EXACTLY ONE
    surviving ``public const string BridgeVersion = "..."`` declaration, refusing to guess
    when more than one is left (e.g. a decoy in an inactive ``#if`` region).

Usage:
  check-bridge-version.py <Cargo.toml> <PayloadBinaries.cs> [bridge.json]  # compare; exit 1 on drift
  check-bridge-version.py --selftest                                       # run regression fixtures
"""
from __future__ import annotations

import json
import re
import sys
import tomllib

# One declaration form only: `public const string BridgeVersion = "…";`.
_DECL = re.compile(r'\bpublic\s+const\s+string\s+BridgeVersion\s*=\s*"([^"]*)"\s*;')

# Alternation that matches, in priority order, a C# raw string, a verbatim string, a
# regular string, a char literal, a line comment, or a block comment. Matching literals
# and comments as whole tokens (raw string FIRST, so `"""…"""` is not mis-split into
# `""` + `"…"`) means a `//`, `/*`, or a decoy declaration occurring INSIDE any literal is
# consumed as part of that literal, never treated as code. `_strip_cs_comments` then drops
# comments and the string forms that can carry UNESCAPED text (raw `"""…"""` and verbatim
# `@"…"`), while keeping regular `"…"` strings — whose inner quotes must be escaped `\"`,
# so a decoy `= "…";` can't form there, and where the real constant's value lives.
_CS_TOKENS = re.compile(
    r'''
      ("{3,})(?s:.*?)\1        # raw string literal   """…"""  (C# 11+, N-quote delimited)
    | @"(?:[^"]|"")*"          # verbatim string      @"…"     ("" is an escaped quote)
    | "(?:\\.|[^"\\])*"        # regular string       "…"
    | '(?:\\.|[^'\\])*'        # char literal         '…'
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


def manifest_version(json_text: str) -> str | None:
    """The ``latestVersion`` string from the bridge.json manifest, or None if absent/malformed."""
    try:
        data = json.loads(json_text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    version = data.get("latestVersion")
    return version if isinstance(version, str) else None


def _strip_cs_comments(src: str) -> str:
    def repl(match: re.Match[str]) -> str:
        token = match.group(0)
        # Drop comments and the string forms that can carry UNESCAPED text (a raw string
        # `"""…"""` or a verbatim string `@"…"`), so a decoy declaration hidden in one of
        # them is removed. Keep regular `"…"` strings and char literals: their inner quotes
        # are escaped (`\"`), so a decoy `= "…";` can't form there, and the real constant's
        # value is a regular string that must survive for the match.
        if token.startswith(("//", "/*", '"""', '@"')):
            return " "
        return token

    return _CS_TOKENS.sub(repl, src)


def cs_declarations(cs_text: str) -> list[str]:
    """Every ``BridgeVersion`` declaration value in the (comment/raw/verbatim-stripped) text."""
    return _DECL.findall(_strip_cs_comments(cs_text))


def cs_version(cs_text: str) -> str | None:
    """The BridgeVersion value IFF there is exactly one declaration, else None.

    Returning None for >1 match is deliberate: rather than model every C# construct that
    could hide a decoy the stripper doesn't remove (an inactive ``#if false`` region, some
    future literal form), we refuse to guess when more than one declaration survives — the
    real file has exactly one, so any extra means "stop and look", not "silently pick the
    first". The caller turns 0 or >1 into a fatal, explained error.
    """
    found = cs_declarations(cs_text)
    return found[0] if len(found) == 1 else None


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
    # A decoy declaration inside a C# 11 raw string literal must not be picked up.
    cs_raw_fixture = (
        '        string doc = """\n'
        '            public const string BridgeVersion = "0.1.0";\n'
        '            """;\n'
        '        public const string BridgeVersion = "9.9.9";\n'
    )
    # A decoy declaration inside a verbatim string ("" escapes a quote) must not either.
    cs_verbatim_fixture = (
        '        string doc = @"public const string BridgeVersion = ""0.1.0"";";\n'
        '        public const string BridgeVersion = "9.9.9";\n'
    )
    # A decoy in an inactive #if false region is NOT a comment/string, so it survives the
    # strip — the guard must refuse to guess (two declarations) rather than pick the first.
    cs_preproc_fixture = (
        "#if false\n"
        '        public const string BridgeVersion = "0.1.0";\n'
        "#endif\n"
        '        public const string BridgeVersion = "9.9.9";\n'
    )
    # Value cases: exactly one real declaration must be extracted.
    value_cases = [
        ("cargo/ multiline-string", cargo_version(toml_fixture), "9.9.9"),
        ("cs/ block+line comment", cs_version(cs_fixture), "9.9.9"),
        ("cs/ url-in-string", cs_version(cs_url_fixture), "1.2.3"),
        ("cs/ raw-string decoy", cs_version(cs_raw_fixture), "9.9.9"),
        ("cs/ verbatim-string decoy", cs_version(cs_verbatim_fixture), "9.9.9"),
        ("manifest/ latestVersion", manifest_version('{"schemaVersion":1,"latestVersion":"9.9.9"}'), "9.9.9"),
        ("manifest/ not json", manifest_version("nope"), None),
        ("manifest/ missing key", manifest_version('{"schemaVersion":1}'), None),
        ("manifest/ non-string", manifest_version('{"latestVersion":5}'), None),
    ]
    # Ambiguity case: more than one surviving declaration ⇒ refuse to guess (cs_version None,
    # and >1 raw declarations so the caller emits a fatal, explained error).
    ambiguous_decls = cs_declarations(cs_preproc_fixture)
    ok = True
    for name, got, want in value_cases:
        status = "OK" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{status}] {name}: got {got!r}, want {want!r}")
    amb_ok = cs_version(cs_preproc_fixture) is None and len(ambiguous_decls) == 2
    ok = ok and amb_ok
    print(
        f"  [{'OK' if amb_ok else 'FAIL'}] cs/ preprocessor decoy (ambiguous): "
        f"declarations={ambiguous_decls!r}, refuse-to-guess={cs_version(cs_preproc_fixture) is None}"
    )
    if not ok:
        print("::error::bridge-version extractor self-test FAILED", file=sys.stderr)
        return 1
    print("bridge-version extractor self-test passed")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return _selftest()
    if len(argv) not in (2, 3):
        print(
            "usage: check-bridge-version.py <Cargo.toml> <PayloadBinaries.cs> [bridge.json]\n"
            "       check-bridge-version.py --selftest",
            file=sys.stderr,
        )
        return 2

    cargo_ver = cargo_version(_read(argv[0]))
    cs_decls = cs_declarations(_read(argv[1]))
    cs_ver = cs_decls[0] if len(cs_decls) == 1 else None
    manifest_ver = manifest_version(_read(argv[2])) if len(argv) == 3 else None
    print(f"Cargo.toml [package] version:   {cargo_ver!r}")
    print(f"PayloadBinaries.BridgeVersion:  {cs_ver!r}")
    if len(argv) == 3:
        print(f"bridge.json latestVersion:      {manifest_ver!r}")

    if len(cs_decls) > 1:
        print(
            f"::error::found {len(cs_decls)} `public const string BridgeVersion` "
            f"declarations in PayloadBinaries.cs ({cs_decls}); refusing to guess which is "
            f"active (an inactive #if region or a duplicate?). Leave exactly one.",
            file=sys.stderr,
        )
        return 1
    if not cargo_ver or not cs_ver or (len(argv) == 3 and not manifest_ver):
        sources = (
            "Cargo.toml, PayloadBinaries.cs, and/or bridge.json"
            if len(argv) == 3
            else "Cargo.toml and/or PayloadBinaries.cs"
        )
        print(
            f"::error::could not read the bridge version from {sources}",
            file=sys.stderr,
        )
        return 1
    if cargo_ver != cs_ver:
        print(
            f"::error::bridge version drift — native/btmqttd/Cargo.toml is "
            f"'{cargo_ver}' but PayloadBinaries.BridgeVersion is '{cs_ver}'. "
            f"Bump these two source-of-truth files together (.well-known/bridge.json is "
            f"release-driven and intentionally not checked here).",
            file=sys.stderr,
        )
        return 1
    if len(argv) == 3 and cargo_ver != manifest_ver:
        print(
            f"::error::bridge version drift — native/btmqttd/Cargo.toml is "
            f"'{cargo_ver}' but .well-known/bridge.json latestVersion is '{manifest_ver}'. "
            f"Bump ALL sources together.",
            file=sys.stderr,
        )
        return 1
    print(f"bridge version in sync: {cargo_ver}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
