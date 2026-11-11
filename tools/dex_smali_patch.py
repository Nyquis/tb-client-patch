#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Smali-level edits to ``classes.dex``, decoded and reassembled with apktool.

Some fixes need *extra* instructions and cannot be expressed as an in-place byte
patch (the method has no spare code units). For those, this module decodes the
dex with baksmali (via the pinned apktool jar), inserts the snippets declared in
``patches/smali.json`` at the start of the named methods, and reassembles it.

The apktool jar is referenced, not vendored::

    APKTOOL_JAR   override the jar path (default: <workspace>/.tools/rea/bin)
    patches/smali.json  holds the pinned SHA-256; doctor verifies it

Every result is cached under ``work/dex-cache/`` keyed by (dex, manifest, rules,
jar) so a cold decode happens once. The step is deterministic: the same inputs
produce the same dex.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "patches" / "smali.json"
DEFAULT_JAR = ROOT.parent.parent / ".tools" / "rea" / "bin" / "apktool_3.0.3.jar"
CACHE = ROOT / "work" / "dex-cache"
BUILD = ROOT / "work" / "dex-build"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jar_path(rules: dict | None = None) -> Path:
    override = os.environ.get("APKTOOL_JAR") or (rules or {}).get("jar")
    return Path(override) if override else DEFAULT_JAR


def check_tooling(rules: dict | None = None) -> tuple[bool, str]:
    """(ok, detail) for doctor: jar present and matching the pinned digest."""
    rules = rules if rules is not None else json.loads(RULES.read_text(encoding="utf-8"))
    jar = jar_path(rules)
    if not jar.is_file():
        return False, f"{jar} (set APKTOOL_JAR or install apktool 3.0.3)"
    digest = _sha(jar.read_bytes())
    pinned = rules.get("apktool_sha256", "")
    if pinned and digest != pinned:
        return False, f"{jar} sha256 {digest[:16]} != pinned {pinned[:16]}"
    return True, f"{jar.name} ({digest[:16]})"


def _insert(lines: list[str], rule: dict) -> list[str]:
    """Insert the rule's snippet before the first instruction of its method."""
    sig = rule["method"]
    try:
        start = next(i for i, line in enumerate(lines)
                     if line.startswith(".method ") and sig in line)
    except StopIteration:
        raise ValueError(f".method {sig} not found in {rule['file']}") from None
    i = start + 1
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped and not stripped.startswith("."):
            break
        i += 1
    snippet = [line for line in rule["insert"].rstrip("\n").split("\n")]
    return lines[:i] + snippet + lines[i:]


def _patch_smali_tree(decoded: Path, rules: list[dict]) -> None:
    for rule in rules:
        path = decoded / "smali" / rule["file"]
        if not path.is_file():
            raise ValueError(f"missing smali file {rule['file']}")
        text = path.read_text(encoding="utf-8")
        patched = "\n".join(_insert(text.splitlines(), rule)) + "\n"
        if patched == text:
            raise ValueError(f"{rule['file']}: snippet not inserted")
        path.write_text(patched, encoding="utf-8")


def apply(dex: bytes, manifest: bytes, rules: dict | None = None) -> bytes:
    """Decode, apply patches/smali.json, reassemble; returns the new classes.dex."""
    rules = rules if rules is not None else json.loads(RULES.read_text(encoding="utf-8"))
    if not rules.get("rules"):
        return dex
    jar = jar_path(rules)
    if not jar.is_file():
        raise FileNotFoundError(f"apktool jar not found: {jar} (set APKTOOL_JAR)")

    key = _sha(dex + manifest + json.dumps(rules, sort_keys=True).encode()
               + _sha(jar.read_bytes()).encode())
    cached = CACHE / f"{key}.dex"
    if cached.is_file():
        return cached.read_bytes()

    work = BUILD / key
    work.mkdir(parents=True, exist_ok=True)
    source = work / "in.apk"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", dex)

    decoded = work / "decoded"
    out = work / "rebuilt.apk"
    java = os.environ.get("JAVA", "java")
    subprocess.run([java, "-jar", str(jar), "d", "-f", "--no-res",
                    "-o", str(decoded), str(source)], check=True,
                   capture_output=True, text=True)
    _patch_smali_tree(decoded, rules["rules"])
    subprocess.run([java, "-jar", str(jar), "b", "-f", "-o", str(out), str(decoded)],
                   check=True, capture_output=True, text=True)

    with zipfile.ZipFile(out) as z:
        rebuilt = z.read("classes.dex")
    CACHE.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(rebuilt)
    shutil.rmtree(work, ignore_errors=True)
    return rebuilt


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("apk", help="original APK (reads classes.dex + the manifest)")
    ap.add_argument("--out", help="write the patched classes.dex here")
    args = ap.parse_args()

    ok, detail = check_tooling()
    print(("OK   " if ok else "FAIL ") + detail)
    if not ok:
        return 1
    with zipfile.ZipFile(args.apk) as z:
        dex = z.read("classes.dex")
        manifest = z.read("AndroidManifest.xml")
    out = apply(dex, manifest)
    print(f"classes.dex: {len(dex)} -> {len(out)} bytes, sha256 {_sha(out)[:16]}")
    if args.out:
        Path(args.out).write_bytes(out)
        print("wrote", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
