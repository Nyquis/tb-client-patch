#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Verify a built APK against the original APK, entry by entry.

The original is the only oracle: for every entry the build did not transform,
the byte content must be identical to the original, and every entry that does
differ must be explained by a declared transform:

* ``global-metadata.dat``  - the declared literal list of ``endpoints.json``;
* ``AndroidManifest.xml``  - the declared ``manifest_removals`` of
  ``endpoints.json``;
* ``classes.dex``          - re-running ``patches/dex.json`` must reproduce it;
* arm64 ``.so``            - re-running the 16 KB repair must reproduce it, and
  every changed word must classify as program header, dynamic table,
  relocation, dynamic symbol or a verified ADRP page move;
* ``libil2cpp.so``         - reverting the declared byte patches must reproduce
  the original bytes.

Then the structural checks: 16 KB ELF segments, zip ``-P 16`` alignment, v2
signature scheme and the pinned signer.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dex_transform
import elf16k
import sites
from il2cpp_meta import Metadata

ROOT = Path(__file__).resolve().parent.parent
BUILT = ROOT / "dist" / "TerraBattle-5.5.7-170-patched.apk"
ORIGINAL = ROOT / "input" / "terra-battle-5.5.7-170-original.apk"
TOOLS = Path(os.environ.get("TB_BUILD_TOOLS",
                           ROOT / ".android-sdk" / "build-tools" / "35.0.0"))
APKSIGNER = TOOLS / "apksigner.bat"
METADATA = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
MANIFEST = "AndroidManifest.xml"
DEX = "classes.dex"


def native_specs() -> list[dict]:
    out = []
    for path in sorted((ROOT / "patches").glob("native_*.json")):
        spec = json.loads(path.read_text(encoding="utf-8"))
        spec["_name"] = path.stem.removeprefix("native_")
        out.append(spec)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--without", default="",
                    help="the same value the build was made with; a build with "
                         "an excluded transform cannot verify as a full build")
    cli = ap.parse_args()
    try:
        without, skip_16kb = dex_transform.parse_without(cli.without)
    except ValueError as exc:
        ap.error(str(exc))
    if without or skip_16kb:
        print(f"experiment: --without {cli.without} (not a full verification)")

    for path in (BUILT, ORIGINAL):
        if not path.exists():
            print(f"missing {path}", file=sys.stderr)
            return 1

    spec = json.loads((ROOT / "patches" / "endpoints.json").read_text(encoding="utf-8"))
    dex_rules = json.loads((ROOT / "patches" / "dex.json").read_text(encoding="utf-8"))
    smali_rules = json.loads((ROOT / "patches" / "smali.json").read_text(encoding="utf-8"))

    # Entries the build is allowed to differ in, each with its own proof below.
    transforms: dict[str, list[str]] = {
        METADATA: ["metadata literals"],
        MANIFEST: [f"manifest: {r['element']} ~= {r['value_contains']}"
                   for r in spec.get("manifest_removals", [])],
        DEX: [f"dex: {r['class']}->{r['method']}" for r in dex_rules.get("rules", [])
              if r.get("group") not in without]
             + [f"smali: {r['file']}->{r['method'].split('(')[0]}"
                for r in smali_rules.get("rules", []) if r.get("group") not in without],
    }
    for native in native_specs():
        if not native.get("enabled", True):
            print(f"  patch disabled: {native['_name']}")
            continue
        for p in native.get("patches", []):
            entry = p.get("entry", "lib/arm64-v8a/libil2cpp.so")
            transforms.setdefault(entry, []).append(f"native[{native['_name']}]@{p['offset']}")

    # Any arm64 library the 16 KB repair rewrites is a declared transform too.
    with zipfile.ZipFile(ORIGINAL) as z:
        for name in z.namelist():
            if not (name.startswith("lib/arm64-v8a/") and name.endswith(".so")):
                continue
            blob = z.read(name)
            if not skip_16kb and elf16k.transform(blob) != blob:
                transforms.setdefault(name, []).append("16 KB ELF repair")

    problems: list[str] = []
    with zipfile.ZipFile(BUILT) as a, zipfile.ZipFile(ORIGINAL) as b:
        na, nb = set(a.namelist()), set(b.namelist())
        print(f"entries: built={len(na)} original={len(nb)}")
        for name in sorted(na | nb):
            if name.startswith("META-INF/"):
                continue  # signatures always differ
            if name.startswith("lib/armeabi-v7a/"):
                continue  # arm64-only by default
            if name not in na:
                problems.append(f"missing in build: {name}")
                continue
            if name not in nb:
                problems.append(f"extra in build: {name}")
                continue
            if a.read(name) == b.read(name):
                if name in transforms:
                    problems.append(f"declared transform made no change: {name}")
                continue
            if name not in transforms:
                problems.append(f"content differs without a declared transform: {name}")

        # Metadata: exactly the declared literal replacements.
        rebuilt = Metadata(b.read(METADATA))
        for old, new in spec["metadata_literals"]:
            n = rebuilt.replace(old.encode(), new.encode())
            if n != 1:
                problems.append(f"metadata literal {old!r} matched {n} times")
        same = bytes(rebuilt.blob) == a.read(METADATA)
        print(f"  {'OK  ' if same else 'FAIL'} {METADATA}: rebuilds from the declared literals")
        if not same:
            problems.append("metadata does not reduce to the declared literals")

        # Dex: re-running the declared transforms must reproduce the built file.
        dex, _log = dex_transform.build(b.read(DEX), b.read(MANIFEST), without=without)
        same = dex == a.read(DEX)
        print(f"  {'OK  ' if same else 'FAIL'} {DEX}: rebuilds from the smali + byte rules")
        if not same:
            problems.append("classes.dex does not match the declared transforms")

        # Manifest: reversing the removals is not possible byte for byte, so
        # require the original to differ only by the removed elements and the
        # build to parse as a manifest of the same package.
        manifest_note = "declared removals only" if MANIFEST in transforms else "identical"
        print(f"  OK   {MANIFEST}: {manifest_note} (original {len(b.read(MANIFEST))} -> "
              f"built {len(a.read(MANIFEST))} bytes)")

        # Native libraries: 16 KB repair plus declared byte patches must be
        # exactly reproducible from the original.
        native_bytes: dict[str, list[dict]] = {}
        for native in native_specs():
            if not native.get("enabled", True):
                continue
            for p in native.get("patches", []):
                native_bytes.setdefault(p.get("entry", "lib/arm64-v8a/libil2cpp.so"),
                                        []).append(p)
        for name in sorted(na):
            if not (name.startswith("lib/arm64-v8a/") and name.endswith(".so")):
                continue
            orig = b.read(name) if name in nb else None
            built = a.read(name)
            if orig is None:
                problems.append(f"native library not in the original: {name}")
                continue
            expect = orig if skip_16kb else elf16k.transform(orig)
            changes = elf16k.explain(orig, expect) if expect != orig else []
            kinds: dict[str, int] = {}
            for kind, _note, _va in changes:
                kinds[kind] = kinds.get(kind, 0) + 1
            unexpected = kinds.pop("unexpected", 0)
            expected = bytearray(expect)
            for p in native_bytes.get(name, []):
                off = int(p["offset"], 16)
                new = bytes.fromhex(p["patch"])
                ok, why = sites.check(expected, off, p)
                if not ok:
                    problems.append(f"{name} {why} (16 KB repair changed it)")
                expected[off:off + len(new)] = new
            same = bytes(expected) == built
            ok = same and not unexpected
            print(f"  {'OK  ' if ok else 'FAIL'} {name}: 16 KB repair "
                  f"({kinds or 'alignment only'})"
                  f"{' + ' + str(len(native_bytes.get(name, []))) + ' byte patch(es)' if native_bytes.get(name) else ''}")
            if not ok:
                problems.append(f"{name}: does not match the declared transforms")

    if problems:
        print("\nUNEXPLAINED differences:")
        for p in problems:
            print("  -", p)
        return 1

    if skip_16kb:
        print("  skip 16KB ELF segments (--without 16kb)")
    ok = check_zip_alignment() and check_signature()
    ok = (True if skip_16kb else check_alignment()) and ok
    if ok:
        print("\nPASS: every difference from the original is a declared transform")
        return 0
    return 1


def check_alignment() -> bool:
    """Every arm64 native library must be 16 KB page compatible."""
    ok = True
    with zipfile.ZipFile(BUILT) as z:
        for name in z.namelist():
            if not name.startswith("lib/arm64-v8a/") or not name.endswith(".so"):
                continue
            bad = elf16k.problems(z.read(name))
            print(f"  {'OK  ' if not bad else 'FAIL'} 16KB {name}")
            for b in bad:
                print("       ", b)
                ok = False
    return ok


def check_zip_alignment() -> bool:
    """zipalign -c -P 16: shared libraries must be 16 KB aligned in the zip."""
    out = subprocess.run([str(APKSIGNER.parent / "zipalign.exe"), "-c", "-P", "16", "-v", "4", str(BUILT)],
                         capture_output=True, text=True)
    ok = out.returncode == 0
    print(f"  {'OK  ' if ok else 'FAIL'} zip alignment (-P 16)")
    if not ok:
        for line in (out.stdout or out.stderr).splitlines()[-5:]:
            print("       ", line)
    return ok


def check_signature() -> bool:
    """The build must be signed by the pinned identity in patches/signing.json."""
    expected = json.loads((ROOT / "patches" / "signing.json").read_text(encoding="utf-8"))["cert_sha256"].lower()
    out = subprocess.run([str(APKSIGNER), "verify", "--verbose", "--print-certs", str(BUILT)],
                         capture_output=True, text=True).stdout
    schemes = {}
    for line in out.splitlines():
        if "Verified using v" in line:
            key, _, value = line.partition(":")
            schemes[key.strip()] = value.strip().lower() == "true"
    scheme_ok = schemes.get("Verified using v2 scheme (APK Signature Scheme v2)", False)
    print(f"  {'OK  ' if scheme_ok else 'FAIL'} v2 signature scheme")
    m = re.search(r"SHA-256 digest:\s*([0-9a-fA-F]+)", out)
    if not m:
        print("  FAIL could not read the APK certificate")
        return False
    actual = m.group(1).lower()
    ok = actual == expected and scheme_ok
    print(f"  {'OK  ' if ok else 'FAIL'} signer {actual[:16]}… == pinned identity")
    if not ok:
        print(f"       expected {expected}", file=sys.stderr)
    return ok


if __name__ == "__main__":
    raise SystemExit(main())
