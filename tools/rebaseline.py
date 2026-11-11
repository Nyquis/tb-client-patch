#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Re-pin the recipe to a new original APK (a different client build).

    pixi run rebaseline --original input/new-original.apk

Walks every declarative transform against the new APK and reports what no
longer applies:

* the endpoint literals (present exactly once, replacement fits),
* the dex rules: smali inserts (needs the pinned apktool) then byte rules,
* the 16 KB ELF repair,
* every native byte patch: its ``original`` bytes must still be at its offset,
* the manifest removals (does each element still exist).

It does **not** invent new offsets. If a native patch no longer matches, the
build would fail on the byte assertion anyway: re-derive that site with
``pixi run find-refs`` / ``pixi run jumptable``, update its generator under
``tools/patchgen/``, then run this again.

Only when everything applies does it re-pin the hash/size in
``patches/inputs.json``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import dex_smali_patch  # noqa: E402
import dex_transform  # noqa: E402
import elf16k  # noqa: E402
import sites  # noqa: E402
from axml import remove_element  # noqa: E402
from il2cpp_meta import Metadata  # noqa: E402


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_literals(apk: Path) -> int:
    spec = json.loads((ROOT / "patches" / "endpoints.json").read_text(encoding="utf-8"))
    with zipfile.ZipFile(apk) as z:
        meta = Metadata(z.read("assets/bin/Data/Managed/Metadata/global-metadata.dat"))
    bad = 0
    for old, new in spec["metadata_literals"]:
        hits = 0
        for i in range(meta.table_size // 8):
            length, index = struct.unpack_from("<II", meta.blob, meta.table_off + i * 8)
            start = meta.data_off + index
            if bytes(meta.blob[start:start + length]) == old.encode():
                hits += 1
        if hits != 1 or len(new) > len(old):
            print(f"  FAIL {old!r}: matches={hits} fits={len(new) <= len(old)}")
            bad += 1
    print(f"endpoints: {len(spec['metadata_literals']) - bad}/{len(spec['metadata_literals'])} still patchable")
    return bad


def check_dex(apk: Path) -> int:
    with zipfile.ZipFile(apk) as z:
        blob = z.read("classes.dex")
        manifest = z.read("AndroidManifest.xml")
    tool_ok, detail = dex_smali_patch.check_tooling()
    if not tool_ok:
        print(f"  FAIL smali step: {detail}")
        return 1
    try:
        patched, log = dex_transform.build(blob, manifest)
    except (ValueError, FileNotFoundError) as exc:
        print(f"  FAIL dex: {exc}")
        return 1
    for line in log:
        print(f"  OK {line}")
    print(f"  OK smali: {len(json.loads((ROOT / 'patches' / 'smali.json').read_text(encoding='utf-8'))['rules'])} rule(s) applied, "
          f"{len(blob)} -> {len(patched)} bytes")
    return 0


def check_elf(apk: Path) -> int:
    bad = 0
    with zipfile.ZipFile(apk) as z:
        for name in z.namelist():
            if not (name.startswith("lib/arm64-v8a/") and name.endswith(".so")):
                continue
            blob = z.read(name)
            try:
                fixed = elf16k.transform(blob)
            except ValueError as exc:
                print(f"  FAIL {name}: {exc}")
                bad += 1
                continue
            kinds: dict[str, int] = {}
            for kind, _note, _va in elf16k.explain(blob, fixed):
                kinds[kind] = kinds.get(kind, 0) + 1
            print(f"  OK {name}: {kinds or 'already 16 KB compatible'}")
            if kinds.get("unexpected"):
                bad += 1
    return bad


def check_native(apk: Path) -> int:
    """Every declared byte patch must still find its original bytes."""
    bad = 0
    with zipfile.ZipFile(apk) as z:
        blobs: dict[str, bytes] = {}
        for path in sorted((ROOT / "patches").glob("native_*.json")):
            spec = json.loads(path.read_text(encoding="utf-8"))
            if not spec.get("enabled", True):
                print(f"  ..   {path.name}: disabled")
                continue
            for patch in spec.get("patches", []):
                entry = patch.get("entry", "lib/arm64-v8a/libil2cpp.so")
                if entry not in blobs:
                    blobs[entry] = z.read(entry)
                off = int(patch["offset"], 16)
                ok, why = sites.check(blobs[entry], off, patch)
                if not ok:
                    print(f"  FAIL {path.name} {entry}: {why}")
                    bad += 1
    print(f"native: {'all sites match' if not bad else f'{bad} site(s) moved'}")
    return bad


def check_manifest(apk: Path) -> int:
    spec = json.loads((ROOT / "patches" / "endpoints.json").read_text(encoding="utf-8"))
    rules = spec.get("manifest_removals", [])
    if not rules:
        return 0
    with zipfile.ZipFile(apk) as z:
        raw = z.read("AndroidManifest.xml")
    bad = 0
    doc = raw
    for rule in rules:
        try:
            shrunk = remove_element(doc, rule["element"], rule["attribute"],
                                    rule["value_contains"])
        except (ValueError, IndexError) as exc:
            print(f"  FAIL manifest: {rule['element']} ~= {rule['value_contains']}: {exc}")
            bad += 1
            continue
        if len(shrunk) >= len(doc):
            print(f"  FAIL manifest: {rule['element']} ~= {rule['value_contains']} not found")
            bad += 1
            continue
        doc = shrunk
    print(f"manifest: {len(rules) - bad}/{len(rules)} removal(s) still present")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--original", required=True)
    ap.add_argument("--repin", action="store_true",
                    help="write patches/inputs.json even if a check fails")
    args = ap.parse_args()
    apk = Path(args.original)

    if not apk.is_file():
        print(f"missing APK: {apk}", file=sys.stderr)
        return 1

    bad = (check_literals(apk) + check_dex(apk) + check_elf(apk)
           + check_native(apk) + check_manifest(apk))
    if bad and not args.repin:
        print(f"\n{bad} transform(s) do not apply: fix them before re-pinning")
        return 1

    inputs = json.loads((ROOT / "patches" / "inputs.json").read_text(encoding="utf-8"))
    try:
        pinned_path = apk.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        pinned_path = apk.as_posix()
    inputs["entries"]["original"] = {"path": pinned_path, "sha256": sha(apk),
                                     "size": apk.stat().st_size}
    (ROOT / "patches" / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n",
                                                  encoding="utf-8")
    print(f"updated patches/inputs.json ({apk.name}, {apk.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
