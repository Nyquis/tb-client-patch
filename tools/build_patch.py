#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Build the patched Terra Battle 5.5.7 client from the original APK.

Pipeline: original APK -> metadata endpoint patch -> manifest removals ->
classes.dex rules (WebView disable) -> 16 KB ELF repair -> native byte patches
-> repack -> zipalign -> sign.

Every step derives its output from the user's own APK; there is no reference
APK, no third-party binary and no pre-built delta.

Diagnostic flags:
  --no-speed        skip the battle-speed byte patches
  --no-time         skip the infinite-time toggle byte patches
  --probe           always-on timer + click colour probe
  --with-armv7      keep the armeabi-v7a libraries (default: arm64-only)
  --out PATH        write the APK somewhere else than the default
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
import signing
import sites
from apk_io import MANIFEST, METADATA, rewrite, sha256
from axml import remove_element
from check_mask_keys import check_mask_keys
from il2cpp_meta import Metadata

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "input" / "terra-battle-5.5.7-170-original.apk"
DIST = ROOT / "dist"
TOOLS = Path(os.environ.get("TB_BUILD_TOOLS",
                           ROOT / ".android-sdk" / "build-tools" / "35.0.0"))
KEYSTORE = ROOT / "keys" / "tb-client.keystore"
OUT = DIST / "TerraBattle-5.5.7-170-patched.apk"


def drop_prefixes(args: argparse.Namespace) -> tuple[str, ...]:
    """arm64-only by default: the phones are arm64 and armv7 libil2cpp is 37 MB."""
    return () if args.with_armv7 else ("lib/armeabi-v7a/",)


def native_specs() -> list[dict]:
    """Every patches/native_*.json, sorted by name."""
    out = []
    for path in sorted((ROOT / "patches").glob("native_*.json")):
        spec = json.loads(path.read_text(encoding="utf-8"))
        spec["_name"] = path.stem.removeprefix("native_")
        out.append(spec)
    return out


def run(cmd: list[str]) -> None:
    print("+", " ".join(str(c) for c in cmd))
    subprocess.run(cmd, check=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-speed", action="store_true")
    ap.add_argument("--no-time", action="store_true",
                    help="skip the infinite-time toggle byte patches")
    ap.add_argument("--probe", action="store_true",
                    help="diagnostic: always-on timer + click colour probe")
    ap.add_argument("--with-armv7", action="store_true",
                    help="keep the armeabi-v7a libraries (default: arm64-only APK)")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()
    out = Path(args.out)

    if not INPUT.exists():
        print(f"missing input APK: {INPUT}", file=sys.stderr)
        return 1
    if not KEYSTORE.exists():
        print("missing signing key; run 'pixi run newkey' first", file=sys.stderr)
        return 1
    spec = json.loads((ROOT / "patches" / "endpoints.json").read_text(encoding="utf-8"))

    DIST.mkdir(exist_ok=True)
    unsigned = DIST / f"unsigned-{out.stem}.apk"
    aligned = DIST / f"aligned-{out.stem}.apk"

    # 1. Endpoint literals.
    src = zipfile.ZipFile(INPUT)
    meta = Metadata(src.read(METADATA))
    total = 0
    for old, new in spec["metadata_literals"]:
        n = meta.replace(old.encode(), new.encode())
        if n != 1:
            print(f"  ! literal {old!r} matched {n} time(s)", file=sys.stderr)
            return 1
        total += n
    print(f"metadata: patched {total} literals")

    # 2. Manifest removals.
    manifest = src.read(MANIFEST)
    for rule in spec.get("manifest_removals", []):
        manifest = remove_element(manifest, rule["element"], rule["attribute"], rule["value_contains"])
        print(f"manifest: removed <{rule['element']} {rule['attribute']}~={rule['value_contains']}>")

    overrides: dict[str, bytes] = {METADATA: bytes(meta.blob), MANIFEST: manifest}

    # 3. classes.dex: smali edits (JNIBridge guard) then byte rules (UniWebView).
    dex, dex_log = dex_transform.build(src.read("classes.dex"), manifest)
    for line in dex_log:
        print(f"dex: {line}")
    overrides["classes.dex"] = dex

    # 4. 16 KB repair of the arm64 libraries that ship 4 KB-aligned segments.
    for name in src.namelist():
        if not (name.startswith("lib/arm64-v8a/") and name.endswith(".so")):
            continue
        blob = src.read(name)
        fixed = elf16k.transform(blob)
        if fixed == blob:
            continue
        changes = elf16k.explain(blob, fixed)
        kinds: dict[str, int] = {}
        for kind, _note, _va in changes:
            kinds[kind] = kinds.get(kind, 0) + 1
        if kinds.get("unexpected"):
            print(f"  ! {name}: unexpected ELF changes: {kinds}", file=sys.stderr)
            return 1
        overrides[name] = fixed
        print(f"elf16k: {name} {len(blob)} -> {len(fixed)} bytes ({kinds})")

    # 5. Native (ARM64) byte patches from every enabled patches/native_*.json.
    skips = {"speed": args.no_speed, "time": args.no_time or args.probe}
    force = {"probe"} if args.probe else set()
    for native in native_specs():
        name = native["_name"]
        if (skips.get(name) or not native.get("enabled", True)) and name not in force:
            print(f"{name}: skipped (patch disabled)")
            continue
        for patch in native.get("patches", []):
            entry = patch.get("entry", "lib/arm64-v8a/libil2cpp.so")
            blob = bytearray(overrides.get(entry) or src.read(entry))
            off = int(patch["offset"], 16)
            new = bytes.fromhex(patch["patch"])
            ok, why = sites.check(blob, off, patch)
            if not ok:
                print(f"  ! {entry} {why}", file=sys.stderr)
                return 1
            blob[off:off + len(new)] = new
            overrides[entry] = bytes(blob)
            print(f"native[{name}]: {entry}@{patch['offset']} -> {new.hex()}")

    # 5b. Semantic guard: every mask reader must use the current key.
    if check_mask_keys() != 0:
        return 1

    # 6. Repack, align, sign.
    rewrite(INPUT, unsigned, overrides, drop_prefixes=drop_prefixes(args))
    return _finish(unsigned, aligned, out)


def _finish(unsigned: Path, aligned: Path, out: Path) -> int:
    run([str(TOOLS / "zipalign.exe"), "-P", "16", "-f", "4", str(unsigned), str(aligned)])
    run([
        str(TOOLS / "apksigner.bat"), "sign",
        "--ks", str(KEYSTORE),
        "--ks-pass", f"pass:{signing.password()}",
        "--key-pass", f"pass:{signing.password()}",
        "--ks-key-alias", signing.alias(),
        "--out", str(out), str(aligned),
    ])
    unsigned.unlink(missing_ok=True)
    aligned.unlink(missing_ok=True)

    # The signing identity is pinned in patches/signing.json.
    expected = signing.pinned_cert_sha256()
    signer_out = subprocess.run(
        [str(TOOLS / "apksigner.bat"), "verify", "--print-certs", str(out)],
        capture_output=True, text=True,
    ).stdout
    match = re.search(r"SHA-256 digest:\s*([0-9a-fA-F]+)", signer_out)
    actual = match.group(1).lower() if match else ""
    if actual != expected:
        out.unlink(missing_ok=True)
        print(f"\nERROR: build signed by {actual or 'unknown'}, expected {expected}\n"
              "The key in keys/ no longer matches patches/signing.json. If keys/ was\n"
              "lost, uninstall the old client on the phone first, then update signing.json.",
              file=sys.stderr)
        return 1
    print(f"signer: {actual} (matches patches/signing.json)")

    print(f"\nbuilt {out} ({out.stat().st_size / 1048576:.1f} MiB)")
    print("sha256", sha256(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
