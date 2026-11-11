#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Pre-flight check: inputs, toolchain, key. Read-only, exits non-zero on FAIL."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = Path(os.environ.get("TB_BUILD_TOOLS",
                           ROOT / ".android-sdk" / "build-tools" / "35.0.0"))

sys.path.insert(0, str(ROOT / "tools"))
import dex_smali_patch  # noqa: E402
import signing  # noqa: E402


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  {'OK  ' if ok else 'FAIL'} {label}{(' - ' + detail) if detail else ''}")
    return ok


def main() -> int:
    ok = True
    print("inputs")
    spec = json.loads((ROOT / "patches" / "inputs.json").read_text(encoding="utf-8"))
    for name, item in spec["entries"].items():
        path = ROOT / item["path"]
        exists = path.exists()
        ok &= check(f"{name} present", exists, item["path"])
        if exists:
            digest = sha256(path)
            ok &= check(f"{name} sha256", digest == item["sha256"], digest[:16])

    print("toolchain")
    for tool in ("zipalign.exe", "apksigner.bat", "aapt2.exe"):
        ok &= check(tool, (TOOLS / tool).exists(),
                    str(TOOLS / tool) if (TOOLS / tool).exists()
                    else "missing; set TB_BUILD_TOOLS to a build-tools 35.0.0 directory")
    adb = Path(os.environ.get("TB_ADB", ROOT / ".android-sdk" / "platform-tools" / "adb.exe"))
    ok &= check("adb", adb.exists(), str(adb))
    ok &= check("java", shutil.which("java") is not None, shutil.which("java") or "not on PATH (run via pixi)")
    tool_ok, detail = dex_smali_patch.check_tooling()
    ok &= check("apktool (smali step)", tool_ok, detail)

    print("signing")
    ok &= check("keystore", (ROOT / "keys" / "tb-client.keystore").exists(), "keys/tb-client.keystore")
    pin = signing.pinned_cert_sha256()
    ok &= check("pinned signer", bool(pin), pin[:16] + "...")
    if (ROOT / "keys" / "tb-client.keystore").exists():
        actual = signing.keystore_sha256()
        ok &= check("keystore matches the pin", actual == pin,
                    f"{actual[:16] if actual else 'unreadable'} (pixi run keycheck)"
                    if actual != pin else "ok")
    source = ("TB_KEY_PASS" if os.environ.get("TB_KEY_PASS")
              else "keys/keystore.pass" if (ROOT / "keys" / "keystore.pass").is_file()
              else "missing")
    ok &= check("keystore password source", source != "missing",
                source if source != "missing" else "write keys/keystore.pass or set TB_KEY_PASS")

    print("patch data")
    for path in sorted((ROOT / "patches").glob("native_*.json")):
        spec = json.loads(path.read_text(encoding="utf-8"))
        state = "enabled" if spec.get("enabled", True) else "disabled"
        count = len(spec.get("patches", []))
        print(f"  ..   {path.name}: {state} ({count} byte patch(es))")
    dex = json.loads((ROOT / "patches" / "dex.json").read_text(encoding="utf-8"))
    print(f"  ..   dex.json: {len(dex.get('rules', []))} method rule(s)")
    endpoints = json.loads((ROOT / "patches" / "endpoints.json").read_text(encoding="utf-8"))
    print(f"  ..   endpoints.json: {len(endpoints['metadata_literals'])} literal(s), "
          f"{len(endpoints.get('manifest_removals', []))} manifest removal(s)")

    print("analysis inputs")
    original = ROOT / json.loads((ROOT / "patches" / "inputs.json").read_text(encoding="utf-8"))["original"]
    ref = ROOT / "work" / "il2cpp" / "libil2cpp.so"
    if not ref.is_file():
        ok &= check("work/il2cpp (pixi run unpack)", False,
                    "missing; audit, patchgen and the analysis tools need it")
    elif original.is_file():
        import zipfile
        with zipfile.ZipFile(original) as z:
            digest = hashlib.sha256(z.read("lib/arm64-v8a/libil2cpp.so")).hexdigest()
        same = sha256(ref) == digest
        ok &= check("work/il2cpp matches the input APK", same,
                    "" if same else "the extracted reference is stale; rerun 'pixi run unpack'")
    else:
        check("work/il2cpp", True, "present (input APK unavailable to compare)")

    free = shutil.disk_usage(ROOT).free
    ok &= check("free space > 4 GiB", free > 4 * 1024**3, f"{free / 1024**3:.1f} GiB")

    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
