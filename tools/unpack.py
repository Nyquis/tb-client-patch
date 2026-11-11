#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Extract the analysis inputs from your own APK into ``work/``.

The build and verify steps read the APK directly, but the cave audit, the
generators and the analysis tools need the unpacked artefacts:

    work/il2cpp/libil2cpp.so            code reference for patches/audit/gen_*
    work/il2cpp/global-metadata.dat     string/literal reference

Both come from ``input/terra-battle-5.5.7-170-original.apk`` (the path pinned in
``patches/inputs.json``). Nothing here is committed; ``work/`` is gitignored.
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "work" / "il2cpp"
ENTRIES = {
    "lib/arm64-v8a/libil2cpp.so": "libil2cpp.so",
    "assets/bin/Data/Managed/Metadata/global-metadata.dat": "global-metadata.dat",
}


def apk_path() -> Path:
    spec = json.loads((ROOT / "patches" / "inputs.json").read_text(encoding="utf-8"))
    return ROOT / spec["original"]


def main() -> int:
    apk = apk_path()
    if not apk.is_file():
        print(f"missing input APK: {apk}", file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk) as z:
        for entry, name in ENTRIES.items():
            data = z.read(entry)
            target = OUT / name
            target.write_bytes(data)
            print(f"{target.relative_to(ROOT)}  ({len(data)} bytes)")
    print("ready: audit, patchgen and the analysis tools can run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
