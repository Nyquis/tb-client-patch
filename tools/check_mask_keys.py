#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Fail if a mask-reading cave still uses the retired Everyplay key.

The TIME/HP/KILL/AUTO mask used to live in the
`ShowedFirstEvelyplayUploadWindow` PlayerPrefs key.  Its setter
(`UserData.SetShowedFirstEveryplayUploadWindow`, 0x19DDA30) writes only
`v & 1` at the title, which wiped bits 2/3, so the mask moved to the
version-verifier literal (`versionVerify_terra_battle_mistwalker`,
cell 0x2BDC668).

This guard disassembles every declared cave in the three mask-using patch
families and checks its adrp+add targets.  A missed reader (as happened when
`native_killstart` was left behind) fails the build with a clear message.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

ROOT = Path(__file__).resolve().parent.parent
PATCHES = ROOT / "patches"
OLD_KEY = 0x2BE2170
NEW_KEY = 0x2BDC668
FILES = ("native_killstart.json", "native_time.json", "native_options.json")

_ADRP = re.compile(r"x(\d+), #(0x[0-9a-f]+)$")
_ADD = re.compile(r"x(\d+), x(\d+), #(0x[0-9a-f]+)(?:, lsl #\d+)?$")


def _add_targets(blob: bytes, base: int) -> set[int]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    pages: dict[int, int] = {}
    targets: set[int] = set()
    for ins in md.disasm(blob, base):
        if ins.mnemonic == "adrp":
            m = _ADRP.match(ins.op_str)
            if m:
                pages[int(m.group(1))] = int(m.group(2), 16)
        elif ins.mnemonic == "add":
            m = _ADD.match(ins.op_str)
            if m:
                rd, rn, imm = int(m.group(1)), int(m.group(2)), int(m.group(3), 16)
                if rd == rn and rn in pages:
                    targets.add(pages[rn] + imm)
    return targets


def check_mask_keys() -> int:
    errors: list[str] = []
    for name in FILES:
        path = PATCHES / name
        spec = json.loads(path.read_text(encoding="utf-8"))
        targets: set[int] = set()
        for patch in spec.get("patches", []):
            targets |= _add_targets(
                bytes.fromhex(patch["patch"]),
                int(patch["offset"], 16),
            )
        if OLD_KEY in targets:
            errors.append(f"{name}: still reads the retired Everyplay key {OLD_KEY:#x}")
        if NEW_KEY not in targets:
            errors.append(f"{name}: no access to the mask key {NEW_KEY:#x}")
        print(f"{name}: mask key {NEW_KEY:#x} found; retired key {'FOUND' if OLD_KEY in targets else 'absent'}")

    if errors:
        print("\nFAIL: mask key is inconsistent:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "Update every mask reader (native_killstart, native_time, native_options) "
            f"to {NEW_KEY:#x}.",
            file=sys.stderr,
        )
        return 1
    print(f"\nPASS: all mask readers use {NEW_KEY:#x}; {OLD_KEY:#x} is not referenced")
    return 0


def main() -> int:
    return check_mask_keys()


if __name__ == "__main__":
    raise SystemExit(main())
