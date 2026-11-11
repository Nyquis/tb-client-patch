#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Negative tests for tools/audit_patches.py.

The audit is the guardrail that has to catch the defects which already cost us
builds.  An unexercised guardrail is worse than none, so each fixture below
injects one known-bad shape into a synthetic patch set and asserts the audit
rejects it.  Run with ``pixi run audit-selftest``.
"""

from __future__ import annotations

import json
import struct
import sys
import tempfile
from pathlib import Path

import audit_patches as ap

REF_SIZE = 0x4000


def word(w: int) -> str:
    return w.to_bytes(4, "little").hex()


def enc_b(pc: int, target: int) -> int:
    off = target - pc
    assert off % 4 == 0
    return 0x14000000 | ((off >> 2) & 0x03FFFFFF)


def enc_adrp(pc: int, rd: int, page: int) -> int:
    imm = (page - (pc & ~0xFFF)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def enc_ldr(rt: int, rn: int, imm: int) -> int:
    return 0xF9400000 | ((imm // 8) << 10) | (rn << 5) | rt


def spec(patches, **extra) -> dict:
    out = {"enabled": True, "patches": patches}
    out.update(extra)
    return out


def hook(off: int, target: int, **extra) -> dict:
    p = {"offset": hex(off), "original": "00000000", "patch": word(enc_b(off, target))}
    p.update(extra)
    return p


def cave(off: int, words, **extra) -> dict:
    p = {"offset": hex(off), "original": "00" * (4 * len(words)),
         "patch": "".join(word(w) for w in words)}
    p.update(extra)
    return p


GOOD = spec([
    hook(0x1000, 0x1100, hook=True, live="x19", targets=[hex(0x1004)]),
    cave(0x1100, [enc_b(0x1100, 0x1004), 0xD503201F]),
])

STALE = spec([
    hook(0x1000, 0x1200, hook=True),          # 0x1200 has no patch in this set
])

LIVE_CLOBBER = spec([
    hook(0x1000, 0x1100, hook=True, live="x19", targets=[hex(0x1004)]),
    cave(0x1100, [0xAA0003F3, enc_b(0x1104, 0x1004)]),   # mov x19, x0
])

X18 = spec([
    hook(0x1000, 0x1100, hook=True, targets=[hex(0x1004)]),
    cave(0x1100, [0xAA0003F2, enc_b(0x1104, 0x1004)]),   # mov x18, x0
])

INTO_PATCH = spec([
    hook(0x1000, 0x1100, hook=True, targets=[hex(0x1014)]),
    cave(0x1010, [enc_b(0x1010, 0x1014), 0xD503201F, 0xD503201F]),
    cave(0x1100, [enc_b(0x1100, 0x1014), 0xD503201F]),   # lands inside another patch
])

UNDECLARED_TARGET = spec([
    hook(0x1000, 0x1100, hook=True, targets=[hex(0xDEAD0)]),
    cave(0x1100, [enc_b(0x1100, 0x1004), 0xD503201F]),
])

COND_EXIT = spec([
    hook(0x1000, 0x1100, hook=True, targets=[hex(0x1004)]),
    cave(0x1100, [0xB4000040, enc_b(0x1104, 0x1004)]),   # cbz x0, outside the cave
])

PREF_KEY = spec([
    hook(0x1000, 0x1100, hook=True, targets=[hex(0x1004)]),
    cave(0x1100, [enc_b(0x1100, 0x1004), 0xD503201F]),
], prefs_keys=[{"name": "k", "slot": "0x2000",
                "sites": [{"ref": "0x1234", "patched": "0x1000"}]}])

# The direction that actually bit us: the binary has a site the declaration does
# not mention. Needs a reference that really contains the adrp+ldr pair.
PREF_SITE_REF = bytearray(REF_SIZE)
struct.pack_into("<I", PREF_SITE_REF, 0x1200, enc_adrp(0x1200, 8, 0x2000))
struct.pack_into("<I", PREF_SITE_REF, 0x1204, enc_ldr(8, 8, 0x660))
PREF_UNDECLARED = spec([], prefs_keys=[{"name": "k", "slot": "0x2660", "sites": []}])


def run(name: str, sp: dict, reference: bytes, expect_fail: bool) -> bool:
    before = len(ap.failures)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "native_fixture.json"
        path.write_text(json.dumps(sp), encoding="utf-8")
        ap.audit_file(path, reference)
    gained = ap.failures[before:]
    ok = bool(gained) if expect_fail else not gained
    status = "PASS" if ok else "FAIL"
    detail = "" if ok else f"  (gained {len(gained)} issue(s))"
    print(f"{status}  {name}{detail}")
    if expect_fail and gained:
        print(f"        caught: {gained[0]}")
    return ok


def main() -> int:
    ap.CODE_LO, ap.CODE_HI = 0, REF_SIZE
    zero = bytes(REF_SIZE)
    dirty = bytearray(REF_SIZE)
    dirty[0x1100:0x1104] = b"\x01\x02\x03\x04"

    cases = [
        ("accepts a coherent hook/cave", GOOD, zero, False),
        ("rejects a hook pointing at a missing cave", STALE, zero, True),
        ("rejects a cave clobbering a live register", LIVE_CLOBBER, zero, True),
        ("rejects x18/w18 in a cave", X18, zero, True),
        ("rejects a branch into another patch", INTO_PATCH, zero, True),
        ("rejects an undeclared branch target", UNDECLARED_TARGET, zero, True),
        ("rejects a conditional exit from a cave", COND_EXIT, zero, True),
        ("rejects a prefs site that does not exist", PREF_KEY, zero, True),
        ("rejects a real prefs site missing from the declaration",
         PREF_UNDECLARED, bytes(PREF_SITE_REF), True),
        ("rejects a cave that is not zero in the reference", GOOD, bytes(dirty), True),
    ]

    results = [run(*c) for c in cases]

    # The shared slot scanner must see a reference whose adrp and ldr are not
    # adjacent: the adjacent-only matcher is what hid the speed key's third
    # reader. Uses a minimal ELF because find_slot_refs reads section headers.
    import find_refs

    def mini_elf(code: bytes, base: int) -> bytes:
        header = bytearray(0x40)
        header[0:4] = b"\x7fELF"
        header[4] = 2
        header[5] = 1
        struct.pack_into("<Q", header, 0x28, 0x40)   # e_shoff
        struct.pack_into("<H", header, 0x3A, 0x40)   # e_shentsize
        struct.pack_into("<H", header, 0x3C, 1)      # e_shnum
        section = bytearray(0x40)
        struct.pack_into("<I", section, 4, 1)        # SHT_PROGBITS
        struct.pack_into("<Q", section, 8, 0x4)      # SHF_EXECINSTR
        struct.pack_into("<Q", section, 16, base)    # sh_addr
        struct.pack_into("<Q", section, 24, 0x80)    # sh_offset
        struct.pack_into("<Q", section, 32, len(code))
        return bytes(header) + bytes(section) + code

    slot = 0x2000 + 0x660
    separated = (struct.pack("<I", enc_adrp(0x1000, 8, 0x2000))
                 + struct.pack("<I", 0xD503201F)              # nop between adrp and ldr
                 + struct.pack("<I", enc_ldr(8, 8, 0x660)))
    found = find_refs.find_slot_refs(mini_elf(separated, 0x1000), slot)
    ok = len(found) == 1 and found[0][0] == 0x1000 and found[0][1] == 0x1008
    print(f"{'PASS' if ok else 'FAIL'}  finds an adrp+ldr pair separated by another instruction"
          + ("" if ok else f"  (got {found})"))
    results.append(ok)

    # literal provenance needs a string-literal slot; exercise it directly
    ap.load_string_literals = lambda: {0x2BD3118}
    ap.failures.clear()
    code = (struct.pack("<I", enc_adrp(0x1100, 8, 0x2BD3000))
            + struct.pack("<I", enc_ldr(2, 8, 0x118)))
    ap.audit_literals(Path("native_fixture.json"), 0x1100, code, 0x1000,
                      bytes(REF_SIZE), {0x1000: "M"}, None)
    ok = bool(ap.failures)
    print(f"{'PASS' if ok else 'FAIL'}  rejects an unacknowledged literal slot"
          + (f"\n        caught: {ap.failures[0]}" if ok else ""))
    results.append(ok)

    print()
    if all(results):
        print(f"PASS: {len(results)} audit self-tests")
        return 0
    print(f"FAILED: {results.count(False)} self-test(s)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
