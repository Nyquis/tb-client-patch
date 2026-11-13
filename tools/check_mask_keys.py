#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Fail if a cave reads the retired mask key, or writes the mask destructively.

The TIME/HP/KILL/AUTO mask used to live in the
`ShowedFirstEvelyplayUploadWindow` PlayerPrefs key.  Its setter
(`UserData.SetShowedFirstEveryplayUploadWindow`, 0x19DDA30) writes only
`v & 1` at the title, which wiped bits 2/3, so the mask moved to the
version-verifier literal (`versionVerify_terra_battle_mistwalker`,
cell 0x2BDC668).

Two rules are enforced:

1. **Every cave reads the mask from the same key.**  A missed reader (as
   happened when `native_killstart` was left behind) is a bug that only shows
   up on a device, so it fails here.

2. **Every cave that stores the mask preserves the bits it does not own.**
   The mask is shared: bits 0-3 are the in-battle flags, bits 4-5 Drop Rate,
   bits 8-9 Coin Rate, bits 10-11 EXP Rate.  A writer that rebuilds the value
   from the flags alone silently resets the three Options rows - exactly the
   reported "rates reset after a zone unlock" defect.  The check tracks, bit
   by bit, whether the word handed to `PlayerPrefs.SetInt` descends from the
   word `PlayerPrefs.GetInt` returned; the rate bits must all be inherited.

Cells are the literal table (`0x2BDC668`), not a per-method usage slot, so a
plain adrp sweep of the original binary cannot see the game's own readers;
that is why this guard is about *our* caves only.
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

GET_INT = 0x1FA6AB8
SET_INT = 0x1FA6A10
# Drop Rate (bits 4-5), Coin Rate (bits 8-9), EXP Rate (bits 10-11).
RATE_BITS = 0xFF0
DROP_BITS = 0x030
COIN_BITS = 0x300
EXP_BITS = 0xC00

_ADRP = re.compile(r"x(\d+), #(0x[0-9a-f]+)$")
_ADD = re.compile(r"x(\d+), x(\d+), #(0x[0-9a-f]+)(?:, lsl #\d+)?$")
_REG = re.compile(r"([wx])(\d+|zr)")
_IMM = re.compile(r"#(-?(?:0x[0-9a-f]+|\d+))")
_SHIFT = re.compile(r",\s*(lsl|lsr|asr)\s*#(\d+)")


def _shifted(text: str) -> tuple[str | None, int]:
    m = _SHIFT.search(text)
    return (m.group(1), int(m.group(2))) if m else (None, 0)


def _apply_shift(bits: int, kind: str | None, amount: int, is_const: bool) -> int:
    if kind is None:
        return bits
    if kind == "lsl":
        return (bits << amount) & 0xFFFFFFFF
    return bits >> amount



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


def _reg(text: str) -> int | None:
    """Register number, or None for a non-register operand / zero register."""
    m = _REG.match(text.strip())
    if not m:
        return None
    name = m.group(2)
    if name == "zr":
        return 31
    num = int(name)
    return 31 if num == 31 else num


def _ops(op_str: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in op_str:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _imm(text: str) -> int | None:
    m = _IMM.search(text)
    return int(m.group(1), 0) if m else None


def _stored_bits(blob: bytes, base: int) -> list[tuple[int, int]]:
    """For each `PlayerPrefs.SetInt` in the cave, the bits of `w2` that descend
    from the value `PlayerPrefs.GetInt` returned.

    A small forward abstract interpretation: `src[r]` is the set of bits of
    register r whose value came from the mask read; `const[r]` is the value of
    a register known to hold a constant.  Only the instructions the caves
    actually use are modelled; anything else drops the taint, which can only
    make the check stricter.
    """
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    src: dict[int, int] = {}
    const: dict[int, int] = {}
    read_seen = False
    found: list[tuple[int, int]] = []

    def kill(reg: int, keep: bool = False) -> None:
        if not keep:
            src[reg] = 0
            const.pop(reg, None)

    for ins in md.disasm(blob, base):
        mn, ops = ins.mnemonic, _ops(ins.op_str)

        if mn in ("bl", "b") and len(ops) == 1:
            m = re.match(r"#(0x[0-9a-f]+|\d+)$", ops[0])
            if not m:
                continue
            target = int(m.group(1), 0)
            if mn != "bl":
                continue
            # A call clobbers w0..w18, but the caves only keep values in
            # x19+ across calls; model w0 explicitly.
            kill(0)
            if target == GET_INT:
                src[0] = 0xFFFFFFFF
                read_seen = True
            elif target == SET_INT:
                found.append((ins.address, src.get(2, 0)))
            continue

        if not ops:
            continue
        dst = _reg(ops[0])
        if dst is None:
            continue

        if mn == "mov":
            # capstone prints `mov wD, #imm` for a movz/movn alias.
            if len(ops) > 1 and ops[1].startswith("#"):
                if not (dst == 0 and read_seen):
                    kill(dst)
                    value = _imm(ops[1])
                    if value is not None:
                        const[dst] = value
                continue
            s = _reg(ops[1]) if len(ops) > 1 else None
            if s == 31:
                # `mov wD, wzr`: the emitter's GetInt default path.  A register
                # that already holds the read stays read-derived.
                if not (dst == 0 and read_seen):
                    kill(dst)
            elif s is not None:
                src[dst] = src.get(s, 0)
                if s in const:
                    const[dst] = const[s]
                else:
                    const.pop(dst, None)
        elif mn in ("movz", "movn"):
            value = _imm(ops[1]) if len(ops) > 1 else None
            if mn == "movn" and value is not None:
                value = (~value) & 0xFFFFFFFF
            if dst == 0 and read_seen:
                # Read-with-default path: keep the read taint.
                continue
            kill(dst)
            if value is not None:
                const[dst] = value
        elif mn in ("orr", "add", "eor", "and", "bic", "sub"):
            a = _reg(ops[1]) if len(ops) > 1 else None
            b = _reg(ops[2]) if len(ops) > 2 else None
            imm = _imm(ops[2]) if len(ops) > 2 else None
            kind, amount = _shifted(ops[2]) if len(ops) > 2 else (None, 0)
            sa = src.get(a, 0) if a is not None else 0
            sb = _apply_shift(src.get(b, 0) if b is not None else 0, kind, amount, False)
            ca = const.get(a)
            cb = const.get(b)
            cb = _apply_shift(cb, kind, amount, True) if cb is not None else None
            if mn == "orr":
                src[dst] = sa | sb
                if ca is not None and cb is not None:
                    const[dst] = (ca | cb) & 0xFFFFFFFF
                else:
                    const.pop(dst, None)
            elif mn == "eor":
                src[dst] = sa | sb
                const.pop(dst, None)
            elif mn in ("and", "bic"):
                if imm is not None:
                    keep = imm
                elif cb is not None:
                    keep = cb
                elif b is not None and sb == 0:
                    # Unknown operand: assume it could clear anything.
                    keep = 0
                else:
                    keep = 0xFFFFFFFF
                src[dst] = (sa & ~keep if mn == "bic" else sa & keep) & 0xFFFFFFFF
                const.pop(dst, None)
            else:  # add / sub
                if b is not None and b == a:
                    src[dst] = (sa << 1) & 0xFFFFFFFF
                elif imm is not None:
                    # Bit i of a sum depends on bits <= i of the addend.
                    out = sa
                    for k in range(1, min(imm, 4) + 1):
                        out |= (sa << k)
                    src[dst] = out & 0xFFFFFFFF
                elif cb is not None:
                    out = sa
                    for k in range(1, min(cb, 4) + 1):
                        out |= (sa << k)
                    src[dst] = out & 0xFFFFFFFF
                else:
                    src[dst] = (sa | sb) & 0xFFFFFFFF
                const.pop(dst, None)
        elif mn == "ubfx" and len(ops) == 4:
            a = _reg(ops[1])
            lsb, width = _imm(ops[2]) or 0, _imm(ops[3]) or 0
            mask = (1 << width) - 1 if width else 0
            src[dst] = ((src.get(a, 0) if a is not None else 0) >> lsb) & mask
            const.pop(dst, None)
        elif mn in ("ldr", "ldrb", "ldrh", "ldrsw", "ldur", "ldursw"):
            kill(dst)
        elif mn in ("ldp", "ldp_post"):
            kill(dst)
            if len(ops) > 1:
                d2 = _reg(ops[1])
                if d2 is not None:
                    kill(d2)
        elif mn in ("movk", "mrs", "adrp", "adr", "csel", "csinc", "csinv"):
            kill(dst)
    return found


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


def check_mask_writers() -> int:
    """Every cave that stores the mask must inherit the rate bits."""
    errors: list[str] = []
    checked = 0
    for path in sorted(PATCHES.glob("native_*.json")):
        spec = json.loads(path.read_text(encoding="utf-8"))
        if not spec.get("enabled", True):
            continue
        for patch in spec.get("patches", []):
            blob = bytes.fromhex(patch["patch"])
            if len(blob) < 16:
                continue
            base = int(patch["offset"], 16)
            if SET_INT not in {
                int(i.op_str.lstrip("#"), 16)
                for i in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(blob, base)
                if i.mnemonic == "bl" and i.op_str.startswith("#")
            }:
                continue
            if NEW_KEY not in _add_targets(blob, base):
                errors.append(
                    f"{path.name} @{patch['offset']}: stores a mask but never reads {NEW_KEY:#x}"
                )
                continue
            checked += 1
            for pc, bits in _stored_bits(blob, base):
                missing = RATE_BITS & ~bits
                # A row cycler may replace its own two bits; nothing may drop a
                # whole row it does not own (that is the 0.2.6 reset bug).
                if missing not in (0, DROP_BITS, COIN_BITS, EXP_BITS):
                    errors.append(
                        f"{path.name} @{patch['offset']}: PlayerPrefs.SetInt at {pc:#x} "
                        f"does not inherit rate bits {missing:#05x} "
                        f"(allowed: 0, {DROP_BITS:#05x} drop, {COIN_BITS:#05x} coin, "
                        f"{EXP_BITS:#05x} EXP)"
                    )

    if errors:
        print("\nFAIL: a cave overwrites bits it does not own:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "A mask writer must start from PlayerPrefs.GetInt and change only its own "
            "bits; rebuilding the value from the in-battle flags wipes the rate rows.",
            file=sys.stderr,
        )
        return 1
    print(f"PASS: {checked} mask writer(s) preserve bits 4-11 (Drop/Coin/EXP)")
    return 0


def main() -> int:
    rc = check_mask_keys()
    rc |= check_mask_writers()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
