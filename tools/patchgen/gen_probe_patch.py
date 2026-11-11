#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Generate patches/native_probe.json (diagnostic build).

Probe A (timer): skip the currentRemainTime store unconditionally.
Probe B (click): the type-30 case toggles the button colour red/white.
Cave 3 is the availability fix so the button stays clickable.
"""

from __future__ import annotations

import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from hooks import annotate
from sites import guard

ROOT = Path(__file__).resolve().parents[2]   # repo root (tools/patchgen/)


def b(pc: int, target: int) -> int:
    off = target - pc
    assert off % 4 == 0 and -(1 << 27) <= off < (1 << 27)
    return 0x14000000 | ((off >> 2) & 0x03FFFFFF)


def bl(pc: int, target: int) -> int:
    off = target - pc
    assert off % 4 == 0 and -(1 << 27) <= off < (1 << 27)
    return 0x94000000 | ((off >> 2) & 0x03FFFFFF)


def cbnz32(pc: int, rt: int, target: int) -> int:
    off = target - pc
    return 0xB5000000 | (((off >> 2) & 0x7FFFF) << 5) | rt


def bcond(pc: int, cond: int, target: int) -> int:
    off = target - pc
    return 0x54000000 | (((off >> 2) & 0x7FFFF) << 5) | cond


def ldrb(rt: int, rn: int, imm: int) -> int:
    return 0x39400000 | ((imm & 0xFFF) << 10) | (rn << 5) | rt


def strb(rt: int, rn: int, imm: int) -> int:
    return 0x39000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rt


def ldr64(rt: int, rn: int, imm: int) -> int:
    return 0xF9400000 | ((imm // 8) << 10) | (rn << 5) | rt


def ldr32(rt: int, rn: int, imm: int) -> int:
    return 0xB9400000 | ((imm // 4) << 10) | (rn << 5) | rt


def eor32(rd: int, rn: int, imm: int) -> int:
    return 0x52000000 | (rn << 5) | rd


def movz32(rd: int, imm: int) -> int:
    return 0x52800000 | ((imm & 0xFFFF) << 5) | rd


def mov_x(rd: int, rn: int) -> int:
    return 0xAA0003E0 | (rn << 16) | rd


def cmp32(rn: int, imm: int) -> int:
    return 0x71000000 | ((imm & 0xFFF) << 10) | (rn << 5) | 31


def ldp(rt: int, rt2: int, rn: int, imm: int) -> int:
    return 0xA9400000 | ((imm // 8) << 15) | (rt2 << 10) | (rn << 5) | rt


def ldp_post(rt: int, rt2: int, rn: int, imm: int) -> int:
    return 0xA8C00000 | ((imm // 8) << 15) | (rt2 << 10) | (rn << 5) | rt


RET = 0xD65F03C0


def build(base: int, items):
    labels = {}
    pc = base
    for item in items:
        if isinstance(item, tuple) and item[0] == "label":
            labels[item[1]] = pc
        else:
            pc += 4
    out = []
    pc = base
    for item in items:
        if isinstance(item, tuple) and item[0] == "label":
            continue
        if isinstance(item, tuple):
            mnem = item[0]
            args = item[1:]
            resolved = [labels[a] if isinstance(a, str) and a in labels else a for a in args]
            fn = {"b": b, "bl": bl, "cbnz": cbnz32, "bcond": bcond}[mnem]
            word = fn(pc, *resolved)
        else:
            word = item
        out.append((pc, word))
        pc += 4
    return out


def show(name, words):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    blob = b"".join(w.to_bytes(4, "little") for _, w in words)
    dis = list(md.disasm(blob, words[0][0]))
    print(f"== {name} ==")
    for (pc, w), ins in zip(words, dis):
        print(f"  {pc:#x}: {w:08x}  {ins.mnemonic:8} {ins.op_str}")
    assert len(dis) == len(words), (len(dis), len(words))


def main() -> int:
    # cave_avail @ 0x20C8AE0 (same as native_time.json)
    avail = build(0x20C8AE0, [
        ldr32(8, 19, 0x28),
        cmp32(8, 0x1E),
        ("bcond", 1, "store"),
        movz32(20, 1),
        ("label", "store"),
        strb(20, 19, 0x68),
        ("b", 0xE93A44),
    ])
    show("cave_avail", avail)

    # cave_click_probe @ 0x20C8B00: flip toggle byte, colour red/white
    click = build(0x20C8B00, [
        ldrb(9, 19, 0x49),
        eor32(9, 9, 1),
        strb(9, 19, 0x49),
        ("cbnz", 9, "red"),
        ("bl", 0x1D64640),      # Color.get_white
        ("b", "apply"),
        ("label", "red"),
        ("bl", 0x1D64618),      # Color.get_red
        ("label", "apply"),
        mov_x(0, 19),
        ("bl", 0xE93AD8),       # UIIconBtn.SetColor
        ldp(29, 30, 31, 0x30),
        ldp(20, 19, 31, 0x20),
        ldp(22, 21, 31, 0x10),
        ldp_post(24, 23, 31, 0x40),
        RET,
    ])
    show("cave_click_probe", click)

    avail_bytes = b"".join(w.to_bytes(4, "little") for _, w in avail)
    click_bytes = b"".join(w.to_bytes(4, "little") for _, w in click)

    spec = {
        "_comment": (
            "DIAGNOSTIC probe build (--probe). Probe A: the currentRemainTime "
            "store is skipped unconditionally (always-on infinite time). Probe B: "
            "the type-30 click case toggles the button colour red/white, so a "
            "visible change proves the click reaches the case. Cave 3 keeps the "
            "Kamcord button available."
        ),
        "enabled": False,
        "patches": [
            {"offset": "0xCC84C0", **guard(bytes.fromhex("615a02bd")), "patch": "01000014",
             "note": "probe A: b 0xCC84C4 - skip currentRemainTime store"},
            {"offset": "0xE95384", **guard(bytes.fromhex("a8de00f0")),
             "patch": b(0xE95384, 0x20C8B00).to_bytes(4, "little").hex(),
             "note": "probe B: type-30 case -> colour probe"},
            {"offset": "0xE93A40", **guard(bytes.fromhex("74a20139")),
             "patch": b(0xE93A40, 0x20C8AE0).to_bytes(4, "little").hex(),
             "note": "availability: force type 30 available"},
            {"offset": "0x20C8AE0", **guard(b"\x00" * len(avail_bytes)),
             "patch": avail_bytes.hex(), "note": "availability cave"},
            {"offset": "0x20C8B00", **guard(b"\x00" * len(click_bytes)),
             "patch": click_bytes.hex(), "note": "click colour probe cave"},
        ],
    }
    annotate(spec)
    (ROOT / "patches" / "native_probe.json").write_text(
        json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    print("\nwrote patches/native_probe.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
