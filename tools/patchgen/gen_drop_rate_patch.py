#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Generate the battle 'Drop Rate' row (Support button) and regenerate the
battle-label cave so it can route type 23 to the new three-state label.

Pieces:
  * label cave  (0x20C9F34, native_kill_label.json): ids 581/298 as before,
    plus `type == 23 -> b <droplabel cave>`.
  * droplabel   : mask bits 4-5 -> one of three pre-tagged strings.
  * click       : type-23 case -> cycle bits 4-5, save, UpdateBtn, epilogue.
  * icon        : InitBtn icons[type] -> icon_treasure_chest_03 for type 23.
  * apply       : the final item drop chance (*1 / *5 / flat 200).

Mask lives in the AppSettings PlayerPrefs key (0x2BDC668) that already stores
TIME/HP/KILL/AUTO in bits 0-3; bits 4-5 are untouched by the existing writers.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from hooks import annotate
from sites import guard

ROOT = Path(__file__).resolve().parents[2]   # repo root (tools/patchgen/)
SO = ROOT / "work" / "il2cpp" / "libil2cpp.so"

BATTLE_LABEL_CAVE = 0x20C9F34
BATTLE_LABEL_HOOK = 0xE93710

ICON_HOOK = 0xE92EE0
ICON_RESUME = 0xE92EE4
CLICK_CASE = 0xE95100
CLICK_EPILOGUE = 0xE965E4
APPLY_HOOK = 0xCEA468
APPLY_RESUME = 0xCEA46C

STRING_NEW = 0xBE7908
SET_TEXT = 0xE89CD0
GET_INT = 0x1FA6AB8
SET_INT = 0x1FA6A10
SAVE = 0x1FA6EE4
UPDATE_BTN = 0xE936A4

MASK_PAGE, MASK_OFF = 0x2BDC000, 0x668
LABEL_RETURN = 0xE9386C
LABEL_PLAIN = 0xE93714
TYPE_SUPPORT = 23

KILL_DATA = b"1-Hit\x00Stop\x00"
DROP_LABELS = [
    b"[ffffff]Drop Rate x1[808080] / x5 / Max\x00",
    b"[ffffff]Drop Rate [808080]x1[ffffff] / x5[808080] / Max\x00",
    b"[ffffff]Drop Rate [808080]x1 / x5[ffffff] / Max\x00",
]
DROP_DATA = b"".join(DROP_LABELS)
DROP_OFF1 = len(DROP_LABELS[0])
DROP_OFF2 = len(DROP_LABELS[0]) + len(DROP_LABELS[1])
ICON_DATA = b"icon_treasure_chest_03\x00"

EQ, NE, LT, GE, LE, HS, LO = 0, 1, 11, 10, 13, 2, 3


def b(pc, t):
    off = t - pc
    assert off % 4 == 0, hex(off)
    return 0x14000000 | ((off >> 2) & 0x03FFFFFF)


def bl(pc, t):
    off = t - pc
    assert off % 4 == 0, hex(off)
    return 0x94000000 | ((off >> 2) & 0x03FFFFFF)


def bcond(pc, cond, t):
    off = t - pc
    assert off % 4 == 0, hex(off)
    return 0x54000000 | (((off >> 2) & 0x7FFFF) << 5) | cond


def cbz(pc, rt, t):
    off = t - pc
    assert off % 4 == 0, hex(off)
    return 0xB4000000 | (((off >> 2) & 0x7FFFF) << 5) | rt


def adrp(pc, rd, page):
    imm = (page - (pc & ~0xFFF)) >> 12
    assert -(1 << 20) <= imm < (1 << 20), hex(imm)
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def add_imm(rd, rn, imm):
    assert 0 <= imm < 0x1000, hex(imm)
    return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def ldr64(rt, rn, imm):
    return 0xF9400000 | ((imm // 8) << 10) | (rn << 5) | rt


def ldr32(rt, rn, imm):
    return 0xB9400000 | ((imm // 4) << 10) | (rn << 5) | rt


def ldr_f(rt, rn, imm):
    return 0xBD400000 | ((imm // 4) << 10) | (rn << 5) | rt


def str_f(rt, rn, imm):
    return 0xBD000000 | ((imm // 4) << 10) | (rn << 5) | rt


def fmul_s(rd, rn, rm):
    return 0x1E200800 | (rm << 16) | (rn << 5) | rd


def cmp32(rn, imm):
    return 0x71000000 | ((imm & 0xFFF) << 10) | (rn << 5) | 31


def movz(rd, imm):
    return 0x52800000 | ((imm & 0xFFFF) << 5) | rd


def mov_x(rd, rn):
    return 0xAA0003E0 | (rn << 16) | rd


def mov_w(rd, rn):
    return 0x2A0003E0 | (rn << 16) | rd


def ubfx(rd, rn, lsb, width):
    return 0x53000000 | (lsb << 16) | ((lsb + width - 1) << 10) | (rn << 5) | rd


def bic_w(rd, rn, rm):
    return 0x0A200000 | (rm << 16) | (rn << 5) | rd


def orr_w_shift(rd, rn, rm, shift):
    return 0x2A000000 | (shift << 10) | (rm << 16) | (rn << 5) | rd


def add_w_imm(rd, rn, imm):
    return 0x11000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def count_words(items) -> int:
    n = 0
    for it in items:
        if isinstance(it, tuple) and it[0] in ("label", "data"):
            continue
        if isinstance(it, tuple) and it[0] in ("str", "fldr"):
            n += 2          # adrp + add / adrp + ldr
        else:
            n += 1
    return n


def resolve(base: int, items, data: bytes):
    """Turn ("str", reg, off) / ("fldr", sreg, off) into adrp(+add/ldr)."""
    code_size = count_words(items) * 4
    out = []
    for it in items:
        if isinstance(it, tuple) and it[0] == "str":
            _, rd, off = it
            addr = base + code_size + off
            out.append(("adrp", rd, addr & ~0xFFF))
            out.append(add_imm(rd, rd, addr & 0xFFF))
        elif isinstance(it, tuple) and it[0] == "fldr":
            _, sreg, off = it
            addr = base + code_size + off
            out.append(("adrp", 8, addr & ~0xFFF))
            out.append(ldr_f(sreg, 8, addr & 0xFFF))
        else:
            out.append(it)
    if data:
        out.append(("data", data))
    return out


def build(base, items):
    labels = {}
    pc = base
    for it in items:
        if isinstance(it, tuple) and it[0] == "label":
            labels[it[1]] = pc
        elif isinstance(it, tuple) and it[0] == "data":
            pc += len(it[1])
        else:
            pc += 4
    out = bytearray()
    pc = base
    for it in items:
        if isinstance(it, tuple) and it[0] == "label":
            continue
        if isinstance(it, tuple) and it[0] == "data":
            out += it[1]
            out += b"\x00" * ((-len(out)) % 4)
            pc = base + len(out)
            continue
        if isinstance(it, tuple):
            mnem, args = it[0], it[1:]
            resolved = [labels[a] if isinstance(a, str) else a for a in args]
            word = {"b": b, "bl": bl, "bcond": bcond, "cbz": cbz,
                    "adrp": adrp}[mnem](pc, *resolved)
        else:
            word = it
        out += word.to_bytes(4, "little")
        pc += 4
    return bytes(out)


def disasm(name, blob, base):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    print(f"== {name} @ {base:#x} ({len(blob)} bytes) ==")
    for ins in md.disasm(blob, base):
        print(f"  {ins.address:#x}: {ins.mnemonic:8} {ins.op_str}")


def mask_head():
    return [("adrp", 8, MASK_PAGE), add_imm(8, 8, MASK_OFF), ldr64(1, 8, 0)]


def get_int():
    return [("cbz", 1, "def"), mov_x(0, 31), mov_w(2, 31), mov_x(3, 31),
            ("bl", GET_INT), ("b", "have"), ("label", "def"), mov_w(0, 31),
            ("label", "have")]


def battle_label_items(drop_cave):
    return [
        ldr32(1, 8, 0x20),
        cmp32(1, 0x245), ("bcond", EQ, "kill"),
        cmp32(1, 0x12A), ("bcond", EQ, "stop"),
        ldr32(9, 19, 0x28), cmp32(9, TYPE_SUPPORT), ("bcond", NE, "notdrop"),
        ("b", drop_cave),
        ("label", "notdrop"), ("b", "plain"),
        ("label", "kill"), ("str", 0, 0), ("b", "emit"),
        ("label", "stop"), ("str", 0, 6), ("b", "emit"),
        ("label", "emit"),
        ldr64(20, 19, 0x38), ("bl", STRING_NEW), mov_x(1, 0), mov_x(0, 20),
        ("bl", SET_TEXT), ("b", LABEL_RETURN),
        ("label", "plain"), ("b", LABEL_PLAIN),
    ]


def drop_label_items():
    return (mask_head() + get_int() + [
        ubfx(9, 0, 4, 2),
        cmp32(9, 1), ("bcond", EQ, "s1"),
        cmp32(9, 2), ("bcond", EQ, "s2"),
        ("str", 0, 0), ("b", "emit"),
        ("label", "s1"), ("str", 0, DROP_OFF1), ("b", "emit"),
        ("label", "s2"), ("str", 0, DROP_OFF2),
        ("label", "emit"),
        ldr64(20, 19, 0x38), ("bl", STRING_NEW), mov_x(1, 0), mov_x(0, 20),
        ("bl", SET_TEXT), ("b", LABEL_RETURN),
    ])


def click_items():
    return (mask_head() + get_int() + [
        ubfx(9, 0, 4, 2),
        cmp32(9, 2), ("bcond", LO, "inc"),
        movz(9, 0), ("b", "store"),
        ("label", "inc"), add_w_imm(9, 9, 1),
        ("label", "store"),
        movz(17, 0x30), bic_w(10, 0, 17), orr_w_shift(10, 10, 9, 4),
        ("adrp", 8, MASK_PAGE), add_imm(8, 8, MASK_OFF), ldr64(1, 8, 0),
        ("cbz", 1, "done"), mov_x(0, 31), mov_w(2, 10), mov_x(3, 31),
        ("bl", SET_INT), ("bl", SAVE),
        ("label", "done"), mov_x(0, 19), ("bl", UPDATE_BTN), ("b", CLICK_EPILOGUE),
    ])


def icon_items():
    return [
        ldr64(21, 8, 0x20),
        ldr32(9, 19, 0x28), cmp32(9, TYPE_SUPPORT), ("bcond", NE, "out"),
        ("str", 0, 0), ("bl", STRING_NEW), mov_x(21, 0),
        ("label", "out"), ("b", ICON_RESUME),
    ]


def apply_items():
    return (mask_head() + get_int() + [
        ubfx(9, 0, 4, 2),
        cmp32(9, 1), ("bcond", EQ, "x5"),
        cmp32(9, 2), ("bcond", EQ, "mx"),
        ("b", "store"),
        ("label", "x5"), ("fldr", 1, 0), fmul_s(0, 0, 1), ("b", "store"),
        ("label", "mx"), ("fldr", 0, 4),
        ("label", "store"),
        str_f(0, 19, 0x34), ("b", APPLY_RESUME),
    ])


def main() -> int:
    so = SO.read_bytes()
    used = []
    for f in sorted((ROOT / "patches").glob("native_*.json")):
        if f.name in ("native_payload.json", "native_droprate.json", "native_kill_label.json"):
            continue
        spec = json.loads(f.read_text(encoding="utf-8"))
        for p in spec.get("patches", []):
            o = int(p["offset"], 16)
            used.append((o, o + len(p["patch"]) // 2))

    def free(off, size):
        return all(not (a < off + size and off < bb) for a, bb in used)

    def alloc(size, hint):
        for off in range(0x20C9000, 0x20CC000, 4):
            if off + size > 0x20CC000:
                break
            if all(x == 0 for x in so[off:off + size]) and free(off, size):
                used.append((off, off + size))
                return off
        raise SystemExit(f"no free run for {hint} ({size} bytes)")

    # measure (immediates do not change length, so a zero base is fine)
    sizes = {
        "drop": len(build(0x100000, resolve(0x100000, drop_label_items(), DROP_DATA))),
        "click": len(build(0x200000, resolve(0x200000, click_items(), b""))),
        "icon": len(build(0x300000, resolve(0x300000, icon_items(), ICON_DATA))),
        "apply": len(build(0x400000, resolve(0x400000, apply_items(),
                                              struct.pack("<ff", 5.0, 200.0)))),
    }
    drop_cave = alloc(sizes["drop"], "droplabel")
    click_cave = alloc(sizes["click"], "click")
    icon_cave = alloc(sizes["icon"], "icon")
    apply_cave = alloc(sizes["apply"], "apply")
    used.append((BATTLE_LABEL_CAVE, BATTLE_LABEL_CAVE + 0x70))

    drop_blob = build(drop_cave, resolve(drop_cave, drop_label_items(), DROP_DATA))
    click_blob = build(click_cave, resolve(click_cave, click_items(), b""))
    icon_blob = build(icon_cave, resolve(icon_cave, icon_items(), ICON_DATA))
    apply_blob = build(apply_cave, resolve(apply_cave, apply_items(),
                                           struct.pack("<ff", 5.0, 200.0)))
    label_blob = build(BATTLE_LABEL_CAVE,
                       resolve(BATTLE_LABEL_CAVE,
                               battle_label_items(drop_cave), KILL_DATA))

    for name, blob, base in (("battle label", label_blob, BATTLE_LABEL_CAVE),
                             ("droplabel", drop_blob, drop_cave),
                             ("click", click_blob, click_cave),
                             ("icon", icon_blob, icon_cave),
                             ("apply", apply_blob, apply_cave)):
        disasm(name, blob, base)

    def patch(off, new, note, **extra):
        d = {"offset": hex(off), **guard(so[off:off + len(new)]),
             "patch": new.hex(), "note": note}
        d.update(extra)
        return d

    kill_spec = json.loads((ROOT / "patches" / "native_kill_label.json").read_text(encoding="utf-8"))
    kill_spec["_comment"] = (
        "Battle-menu labels. UIIconBtn.UpdateBtn resolves titles[type] through "
        "StringSet.GetUIString; hooking that load lets the cave substitute its own "
        "strings. ids 581 (UI_KILL) and 298 (UI_BTN_KAMCORD_STOP) become '1-Hit' and "
        "'Stop'; type 23 (Support) branches to the drop-rate label cave in "
        "native_droprate.json. Strings are built with il2cpp_string_new from ASCII in "
        "the cave padding, so no metadata literal is rewritten."
    )
    kill_spec["patches"] = [
        {"offset": hex(BATTLE_LABEL_HOOK), **guard(bytes.fromhex("012140b9")),
         "patch": b(BATTLE_LABEL_HOOK, BATTLE_LABEL_CAVE).to_bytes(4, "little").hex(),
         "hook": True, "live": "x19",
         "targets": [hex(LABEL_PLAIN), hex(LABEL_RETURN), hex(drop_cave)],
         "note": "UpdateBtn: titles[type] load -> label cave (ids 581/298, type 23)"},
        {"offset": hex(BATTLE_LABEL_CAVE), **guard(b"\x00" * len(label_blob)),
         "patch": label_blob.hex(),
         "note": "label cave: 1-Hit / Stop, and type 23 -> drop-rate label cave"},
    ]
    annotate(kill_spec)
    (ROOT / "patches" / "native_kill_label.json").write_text(
        json.dumps(kill_spec, indent=2) + "\n", encoding="utf-8")

    drop_spec = {
        "_comment": ("Battle 'Drop Rate' row on the Support button (UIIconBtn.Type 23). "
                     "Mask bits 4-5 of the AppSettings key 0x2BDC668 hold the state "
                     "(0 = x1, 1 = x5, 2 = Max); the existing writers bic #0xC so bits 4-5 "
                     "survive. The label is rendered by the label cave in native_kill_label.json, "
                     "which branches here for type 23. 'Max' forces the final item drop chance "
                     "to 200, always above the [0,100) roll threshold; x5 multiplies it by 5."),
        "enabled": True,
        "patches": [
            patch(CLICK_CASE, b(CLICK_CASE, click_cave).to_bytes(4, "little"),
                  "Support click -> cycle drop rate, save, refresh",
                  hook=True, live="x19", targets=[hex(CLICK_EPILOGUE)]),
            patch(click_cave, click_blob, "drop-rate click cave"),
            patch(drop_cave, drop_blob, "drop-rate label cave (type 23)"),
            patch(ICON_HOOK, b(ICON_HOOK, icon_cave).to_bytes(4, "little"),
                  "InitBtn icons[type] -> icon_treasure_chest_03 for type 23",
                  hook=True, live="x19,x20", targets=[hex(ICON_RESUME)]),
            patch(icon_cave, icon_blob, "drop-rate icon cave"),
            patch(APPLY_HOOK, b(APPLY_HOOK, apply_cave).to_bytes(4, "little"),
                  "final item drop chance -> x1 / x5 / Max",
                  hook=True, live="x19,x20", targets=[hex(APPLY_RESUME)]),
            patch(apply_cave, apply_blob, "drop-rate apply cave"),
        ],
    }
    annotate(drop_spec)
    (ROOT / "patches" / "native_droprate.json").write_text(
        json.dumps(drop_spec, indent=2) + "\n", encoding="utf-8")
    print(f"\ncaves: drop {drop_cave:#x} click {click_cave:#x} "
          f"icon {icon_cave:#x} apply {apply_cave:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
