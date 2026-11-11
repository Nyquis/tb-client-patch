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

# --- Coin Rate (PrivacyPolicy, type 25) and EXP Rate (Credits, type 22) ------
TYPE_PRIVACY = 25
TYPE_CREDITS = 22

COIN_LABELS = [
    b"[ffffff]Coin Rate x1[808080] / x15 / x99\x00",
    b"[ffffff]Coin Rate [808080]x1[ffffff] / x15[808080] / x99\x00",
    b"[ffffff]Coin Rate [808080]x1 / x15[ffffff] / x99\x00",
]
COIN_DATA = b"".join(COIN_LABELS)
COIN_OFF1 = len(COIN_LABELS[0])
COIN_OFF2 = len(COIN_LABELS[0]) + len(COIN_LABELS[1])

EXP_LABELS = [
    b"[ffffff]EXP Rate x1[808080] / x10 / Max\x00",
    b"[ffffff]EXP Rate [808080]x1[ffffff] / x10[808080] / Max\x00",
    b"[ffffff]EXP Rate [808080]x1 / x10[ffffff] / Max\x00",
]
EXP_DATA = b"".join(EXP_LABELS)
EXP_OFF1 = len(EXP_LABELS[0])
EXP_OFF2 = len(EXP_LABELS[0]) + len(EXP_LABELS[1])

COIN_CLICK_CASE = 0xE9518C          # OnClickBtn case for type 25
EXP_CLICK_CASE = 0xE950C4           # OnClickBtn case for type 22
COIN_APPLY_HOOK = 0xCEA410          # fmul s0, s2, s0  (baseCoin x coinMulti)
COIN_APPLY_RESUME = 0xCEA414

# EXP is accumulated in BattleManager.earnedExp inside _CheckForDrops.
# EXP accumulates in BattleManager.earnedExp from inside _CheckForDrops, the
# same iterator the coin hook already reads the mask from:
#   w21 = get_earnedExp(); w22 = [x19+0x2c]; w1 = w21 + w22; set_earnedExp(w1)
# Scaling the delta here means the in-battle counter, the results screen and the
# uploaded jobLevels all derive from one number.
EXP_EARN_HOOK = 0xCEB5F4             # add w1, w21, w22
EXP_EARN_RESUME = 0xCEB5F8

COIN_BITS = (8, 0x300)              # mask bits 8-9
EXP_BITS = (10, 0xC00)              # mask bits 10-11

# Temporary instrumentation: log which state each apply cave observes.
PROBE = False
DEBUG_LOG = 0x1D56B64               # UnityEngine.Debug.Log(object)
COIN_PROBE_DATA = b"TBC0\x00TBC1\x00TBC2\x00"
EXP_PROBE_DATA = b"TBA0\x00TBA1\x00TBA2\x00"

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


def add_w(rd, rn, rm):
    return 0x0B000000 | (rm << 16) | (rn << 5) | rd


def smul_w(rd, rn, rm):
    return 0x1B000000 | (rm << 16) | (0x1F << 10) | (rn << 5) | rd


def str32(rt, rn, imm):
    return 0xB9000000 | ((imm // 4) << 10) | (rn << 5) | rt


def str64(rt, rn, imm):
    return 0xF9000000 | ((imm // 8) << 10) | (rn << 5) | rt


def sub_sp(imm):
    return 0xD10003FF | ((imm & 0xFFF) << 10)


def add_sp(imm):
    return 0x910003FF | ((imm & 0xFFF) << 10)


def probe_items(off0, off1, off2):
    """Three-way branch that logs a per-state marker, then restores w9."""
    def log_at(off):
        return [("str", 0, off), ("bl", STRING_NEW), mov_x(1, 0),
                mov_x(0, 31), mov_x(2, 31), ("bl", DEBUG_LOG)]
    return ([sub_sp(16), str32(9, 31, 0),
             cmp32(9, 1), ("bcond", EQ, "p1"),
             cmp32(9, 2), ("bcond", EQ, "p2")]
            + log_at(off0) + [("b", "pdone"), ("label", "p1")]
            + log_at(off1) + [("b", "pdone"), ("label", "p2")]
            + log_at(off2)
            + [("label", "pdone"), ldr32(9, 31, 0), add_sp(16)])


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


def battle_label_items(drop_cave, coin_cave, exp_cave):
    return [
        ldr32(1, 8, 0x20),
        cmp32(1, 0x245), ("bcond", EQ, "kill"),
        cmp32(1, 0x12A), ("bcond", EQ, "stop"),
        ldr32(9, 19, 0x28),
        cmp32(9, TYPE_SUPPORT), ("bcond", EQ, "drop"),
        cmp32(9, TYPE_PRIVACY), ("bcond", EQ, "coin"),
        cmp32(9, TYPE_CREDITS), ("bcond", EQ, "exp"),
        ("b", "plain"),
        ("label", "kill"), ("str", 0, 0), ("b", "emit"),
        ("label", "stop"), ("str", 0, 6), ("b", "emit"),
        ("label", "emit"),
        ldr64(20, 19, 0x38), ("bl", STRING_NEW), mov_x(1, 0), mov_x(0, 20),
        ("bl", SET_TEXT), ("b", LABEL_RETURN),
        ("label", "drop"), ("b", drop_cave),
        ("label", "coin"), ("b", coin_cave),
        ("label", "exp"), ("b", exp_cave),
        ("label", "plain"), ("b", LABEL_PLAIN),
    ]


def three_state_label(shift, off0, off1, off2):
    return (mask_head() + get_int() + [
        ubfx(9, 0, shift, 2),
        cmp32(9, 1), ("bcond", EQ, "s1"),
        cmp32(9, 2), ("bcond", EQ, "s2"),
        ("str", 0, off0), ("b", "emit"),
        ("label", "s1"), ("str", 0, off1), ("b", "emit"),
        ("label", "s2"), ("str", 0, off2),
        ("label", "emit"),
        ldr64(20, 19, 0x38), ("bl", STRING_NEW), mov_x(1, 0), mov_x(0, 20),
        ("bl", SET_TEXT), ("b", LABEL_RETURN),
    ])


def cycle_click_items(shift, field_mask):
    return (mask_head() + get_int() + [
        ubfx(9, 0, shift, 2),
        cmp32(9, 2), ("bcond", LO, "inc"),
        movz(9, 0), ("b", "store"),
        ("label", "inc"), add_w_imm(9, 9, 1),
        ("label", "store"),
        movz(17, field_mask), bic_w(10, 0, 17), orr_w_shift(10, 10, 9, shift),
        ("adrp", 8, MASK_PAGE), add_imm(8, 8, MASK_OFF), ldr64(1, 8, 0),
        ("cbz", 1, "done"), mov_x(0, 31), mov_w(2, 10), mov_x(3, 31),
        ("bl", SET_INT), ("bl", SAVE),
        ("label", "done"), mov_x(0, 19), ("bl", UPDATE_BTN),
        ("b", CLICK_EPILOGUE),
    ])


def coin_apply_items():
    body = [sub_sp(16), str_f(0, 31, 0), str_f(2, 31, 8)]
    body += mask_head() + get_int()
    body += [ubfx(9, 0, COIN_BITS[0], 2)]
    if PROBE:
        body += probe_items(8, 13, 18)
    body += [
        ldr_f(0, 31, 0), ldr_f(2, 31, 8), add_sp(16),
        cmp32(9, 1), ("bcond", EQ, "x15"),
        cmp32(9, 2), ("bcond", EQ, "x99"),
        ("b", "mul"),
        ("label", "x15"), ("fldr", 1, 0), fmul_s(0, 0, 1), ("b", "mul"),
        ("label", "x99"), ("fldr", 1, 4), fmul_s(0, 0, 1),
        ("label", "mul"), fmul_s(0, 2, 0),
        ("b", COIN_APPLY_RESUME),
    ]
    return body


def coin_apply_data():
    data = struct.pack("<ff", 15.0, 99.0)
    return data + (COIN_PROBE_DATA if PROBE else b"")


def exp_apply_items():
    """Scale the per-kill EXP delta before it is added to earnedExp."""
    body = [sub_sp(16), str32(21, 31, 0), str32(22, 31, 4)]
    body += mask_head() + get_int()
    body += [ubfx(9, 0, EXP_BITS[0], 2)]
    if PROBE:
        body += probe_items(0, 5, 10)
    body += [
        ldr32(21, 31, 0), ldr32(22, 31, 4), add_sp(16),
        cmp32(9, 1), ("bcond", EQ, "x10"),
        cmp32(9, 2), ("bcond", EQ, "x99"),
        add_w(1, 21, 22), ("b", "done"),
        ("label", "x10"), movz(10, 10), smul_w(11, 22, 10),
        add_w(1, 21, 11), ("b", "done"),
        ("label", "x99"), movz(10, 99), smul_w(11, 22, 10),
        add_w(1, 21, 11),
        ("label", "done"),
        ("b", EXP_EARN_RESUME),
    ]
    return body


def exp_apply_data():
    return EXP_PROBE_DATA if PROBE else b""


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
        "coin_label": len(build(0x500000, resolve(0x500000, three_state_label(
            COIN_BITS[0], 0, COIN_OFF1, COIN_OFF2), COIN_DATA))),
        "coin_click": len(build(0x600000, resolve(0x600000,
                                                  cycle_click_items(*COIN_BITS), b""))),
        "coin_apply": len(build(0x700000, resolve(0x700000, coin_apply_items(),
                                                  coin_apply_data()))),
        "exp_label": len(build(0x800000, resolve(0x800000, three_state_label(
            EXP_BITS[0], 0, EXP_OFF1, EXP_OFF2), EXP_DATA))),
        "exp_click": len(build(0x900000, resolve(0x900000,
                                                 cycle_click_items(*EXP_BITS), b""))),
        "exp_apply": len(build(0xA00000, resolve(0xA00000, exp_apply_items(),
                                                 exp_apply_data()))),
    }
    drop_cave = alloc(sizes["drop"], "droplabel")
    click_cave = alloc(sizes["click"], "click")
    icon_cave = alloc(sizes["icon"], "icon")
    apply_cave = alloc(sizes["apply"], "apply")
    coin_label = alloc(sizes["coin_label"], "coin label")
    coin_click = alloc(sizes["coin_click"], "coin click")
    coin_apply = alloc(sizes["coin_apply"], "coin apply")
    exp_label = alloc(sizes["exp_label"], "exp label")
    exp_click = alloc(sizes["exp_click"], "exp click")
    exp_apply = alloc(sizes["exp_apply"], "exp apply")
    # The shared label cave outgrew its old 0x76-byte zero run (three more type
    # branches), so it is allocated like every other cave.
    label_size = len(build(0xB00000, resolve(0xB00000, battle_label_items(
        drop_cave, coin_label, exp_label), KILL_DATA)))
    label_cave = alloc(label_size, "battle label")

    drop_blob = build(drop_cave, resolve(drop_cave, drop_label_items(), DROP_DATA))
    click_blob = build(click_cave, resolve(click_cave, click_items(), b""))
    icon_blob = build(icon_cave, resolve(icon_cave, icon_items(), ICON_DATA))
    apply_blob = build(apply_cave, resolve(apply_cave, apply_items(),
                                           struct.pack("<ff", 5.0, 200.0)))
    coin_label_blob = build(coin_label, resolve(coin_label, three_state_label(
        COIN_BITS[0], 0, COIN_OFF1, COIN_OFF2), COIN_DATA))
    coin_click_blob = build(coin_click, resolve(coin_click,
                                                cycle_click_items(*COIN_BITS), b""))
    coin_apply_blob = build(coin_apply, resolve(coin_apply, coin_apply_items(),
                                                coin_apply_data()))
    exp_label_blob = build(exp_label, resolve(exp_label, three_state_label(
        EXP_BITS[0], 0, EXP_OFF1, EXP_OFF2), EXP_DATA))
    exp_click_blob = build(exp_click, resolve(exp_click,
                                              cycle_click_items(*EXP_BITS), b""))
    exp_apply_blob = build(exp_apply, resolve(exp_apply, exp_apply_items(),
                                              exp_apply_data()))
    label_blob = build(label_cave,
                       resolve(label_cave,
                               battle_label_items(drop_cave, coin_label, exp_label),
                               KILL_DATA))

    for name, blob, base in (("battle label", label_blob, label_cave),
                             ("droplabel", drop_blob, drop_cave),
                             ("click", click_blob, click_cave),
                             ("icon", icon_blob, icon_cave),
                             ("apply", apply_blob, apply_cave),
                             ("coin label", coin_label_blob, coin_label),
                             ("coin click", coin_click_blob, coin_click),
                             ("coin apply", coin_apply_blob, coin_apply),
                             ("exp label", exp_label_blob, exp_label),
                             ("exp click", exp_click_blob, exp_click),
                             ("exp apply", exp_apply_blob, exp_apply),
                             ):
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
         "patch": b(BATTLE_LABEL_HOOK, label_cave).to_bytes(4, "little").hex(),
         "hook": True, "live": "x19",
         "targets": [hex(LABEL_PLAIN), hex(LABEL_RETURN), hex(drop_cave),
                     hex(coin_label), hex(exp_label)],
         "note": "UpdateBtn: titles[type] load -> label cave (types 23/25/22)"},
        {"offset": hex(label_cave), **guard(b"\x00" * len(label_blob)),
         "patch": label_blob.hex(),
         "note": "label cave: 1-Hit / Stop, 23 -> drop, 25 -> coin, 22 -> exp"},
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

    rates_spec = {
        "_comment": (
            "Battle 'Coin Rate' (PrivacyPolicy, type 25) and 'EXP Rate' (Credits, "
            "type 22) rows. State lives in the AppSettings key 0x2BDC668: bits 8-9 "
            "coins, 10-11 EXP (Drop Rate owns 4-5). Coin multiplies the client's "
            "coin formula. EXP scales the addExp that UITeamStateItem.<AddExp> "
            "stores and, in Max, clamps the level handed to SetJobLevel at 90 - "
            "UIBattleResultTeam.AddExp is dead code with no call sites. The reTB "
            "server must keep exp_multiplier/coin_multiplier at 1.0 or the two "
            "compound."),
        "enabled": True,
        "patches": [
            patch(COIN_CLICK_CASE, b(COIN_CLICK_CASE, coin_click).to_bytes(4, "little"),
                  "PrivacyPolicy click -> cycle coin rate, save, refresh",
                  hook=True, live="x19", targets=[hex(CLICK_EPILOGUE)]),
            patch(coin_click, coin_click_blob, "coin-rate click cave"),
            patch(coin_label, coin_label_blob, "coin-rate label cave (type 25)"),
            patch(COIN_APPLY_HOOK, b(COIN_APPLY_HOOK, coin_apply).to_bytes(4, "little"),
                  "coin formula -> x1 / x15 / x99",
                  hook=True, live="x19", targets=[hex(COIN_APPLY_RESUME)]),
            patch(coin_apply, coin_apply_blob, "coin-rate apply cave"),
            patch(EXP_CLICK_CASE, b(EXP_CLICK_CASE, exp_click).to_bytes(4, "little"),
                  "Credits click -> cycle EXP rate, save, refresh",
                  hook=True, live="x19", targets=[hex(CLICK_EPILOGUE)]),
            patch(exp_click, exp_click_blob, "exp-rate click cave"),
            patch(exp_label, exp_label_blob, "exp-rate label cave (type 22)"),
            patch(EXP_EARN_HOOK, b(EXP_EARN_HOOK, exp_apply).to_bytes(4, "little"),
                  "earnedExp accumulator -> x1 / x10 per kill",
                  hook=True, live="x19,x20", targets=[hex(EXP_EARN_RESUME)]),
            patch(exp_apply, exp_apply_blob, "exp-rate apply cave"),
        ],
    }
    annotate(rates_spec)
    (ROOT / "patches" / "native_rates.json").write_text(
        json.dumps(rates_spec, indent=2) + "\n", encoding="utf-8")
    print(f"\ncaves: drop {drop_cave:#x} click {click_cave:#x} "
          f"icon {icon_cave:#x} apply {apply_cave:#x}")
    print(f"       coin label {coin_label:#x} click {coin_click:#x} apply {coin_apply:#x}")
    print(f"       exp  label {exp_label:#x} click {exp_click:#x} "
          f"apply {exp_apply:#x}")
    print(f"       battle label {label_cave:#x} ({label_size} B)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
