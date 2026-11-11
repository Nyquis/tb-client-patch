#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Enable the 3-state battle speed and show x2 / x3 / x4 in the Options row.

The engine path is already in ``native_speed.json``: cave A maps the saved
state 0/1/2 to ``timeScale * 2/3/4``, and ``BattleManager.<StartBattle>``
loads the raw state at battle start.

Two fixes:

* The label cave must not read standalone literals such as ``" / "`` or
  ``[ffffff]``.  Those usage slots are not initialized when UpdateBtn runs, so
  Concat silently dropped them (the row showed ``x3x4``).  The cave now takes
  the separator and the colour tags from the already-loaded 2x/3x suffix
  strings with ``String.IndexOf``/``Substring``, and only uses the live ``x4``
  literal.
* The options click only saved PlayerPrefs; the live selector field
  (``[GameManager+0xa0]+0x20``) was only written by the StartBattle loader.
  A small cave at ``0xE95DB0`` writes it immediately, so the new speed is used
  by ``GameManager.Update`` without a restart.  That cave must preserve ``x8``:
  the caller loaded the PlayerPrefs key slot into it and re-reads it after the
  hook (see ``LIVE`` below).
* The pref key has two sites, not one.  ``UIIconBtn.InitBtn`` loads it at
  ``0xE93674`` and collapses the value with ``value == 1``, so a saved 2 came
  back as 0 on the next launch.  Cave P at ``0x20D3568`` stores the value
  verbatim for type 63 and replays the boolean conversion for other toggles.

The label cave always shows three states:
  2x: state0 + sep + greyTag + x4
  3x: state1 + sep + greyTag + x4
  4x: greyTag + state0 + sep + whiteTag + x4
where greyTag/whiteTag are the first/second tag of the 3x suffix.
"""

from __future__ import annotations

import json
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_REG
from hooks import annotate
from sites import guard

ROOT = Path(__file__).resolve().parents[2]   # repo root (tools/patchgen/)
SO = ROOT / "work" / "il2cpp" / "libil2cpp.so"
SPEC = ROOT / "patches" / "native_speed.json"
LITERALS = ROOT / "work" / "dump" / "stringliteral.json"

LABEL_HOOK = 0xE93738
LABEL_ORIG = 0xE93744
LABEL_RETURN = 0xE9386C
LABEL_CAVE = 0x20D1300

CYCLE_HOOK = 0xE94958
CYCLE_CAVE = 0x20D3500
CYCLE_RESUME = 0xE94964
CYCLE_TYPE = 63

APPLY_HOOK = 0xE95DB0
APPLY_RESUME = 0xE95DB4
APPLY_CAVE = 0x20D3540

# UIIconBtn.InitBtn loads the same pref key and remaps it to a bool
# (cmp w0,#1 / cset w8,eq), which turns a saved 2 back into 0.
LOAD_HOOK = 0xE93690           # cmp w0,#1
LOAD_CSET = 0xE93694           # cset w8,eq
LOAD_STORE = 0xE93698          # strb w8,[x19,#0x49]
LOAD_RESUME = 0xE9369C
LOAD_CAVE = 0x20D3568

CONCAT = 0xA17B48
SET_TEXT = 0xE89CD0
INDEX_CHAR = 0xA2FBA4
INDEX_CHAR_FROM = 0xA2FBBC
SUBSTRING = 0xA2D96C

SUFFIX_2X = 0x2A508E0          # toggle 0 suffix cell
SUFFIX_3X = 0x2A3B6F0          # toggle >= 1 suffix cell
X4 = 0x2BD3118                 # "x4"

EQ, NE, LT, GE, LE = 0, 1, 11, 10, 13


def b(pc: int, target: int) -> int:
    off = target - pc
    assert off % 4 == 0 and -(1 << 27) <= off < (1 << 27), hex(off)
    return 0x14000000 | ((off >> 2) & 0x03FFFFFF)


def bl(pc: int, target: int) -> int:
    off = target - pc
    assert off % 4 == 0 and -(1 << 27) <= off < (1 << 27), hex(off)
    return 0x94000000 | ((off >> 2) & 0x03FFFFFF)


def cbz32(pc: int, rt: int, target: int) -> int:
    off = target - pc
    assert off % 4 == 0 and -(1 << 20) <= off < (1 << 20), hex(off)
    return 0xB4000000 | (((off >> 2) & 0x7FFFF) << 5) | rt


def cbnz32(pc: int, rt: int, target: int) -> int:
    off = target - pc
    assert off % 4 == 0 and -(1 << 20) <= off < (1 << 20), hex(off)
    return 0xB5000000 | (((off >> 2) & 0x7FFFF) << 5) | rt


def bcond(pc: int, cond: int, target: int) -> int:
    off = target - pc
    assert off % 4 == 0 and -(1 << 20) <= off < (1 << 20), hex(off)
    return 0x54000000 | (((off >> 2) & 0x7FFFF) << 5) | cond


def adrp(pc: int, rd: int, page: int) -> int:
    imm = (page - (pc & ~0xFFF)) >> 12
    assert -(1 << 20) <= imm < (1 << 20), hex(imm)
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def ldr64(rt: int, rn: int, imm: int) -> int:
    assert imm % 8 == 0 and 0 <= imm < 0x8000
    return 0xF9400000 | ((imm // 8) << 10) | (rn << 5) | rt


def ldr32(rt: int, rn: int, imm: int) -> int:
    assert imm % 4 == 0 and 0 <= imm < 0x4000
    return 0xB9400000 | ((imm // 4) << 10) | (rn << 5) | rt


def ldrh(rt: int, rn: int, imm: int) -> int:
    assert imm % 2 == 0 and 0 <= imm < 0x8000
    return 0x79400000 | ((imm // 2) << 10) | (rn << 5) | rt


def ldrb(rt: int, rn: int, imm: int) -> int:
    return 0x39400000 | ((imm & 0xFFF) << 10) | (rn << 5) | rt


def strb(rt: int, rn: int, imm: int) -> int:
    return 0x39000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rt


def str_x_sp(rt: int, imm: int) -> int:
    return 0xF9000000 | ((imm // 8) << 10) | (31 << 5) | rt


def str_w_sp(rt: int, imm: int) -> int:
    return 0xB9000000 | ((imm // 4) << 10) | (31 << 5) | rt


def ldr_w_sp(rt: int, imm: int) -> int:
    return 0xB9400000 | ((imm // 4) << 10) | (31 << 5) | rt


def sub_sp(imm: int) -> int:
    return 0xD1000000 | (imm << 10) | (31 << 5) | 31


def add_sp(imm: int) -> int:
    return 0x91000000 | (imm << 10) | (31 << 5) | 31


def add_w_imm(rd: int, rn: int, imm: int) -> int:
    return 0x11000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def sub_w_imm(rd: int, rn: int, imm: int) -> int:
    return 0x51000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def movz_w(rd: int, imm: int) -> int:
    return 0x52800000 | ((imm & 0xFFFF) << 5) | rd


def mov_x(rd: int, rn: int) -> int:
    return 0xAA0003E0 | (rn << 16) | rd


def mov_w(rd: int, rn: int) -> int:
    return 0x2A0003E0 | (rn << 16) | rd


def ubfx(rd: int, rn: int, lsb: int, width: int) -> int:
    return 0x53000000 | (lsb << 16) | ((lsb + width - 1) << 10) | (rn << 5) | rd


def cmp32(rn: int, imm: int) -> int:
    return 0x71000000 | ((imm & 0xFFF) << 10) | (rn << 5) | 31


def build(base: int, items):
    labels: dict[str, int] = {}
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
            mnem, args = item[0], item[1:]
            resolved = [labels[a] if isinstance(a, str) else a for a in args]
            fn = {"b": b, "bl": bl, "cbz": cbz32, "cbnz": cbnz32,
                  "bcond": bcond, "adrp": adrp}[mnem]
            word = fn(pc, *resolved)
        else:
            word = item
        out.append((pc, word))
        pc += 4
    return out


def show(name: str, words) -> None:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    blob = b"".join(w.to_bytes(4, "little") for _, w in words)
    dis = list(md.disasm(blob, words[0][0]))
    assert len(dis) == len(words), (len(dis), len(words))
    print(f"== {name} ==")
    for (pc, w), ins in zip(words, dis):
        print(f"  {pc:#x}: {w:08x}  {ins.mnemonic:8} {ins.op_str}")


# Registers that must still hold their entry value when the cave branches back
# into the original function.  A hook that clobbers one of these silently
# corrupts whatever the continuation does next (that is how the x8 clobber in
# the apply cave turned PlayerPrefs.SetInt's key into a GameManager object).
LIVE = {LABEL_HOOK: {"x19"}, CYCLE_HOOK: {"x19"}, APPLY_HOOK: {"x8", "x19"},
        LOAD_HOOK: {"x19"}}

WRITE_DEST = {"mov", "movz", "movk", "movn", "add", "adds", "sub", "subs",
              "and", "ands", "orr", "eor", "ubfx", "sbfx", "csel", "cset",
              "lsl", "lsr", "asr", "sxtw", "uxtb", "uxth", "ldr", "ldrb",
              "ldrh", "ldrsw", "ldrsb", "ldrsh", "adrp", "adr", "mrs"}


def written_regs(words) -> set[str]:
    """64-bit names of the registers a cave writes as a destination."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    blob = b"".join(w.to_bytes(4, "little") for _, w in words)
    out: set[str] = set()
    for ins in md.disasm(blob, words[0][0]):
        if ins.mnemonic not in WRITE_DEST or not ins.operands:
            continue
        op = ins.operands[0]
        if op.type != ARM64_OP_REG:
            continue
        name = ins.reg_name(op.reg)
        # normalise w0 -> x0 so the live sets can be written once
        if name and name[0] == "w":
            name = "x" + name[1:]
        out.add(name)
    return out


def check_live(name: str, hook: int, words) -> None:
    clash = written_regs(words) & LIVE[hook]
    assert not clash, f"{name}: cave clobbers live register(s) {sorted(clash)}"


def label_cave():
    return build(LABEL_CAVE, [
        sub_sp(0x20),
        ldrh(8, 19, 0x48),
        ubfx(9, 8, 0, 8),
        ("cbz", 9, "plain"),
        ldr32(9, 19, 0x28),
        cmp32(9, CYCLE_TYPE),
        ("bcond", NE, "orig"),
        ubfx(10, 8, 8, 8),
        str_w_sp(10, 0x18),
        ldr64(20, 19, 0x38),
        # base = state 1 ? 3x suffix : 2x suffix (state 2 uses 2x + grey)
        cmp32(10, 1),
        ("bcond", EQ, "b1"),
        ("adrp", 8, SUFFIX_2X & ~0xFFF),
        ldr64(8, 8, SUFFIX_2X & 0xFFF),
        ("b", "b2"),
        ("label", "b1"),
        ("adrp", 8, SUFFIX_3X & ~0xFFF),
        ldr64(8, 8, SUFFIX_3X & 0xFFF),
        ("label", "b2"),
        ldr64(21, 8, 0),
        # tags from the 3x suffix
        ("adrp", 8, SUFFIX_3X & ~0xFFF),
        ldr64(8, 8, SUFFIX_3X & 0xFFF),
        ldr64(22, 8, 0),
        mov_x(0, 22),
        movz_w(1, 0x5B),
        mov_x(2, 31),
        ("bl", INDEX_CHAR),
        str_w_sp(0, 0x1C),
        cmp32(0, 0),
        ("bcond", LT, "no_tags"),
        mov_w(1, 0),
        mov_x(0, 22),
        movz_w(2, 8),
        mov_x(3, 31),
        ("bl", SUBSTRING),
        str_x_sp(0, 0),
        ldr_w_sp(2, 0x1C),
        add_w_imm(2, 2, 1),
        mov_x(0, 22),
        movz_w(1, 0x5B),
        mov_x(3, 31),
        ("bl", INDEX_CHAR_FROM),
        cmp32(0, 0),
        ("bcond", LT, "no_white"),
        mov_w(1, 0),
        mov_x(0, 22),
        movz_w(2, 8),
        mov_x(3, 31),
        ("bl", SUBSTRING),
        str_x_sp(0, 8),
        ("b", "tags_done"),
        ("label", "no_white"),
        mov_x(0, 22),
        mov_w(1, 31),
        mov_w(2, 31),
        mov_x(3, 31),
        ("bl", SUBSTRING),
        str_x_sp(0, 8),
        ("b", "tags_done"),
        ("label", "no_tags"),
        mov_x(0, 22),
        mov_w(1, 31),
        mov_w(2, 31),
        mov_x(3, 31),
        ("bl", SUBSTRING),
        str_x_sp(0, 0),
        mov_x(0, 22),
        mov_w(1, 31),
        mov_w(2, 31),
        mov_x(3, 31),
        ("bl", SUBSTRING),
        str_x_sp(0, 8),
        ("label", "tags_done"),
        # separator from the 2x suffix
        ("adrp", 8, SUFFIX_2X & ~0xFFF),
        ldr64(8, 8, SUFFIX_2X & 0xFFF),
        ldr64(22, 8, 0),
        mov_x(0, 22),
        movz_w(1, 0x2F),
        mov_x(2, 31),
        ("bl", INDEX_CHAR),
        cmp32(0, 1),
        ("bcond", LT, "sep_empty"),
        sub_w_imm(1, 0, 1),
        mov_x(0, 22),
        movz_w(2, 3),
        mov_x(3, 31),
        ("bl", SUBSTRING),
        ("b", "sep_done"),
        ("label", "sep_empty"),
        mov_x(0, 22),
        mov_w(1, 31),
        mov_w(2, 31),
        mov_x(3, 31),
        ("bl", SUBSTRING),
        ("label", "sep_done"),
        str_x_sp(0, 0x10),
        # state 2: greyTag + 2x suffix
        ldr_w_sp(10, 0x18),
        cmp32(10, 2),
        ("bcond", NE, "base_ready"),
        ldr64(1, 31, 0),
        mov_x(2, 21),
        mov_x(0, 31),
        mov_x(3, 31),
        ("bl", CONCAT),
        mov_x(21, 0),
        ("label", "base_ready"),
        # base + sep
        mov_x(1, 21),
        ldr64(2, 31, 0x10),
        mov_x(0, 31),
        mov_x(3, 31),
        ("bl", CONCAT),
        mov_x(21, 0),
        # + tag (grey for 2x/3x, white for 4x)
        ldr64(2, 31, 0),
        ldr_w_sp(10, 0x18),
        cmp32(10, 2),
        ("bcond", NE, "tag_ready"),
        ldr64(2, 31, 8),
        ("label", "tag_ready"),
        mov_x(1, 21),
        mov_x(0, 31),
        mov_x(3, 31),
        ("bl", CONCAT),
        mov_x(21, 0),
        # + x4
        ("adrp", 8, X4 & ~0xFFF),
        ldr64(2, 8, X4 & 0xFFF),
        mov_x(1, 21),
        mov_x(0, 31),
        mov_x(3, 31),
        ("bl", CONCAT),
        # label.text + suffix
        mov_x(21, 0),
        ldr64(1, 20, 0x180),
        mov_x(2, 21),
        mov_x(0, 31),
        mov_x(3, 31),
        ("bl", CONCAT),
        mov_x(1, 0),
        mov_x(0, 20),
        ("bl", SET_TEXT),
        ("b", "ret2"),
        ("label", "plain"),
        add_sp(0x20),
        ("b", LABEL_RETURN),
        ("label", "orig"),
        add_sp(0x20),
        ("b", LABEL_ORIG),
        ("label", "ret2"),
        add_sp(0x20),
        ("b", LABEL_RETURN),
    ])


def cycle_cave():
    return build(CYCLE_CAVE, [
        ldr32(9, 19, 0x28),
        cmp32(9, CYCLE_TYPE),
        ("bcond", NE, "simple"),
        0x11000508,                    # add w8,w8,#1
        0x71000D1F,                    # cmp w8,#3
        0x1A8803E8,                    # csel w8,wzr,w8,eq
        ("b", "store"),
        ("label", "simple"),
        0x52000108,                    # eor w8,w8,#1
        ("label", "store"),
        strb(8, 19, 0x49),
        mov_x(0, 19),
        ("b", CYCLE_RESUME),
    ])


def apply_cave():
    # x8 is live here: the caller loaded the PlayerPrefs key slot into it at
    # 0xE95DA8 and re-reads it at 0xE95DBC (ldr x1,[x8]).  Clobbering x8 made
    # SetInt receive *(static_fields) -- the GameManager instance -- as the key
    # string and crashed the process.  Use x9/x10 instead.
    return build(APPLY_CAVE, [
        ldrb(2, 19, 0x49),
        ldr32(10, 19, 0x28),
        cmp32(10, CYCLE_TYPE),
        ("bcond", NE, "skip"),
        ("adrp", 9, 0x2AB8000),
        ldr64(9, 9, 0xD38),
        ldr64(9, 9, 0),
        ldr64(9, 9, 0xA0),
        strb(2, 9, 0x20),
        ("label", "skip"),
        ("b", APPLY_RESUME),
    ])


def load_cave():
    """Restore the saved speed verbatim (0/1/2) instead of (value == 1)."""
    return build(LOAD_CAVE, [
        ldr32(8, 19, 0x28),
        cmp32(8, CYCLE_TYPE),
        ("bcond", NE, "plain"),
        # clamp to 0..2 so a malformed pref cannot produce a nonsense state
        cmp32(0, 2),
        ("bcond", LE, "clamp_lo"),
        movz_w(0, 2),
        ("label", "clamp_lo"),
        cmp32(0, 0),
        ("bcond", GE, "store"),
        mov_w(0, 31),
        ("b", "store"),
        # every other toggle keeps the original boolean conversion
        ("label", "plain"),
        cmp32(0, 1),
        0x1A9F17E8,                    # cset w8,eq
        mov_w(0, 8),
        ("label", "store"),
        strb(0, 19, 0x49),
        ("b", LOAD_RESUME),
    ])


def blob(words) -> bytes:
    return b"".join(w.to_bytes(4, "little") for _, w in words)


def main() -> int:
    so = SO.read_bytes()
    assert so[LABEL_HOOK:LABEL_HOOK + 4] == bytes.fromhex("68924079"), "label hook"
    assert so[APPLY_HOOK:APPLY_HOOK + 4] == bytes.fromhex("62264139"), "apply hook"
    assert so[CYCLE_HOOK:CYCLE_HOOK + 4] == bytes.fromhex("08010052"), "cycle hook"
    assert so[LOAD_HOOK:LOAD_HOOK + 4] == bytes.fromhex("1f040071"), "load hook"
    assert so[LOAD_CSET:LOAD_CSET + 4] == bytes.fromhex("e8179f1a"), "load cset"
    assert so[LOAD_STORE:LOAD_STORE + 4] == bytes.fromhex("68260139"), "load store"
    assert all(x == 0 for x in so[LABEL_CAVE:LABEL_CAVE + 0x230]), "label cave"
    assert all(x == 0 for x in so[CYCLE_CAVE:CYCLE_CAVE + 0x40]), "cycle cave"
    assert all(x == 0 for x in so[APPLY_CAVE:APPLY_CAVE + 0x40]), "apply cave"
    assert all(x == 0 for x in so[LOAD_CAVE:LOAD_CAVE + 0x60]), "load cave"

    literals = {int(e["address"], 16): e["value"] for e in
                json.loads(LITERALS.read_text(encoding="utf-8-sig"))}
    assert literals.get(X4) == "x4"

    lab = label_cave()
    cyc = cycle_cave()
    app = apply_cave()
    lod = load_cave()
    show("speed label", lab)
    show("speed cycle", cyc)
    show("speed live-state", app)
    show("speed load", lod)
    check_live("label", LABEL_HOOK, lab)
    check_live("cycle", CYCLE_HOOK, cyc)
    check_live("apply", APPLY_HOOK, app)
    check_live("load", LOAD_HOOK, lod)
    assert len(blob(lab)) <= 0x230, len(blob(lab))
    print(f"label {len(blob(lab))}B, cycle {len(blob(cyc))}B, apply {len(blob(app))}B, "
          f"load {len(blob(lod))}B")

    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    spec["enabled"] = True
    spec["_comment"] = (
        "3-state battle speed (2x/3x/4x). Cave A maps GameManager.Update state "
        "0/1/2 to timeScale*2/3/4. Cave B is gated on UIIconBtn.Type 63. The "
        "label cave shows all three values, taking the separator and colour "
        "tags from the live 2x/3x suffix strings (standalone literal slots are "
        "not initialized at that point). The apply cave writes the live state "
        "field on click, so 4x applies without a restart."
    )
    drop = {hex(LABEL_HOOK), hex(LABEL_CAVE), hex(APPLY_HOOK), hex(APPLY_CAVE),
            hex(CYCLE_HOOK), hex(CYCLE_CAVE), hex(LOAD_HOOK), hex(LOAD_CSET),
            hex(LOAD_STORE), hex(LOAD_CAVE), "0x20c8a00", "0x20d3000"}
    keep = [p for p in spec["patches"] if p["offset"].lower() not in drop]
    for p in keep:
        if p["offset"].lower() == hex(CYCLE_HOOK):
            p["patch"] = b(CYCLE_HOOK, CYCLE_CAVE).to_bytes(4, "little").hex()
        if p["offset"].lower() == "0xd9cf68":
            # GameManager.Update keeps the metadata slot in x21 across the
            # class-init call, so cave A must not touch it.
            p["live"] = "x21"
            p["hook"] = True
            p["targets"] = [hex(0xD9CF6C), hex(0xD9CF98), hex(0xD9CEC8)]
    keep += [
        {"offset": hex(CYCLE_HOOK), **guard(so[CYCLE_HOOK:CYCLE_HOOK + 4]),
         "patch": b(CYCLE_HOOK, CYCLE_CAVE).to_bytes(4, "little").hex(),
         "live": "x19", "hook": True, "targets": [hex(CYCLE_RESUME)],
         "note": "toggle prologue -> cycle cave (type 63 only)"},
        {"offset": hex(LABEL_HOOK), **guard(so[LABEL_HOOK:LABEL_HOOK + 4]),
         "patch": b(LABEL_HOOK, LABEL_CAVE).to_bytes(4, "little").hex(),
         "live": "x19", "hook": True, "targets": [hex(LABEL_ORIG), hex(LABEL_RETURN)],
         "literal_risk": [hex(X4)],
         "note": "UpdateBtn -> label cave (all three speed values)"},
        {"offset": hex(LABEL_CAVE), **guard(b"\x00" * len(blob(lab))),
         "patch": blob(lab).hex(), "note": "label cave: live suffix separator/tags"},
        {"offset": hex(APPLY_HOOK), **guard(so[APPLY_HOOK:APPLY_HOOK + 4]),
         "patch": b(APPLY_HOOK, APPLY_CAVE).to_bytes(4, "little").hex(),
         "live": "x8,x19", "hook": True, "targets": [hex(APPLY_RESUME)],
         "note": "speed save -> live-state cave; x8 holds the prefs key slot"},
        {"offset": hex(APPLY_CAVE), **guard(b"\x00" * len(blob(app))),
         "patch": blob(app).hex(), "note": "write live moreFasterFastForward"},
        {"offset": hex(CYCLE_CAVE), **guard(b"\x00" * len(blob(cyc))),
         "patch": blob(cyc).hex(), "note": "type 63 cycles 0/1/2; others 0/1"},
        {"offset": hex(LOAD_HOOK), **guard(so[LOAD_HOOK:LOAD_HOOK + 4]),
         "patch": b(LOAD_HOOK, LOAD_CAVE).to_bytes(4, "little").hex(),
         "live": "x19", "hook": True, "targets": [hex(LOAD_RESUME)],
         "note": "InitBtn: GetInt(key) -> load cave (restore 0..2 verbatim)"},
        {"offset": hex(LOAD_CSET), **guard(so[LOAD_CSET:LOAD_CSET + 4]),
         "patch": "1f2003d5", "note": "drop (value == 1) bool conversion"},
        {"offset": hex(LOAD_STORE), **guard(so[LOAD_STORE:LOAD_STORE + 4]),
         "patch": "1f2003d5", "note": "drop duplicate toggle store"},
        {"offset": hex(LOAD_CAVE), **guard(b"\x00" * len(blob(lod))),
         "patch": blob(lod).hex(),
         "note": "type 63 stores raw 0..2; other toggles keep (value == 1)"},
    ]
    spec["patches"] = keep
    spec["prefs_keys"] = [
        {
            "name": "battle speed / moreFasterFastForward",
            "slot": "0x2AAA660",
            "sites": [
                {"ref": hex(LOAD_HOOK - 0x1C), "patched": hex(LOAD_HOOK),
                 "role": "UIIconBtn.InitBtn loads it (was value == 1)"},
                {"ref": hex(APPLY_HOOK - 8), "patched": hex(APPLY_HOOK),
                 "role": "UIIconBtn.OnClickBtn saves it"},
                {"ref": "0xcf9e2c", "patched": "0xcf9e78",
                 "role": "BattleManager.<StartBattle>c__Iterator6.MoveNext re-reads the stored state"},
            ],
        }
    ]
    annotate(spec)
    SPEC.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    print("wrote", SPEC.relative_to(ROOT))

    written = json.loads(SPEC.read_text(encoding="utf-8"))
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    want = {LABEL_HOOK: LABEL_CAVE, CYCLE_HOOK: CYCLE_CAVE,
            APPLY_HOOK: APPLY_CAVE}
    for p in written["patches"]:
        off = int(p["offset"], 16)
        if off in want:
            ins = list(md.disasm(bytes.fromhex(p["patch"]), off))[0]
            assert ins.op_str == f"#{want[off]:#x}", (hex(off), ins.op_str)
            print(f"hook {off:#x} -> {ins.op_str}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
