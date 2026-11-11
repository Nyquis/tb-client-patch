#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Generate patches/native_options.json.

Repurposes the Options "Help" row (UIIconBtn type 27) as an Auto Play toggle.

* Label: titles[27] = UI_MULTIPLAY_REGION_AUTO (450) -> "Auto".
* Toggle state: PlayerPrefs mask bit 3 under the version-verifier literal
  ("versionVerify_terra_battle_mistwalker", cell 0x2BDC668). The old Everyplay
  key is unusable: its setter writes only 0/1 at the title and wipes the mask.
* Click: flips bit 3 from the mask; when enabling, clears bit 2 (manual defeat).
  The in-game KILL button then becomes STOP.

The row is deliberately kept as a *plain* row (isToggleBtn = 0).  The built-in
toggle mode makes OnClickBtn flip `toggle` and call UpdateBtn *before* the type
dispatch; that toggle-specific UpdateBtn path is what broke type 27 in practice
while the plain Sound/Music rows worked.  The Auto state is therefore handled
entirely by our own hooks:

* 0xE9349C (the `bl UpdateBtn` at the end of InitBtn's default path): set the
  label, keep isToggleBtn = 0, call UpdateBtn for the text, then paint
  red/white from mask bit 3.
* 0xE95218 (the type-27 OnClickBtn case): toggle bit 3 in the mask, save, and
  repaint.  With isToggleBtn = 0 the prologue skips its UpdateBtn branch and
  dispatches straight here, exactly like the working plain rows.
"""

from __future__ import annotations

import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from hooks import annotate
from sites import guard

ROOT = Path(__file__).resolve().parents[2]   # repo root (tools/patchgen/)
SO = ROOT / "work" / "il2cpp" / "libil2cpp.so"

INIT_END_HOOK = 0xE9349C   # bl UpdateBtn at the end of InitBtn's default path
INIT_END_RESUME = 0xE934A0
CLICK_HOOK = 0xE95218      # first insn of UIIconBtn.OnClickBtn Help case
CLICK_EPILOGUE = 0xE965E4
UPDATE_BTN = 0xE936A4
CAVE_BASE = 0x20D2E00

PREF_GET_INT = 0x1FA6AB8
PREF_SET_INT = 0x1FA6A10
PREF_SAVE = 0x1FA6EE4
GET_RED = 0x1D64618
GET_WHITE = 0x1D64640
SET_COLOR = 0xE93AD8
SET_SPRITE_NAME = 0xD5543C
ICON_BATTLE_HI = 0x2BE0000
ICON_BATTLE_LO = 0x5C8
MASK_CELL_HI = 0x2BDC000
MASK_CELL_LO = 0x668
TYPE_HELP = 27
TITLE_AUTO = 450


def b(pc, target):
    off = target - pc
    assert off % 4 == 0 and -(1 << 27) <= off < (1 << 27)
    return 0x14000000 | ((off >> 2) & 0x03FFFFFF)


def bl(pc, target):
    off = target - pc
    assert off % 4 == 0 and -(1 << 27) <= off < (1 << 27)
    return 0x94000000 | ((off >> 2) & 0x03FFFFFF)


def bcond(pc, cond, target):
    off = target - pc
    return 0x54000000 | (((off >> 2) & 0x7FFFF) << 5) | cond


def cbz(pc, rt, target, wide):
    off = target - pc
    return (0xB4000000 if wide else 0x34000000) | (((off >> 2) & 0x7FFFF) << 5) | rt


def cbnz(pc, rt, target, wide):
    off = target - pc
    return (0xB5000000 if wide else 0x35000000) | (((off >> 2) & 0x7FFFF) << 5) | rt


def adrp(pc, rd, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def ldr64(rt, rn, imm):
    return 0xF9400000 | ((imm // 8) << 10) | (rn << 5) | rt


def str64(rt, rn, imm):
    return 0xF9000000 | ((imm // 8) << 10) | (rn << 5) | rt


def ldr32(rt, rn, imm):
    return 0xB9400000 | ((imm // 4) << 10) | (rn << 5) | rt


def ldrb(rt, rn, imm):
    return 0x39400000 | ((imm & 0xFFF) << 10) | (rn << 5) | rt


def strb(rt, rn, imm):
    return 0x39000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rt


def str32(rt, rn, imm):
    return 0xB9000000 | ((imm // 4) << 10) | (rn << 5) | rt


def movz32(rd, imm):
    return 0x52800000 | ((imm & 0xFFFF) << 5) | rd


def mov_x(rd, rn):
    return 0xAA0003E0 | (rn << 16) | rd


def mov_w(rd, rn):
    return 0x2A0003E0 | (rn << 16) | rd


def cmp32(rn, imm):
    return 0x71000000 | ((imm & 0xFFF) << 10) | (rn << 5) | 31


def add64(rd, rn, imm):
    return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def ubfx(rd, rn, lsb, width):
    return 0x53000000 | ((lsb & 0x1F) << 16) | (((lsb + width - 1) & 0x1F) << 10) | (rn << 5) | rd


def orr32(rd, rn, rm):
    return 0x2A000000 | (rm << 16) | (rn << 5) | rd


def bic32(rd, rn, rm):
    return 0x0A200000 | (rm << 16) | (rn << 5) | rd


def stp_pre(rt, rt2, rn, imm):
    return 0xA9800000 | (((imm // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def stp_off(rt, rt2, rn, imm):
    return 0xA9000000 | (((imm // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def ldp_off(rt, rt2, rn, imm):
    return 0xA9400000 | (((imm // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def ldp_post(rt, rt2, rn, imm):
    return 0xA8C00000 | (((imm // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


class Asm:
    def __init__(self, base):
        self.base = base
        self.pc = base
        self.words = []
        self.labels = {}
        self.fix = []

    def label(self, name):
        self.labels[name] = self.pc

    def emit(self, w):
        self.words.append((self.pc, w))
        self.pc += 4

    def ref(self, mnem, *args):
        self.fix.append((len(self.words), mnem, args, self.pc))
        self.words.append((self.pc, 0))
        self.pc += 4

    def finish(self):
        for idx, mnem, args, at in self.fix:
            r = [self.labels[a] if isinstance(a, str) else a for a in args]
            if mnem == "b":
                w = b(at, r[0])
            elif mnem == "bl":
                w = bl(at, r[0])
            elif mnem == "bcond":
                w = bcond(at, r[0], r[1])
            elif mnem == "cbz32":
                w = cbz(at, r[0], r[1], False)
            elif mnem == "cbz64":
                w = cbz(at, r[0], r[1], True)
            elif mnem == "cbnz32":
                w = cbnz(at, r[0], r[1], False)
            elif mnem == "cbnz64":
                w = cbnz(at, r[0], r[1], True)
            else:
                raise ValueError(mnem)
            self.words[idx] = (at, w)
        return b"".join(w.to_bytes(4, "little") for _, w in self.words)

    def show(self, name):
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        blob = b"".join(w.to_bytes(4, "little") for _, w in self.words)
        print(f"== {name} ==")
        for (pc, w), ins in zip(self.words, md.disasm(blob, self.base)):
            print(f"  {pc:#x}: {w:08x}  {ins.mnemonic:8} {ins.op_str}")


def emit_read_mask(a, zero, after):
    a.emit(adrp(a.pc, 8, MASK_CELL_HI))
    a.emit(add64(8, 8, MASK_CELL_LO))
    a.emit(ldr64(1, 8, 0))
    a.ref("cbz64", 1, zero)
    a.emit(mov_x(0, 31))
    a.emit(movz32(2, 0))
    a.emit(mov_x(3, 31))
    a.ref("bl", PREF_GET_INT)
    a.ref("b", after)
    a.label(zero)
    a.emit(movz32(0, 0))
    a.label(after)


def emit_write_mask(a, done, val_reg):
    a.emit(adrp(a.pc, 8, MASK_CELL_HI))
    a.emit(add64(8, 8, MASK_CELL_LO))
    a.emit(ldr64(1, 8, 0))
    a.ref("cbz64", 1, done)
    a.emit(mov_x(0, 31))
    a.emit(mov_w(2, val_reg))
    a.emit(mov_x(3, 31))
    a.ref("bl", PREF_SET_INT)
    a.emit(mov_x(0, 31))
    a.emit(mov_x(1, 31))
    a.ref("bl", PREF_SAVE)
    a.label(done)


def build_init_end(base):
    """End of InitBtn's default path: label + Auto colour, keep it a plain row."""
    a = Asm(base)
    a.emit(stp_pre(29, 30, 31, -0x20))
    a.emit(ldr32(8, 19, 0x28))          # type
    a.emit(cmp32(8, TYPE_HELP))
    a.ref("bcond", 1, "original")       # NE
    a.emit(ldr64(9, 19, 0x20))          # titles[]
    a.ref("cbz64", 9, "have_title")
    a.emit(movz32(10, TITLE_AUTO))
    a.emit(str32(10, 9, 0x8C))          # titles[27] = 450
    a.label("have_title")
    # Plain-row mode: OnClickBtn must not take its toggle/UpdateBtn branch.
    a.emit(movz32(10, 0))
    a.emit(strb(10, 19, 0x48))          # isToggleBtn = 0
    a.emit(strb(10, 19, 0x49))          # toggle = 0
    a.emit(mov_x(0, 19))
    a.ref("bl", UPDATE_BTN)             # sets the label text only
    # Auto icon: the Options rows use the button atlas, which contains both
    # icon_hints_tips (the old Help icon) and icon_battle (crossed swords).
    a.emit(ldr64(0, 19, 0x30))          # UISprite icon
    a.ref("cbz64", 0, "icon_done")
    a.emit(adrp(a.pc, 8, ICON_BATTLE_HI))
    a.emit(add64(8, 8, ICON_BATTLE_LO))
    a.emit(ldr64(1, 8, 0))
    a.ref("bl", SET_SPRITE_NAME)
    a.label("icon_done")
    emit_read_mask(a, "i_zero", "i_after")
    a.emit(ubfx(9, 0, 3, 1))
    a.emit(strb(9, 19, 0x49))           # keep toggle in sync for reference
    a.ref("cbz32", 9, "i_white")
    a.ref("bl", GET_RED)
    a.ref("b", "i_apply")
    a.label("i_white")
    a.ref("bl", GET_WHITE)
    a.label("i_apply")
    a.emit(mov_x(0, 19))
    a.ref("bl", SET_COLOR)
    a.ref("b", "done")
    a.label("original")
    a.emit(mov_x(0, 19))
    a.ref("bl", UPDATE_BTN)
    a.label("done")
    a.emit(ldp_post(29, 30, 31, 0x20))
    a.ref("b", INIT_END_RESUME)
    return a


def build_click(base):
    a = Asm(base)
    a.emit(stp_pre(29, 30, 31, -0x20))
    emit_read_mask(a, "c_zero", "c_after")
    a.emit(mov_w(16, 0))                # mask
    a.emit(ubfx(17, 16, 3, 1))          # current AUTO
    a.ref("cbnz32", 17, "disable")
    # enable: set bit 3, clear manual bit 2
    a.emit(movz32(17, 8))
    a.emit(orr32(16, 16, 17))
    a.emit(movz32(17, 4))
    a.emit(bic32(16, 16, 17))
    a.emit(movz32(9, 1))                # new toggle
    a.ref("b", "write")
    a.label("disable")
    a.emit(movz32(17, 0xC))
    a.emit(bic32(16, 16, 17))           # clear bits 3 and 2
    a.emit(movz32(9, 0))
    a.label("write")
    a.emit(str32(9, 31, 0x10))          # save new toggle across PlayerPrefs
    a.emit(mov_w(0, 16))
    emit_write_mask(a, "c_wdone", 16)
    a.emit(ldr32(9, 31, 0x10))
    a.emit(strb(9, 19, 0x49))           # keep toggle in sync for reference
    a.emit(strb(31, 19, 0x48))          # isToggleBtn = 0 (plain row)
    a.ref("cbz32", 9, "white")
    a.ref("bl", GET_RED)
    a.ref("b", "apply")
    a.label("white")
    a.ref("bl", GET_WHITE)
    a.label("apply")
    a.emit(mov_x(0, 19))
    a.ref("bl", SET_COLOR)
    a.emit(ldp_post(29, 30, 31, 0x20))
    a.ref("b", CLICK_EPILOGUE)
    return a


def main() -> int:
    so = SO.read_bytes()
    assert so[INIT_END_HOOK:INIT_END_HOOK + 4] == bytes.fromhex("82000094"), "init-end hook"
    assert so[CLICK_HOOK:CLICK_HOOK + 4] == bytes.fromhex("13e100f0"), "click hook"
    assert all(x == 0 for x in so[CAVE_BASE:CAVE_BASE + 400]), "cave not zero"

    init_a = build_init_end(CAVE_BASE)
    init_blob = init_a.finish()
    click_base = (CAVE_BASE + len(init_blob) + 0xF) & ~0xF
    click_a = build_click(click_base)
    click_blob = click_a.finish()
    end = click_base + len(click_blob)
    assert end <= 0x20D3198, hex(end)

    init_a.show("options init end")
    click_a.show("options click")

    spec = {
        "_comment": (
            "Options 'Help' row (UIIconBtn type 27) repurposed as Auto Play. "
            "Label titles[27] = UI_MULTIPLAY_REGION_AUTO (450). State is mask "
            "bit 3 under the version-verifier literal (0x2BDC668), not the "
            "Everyplay key (its 0/1 setter wipes the mask); "
            "enabling Auto clears the one-hit bit (bit 2). The row is kept as a "
            "plain row (isToggleBtn=0) because the built-in toggle prologue "
            "runs UpdateBtn before the type dispatch (the failing path for "
            "type 27). 0xE9349C sets the label/colour at the end of InitBtn; "
            "0xE95218 toggles the mask from the click case."
        ),
        "enabled": True,
        "patches": [
            {
                "offset": hex(INIT_END_HOOK),
                **guard(so[INIT_END_HOOK:INIT_END_HOOK + 4]),
                "patch": b(INIT_END_HOOK, CAVE_BASE).to_bytes(4, "little").hex(),
                "note": "InitBtn default tail: type-27 Auto label/colour, plain-row mode",
            },
            {
                "offset": hex(CLICK_HOOK),
                **guard(so[CLICK_HOOK:CLICK_HOOK + 4]),
                "patch": b(CLICK_HOOK, click_base).to_bytes(4, "little").hex(),
                "note": "OnClickBtn Help case: toggle Auto from the mask, persist",
            },
            {
                "offset": hex(CAVE_BASE),
                **guard(b"\x00" * len(init_blob)),
                "patch": init_blob.hex(),
                "note": "options init-end cave",
            },
            {
                "offset": hex(click_base),
                **guard(b"\x00" * len(click_blob)),
                "patch": click_blob.hex(),
                "note": "options click cave",
            },
        ],
    }
    out = ROOT / "patches" / "native_options.json"
    annotate(spec)
    out.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {out.relative_to(ROOT)}")
    print(f"  init end {len(init_blob)}B @ {CAVE_BASE:#x}")
    print(f"  click    {len(click_blob)}B @ {click_base:#x} end {end:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
