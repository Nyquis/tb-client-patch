#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Generate patches/native_time.json.

Three toggles in the in-battle menu:
  * KamcordShare    (type 28) -> DebugManager.enableTestZClass (+0x25) -> one-hit enemies
  * KamcordStartRec (type 30) -> DebugManager.higeTest (+0x11)  -> infinite time
  * KamcordStopRec  (type 29) -> DebugManager.higeMiniTest (+0x12)
        -> TutorialManager.SetMutekiFlag(Party) -> Entity.isMuteki
All buttons survive the Everyplay gate and the StartBattle disable flags, all show
red (on) / white (off) when the menu is reopened, and all persist across restarts.
"""

from __future__ import annotations

import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from hooks import annotate
from sites import guard

ROOT = Path(__file__).resolve().parents[2]   # repo root (tools/patchgen/)
SO = ROOT / "work" / "il2cpp" / "libil2cpp.so"
RET = 0xD65F03C0


def b(pc, target):
    off = target - pc
    assert off % 4 == 0 and -(1 << 27) <= off < (1 << 27), (hex(pc), hex(target))
    return 0x14000000 | ((off >> 2) & 0x03FFFFFF)


def bl(pc, target):
    off = target - pc
    assert off % 4 == 0 and -(1 << 27) <= off < (1 << 27), (hex(pc), hex(target))
    return 0x94000000 | ((off >> 2) & 0x03FFFFFF)


def bcond(pc, cond, target):
    off = target - pc
    assert off % 4 == 0 and -(1 << 20) <= off < (1 << 20)
    return 0x54000000 | (((off >> 2) & 0x7FFFF) << 5) | cond


def cbz(pc, rt, target, wide):
    off = target - pc
    base = 0xB4000000 if wide else 0x34000000
    return base | (((off >> 2) & 0x7FFFF) << 5) | rt


def cbnz(pc, rt, target, wide):
    off = target - pc
    base = 0xB5000000 if wide else 0x35000000
    return base | (((off >> 2) & 0x7FFFF) << 5) | rt


def adrp(pc, rd, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def ldr64(rt, rn, imm):
    return 0xF9400000 | ((imm // 8) << 10) | (rn << 5) | rt


def ldr32(rt, rn, imm):
    return 0xB9400000 | ((imm // 4) << 10) | (rn << 5) | rt


def str32(rt, rn, imm):
    return 0xB9000000 | ((imm // 4) << 10) | (rn << 5) | rt


def ldrb(rt, rn, imm):
    return 0x39400000 | ((imm & 0xFFF) << 10) | (rn << 5) | rt


def strb(rt, rn, imm):
    return 0x39000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rt


def eor32(rd, rn, imm):
    return 0x52000000 | (rn << 5) | rd


def movz32(rd, imm):
    return 0x52800000 | ((imm & 0xFFFF) << 5) | rd


def mov_x(rd, rn):
    return 0xAA0003E0 | (rn << 16) | rd


def mov_w(rd, rn):
    return 0x2A0003E0 | (rn << 16) | rd


def cmp32(rn, imm):
    return 0x71000000 | ((imm & 0xFFF) << 10) | (rn << 5) | 31


def sub32(rd, rn, imm):
    return 0x51000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def add64(rd, rn, imm):
    return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def add32(rd, rn, imm):
    return 0x11000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def cmp_reg(rn, rm):
    return 0x6B000000 | (rm << 16) | (rn << 5) | 31


def stp_pre(rt, rt2, rn, imm):
    return 0xA9800000 | (((imm // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def stp_off(rt, rt2, rn, imm):
    return 0xA9000000 | (((imm // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def ldp_off(rt, rt2, rn, imm):
    return 0xA9400000 | (((imm // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def ldp_post(rt, rt2, rn, imm):
    return 0xA8C00000 | (((imm // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def add_sp(imm):
    return 0x910003FF | ((imm & 0xFFF) << 10)


def orr32(rd, rn, rm):
    return 0x2A000000 | (rm << 16) | (rn << 5) | rd


def bic32(rd, rn, rm):
    return 0x0A200000 | (rm << 16) | (rn << 5) | rd


def tbnz(pc, rt, bit, target):
    off = target - pc
    assert off % 4 == 0 and -(1 << 14) <= (off >> 2) < (1 << 14)
    return 0x37000000 | (bit << 26) | (((off >> 2) & 0x3FFF) << 5) | rt


def tbz(pc, rt, bit, target):
    off = target - pc
    assert off % 4 == 0 and -(1 << 14) <= (off >> 2) < (1 << 14)
    return 0x36000000 | (bit << 26) | (((off >> 2) & 0x3FFF) << 5) | rt


def add_reg32(rd, rn, rm):
    return 0x0B000000 | (rm << 16) | (rn << 5) | rd


def ubfx(rd, rn, lsb, width):
    return 0x53000000 | ((lsb & 0x1F) << 16) | (((lsb + width - 1) & 0x1F) << 10) | (rn << 5) | rd


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
            resolved = [self.labels[a] if isinstance(a, str) else a for a in args]
            if mnem == "b":
                w = b(at, resolved[0])
            elif mnem == "bl":
                w = bl(at, resolved[0])
            elif mnem == "bcond":
                w = bcond(at, *resolved)
            elif mnem == "cbz32":
                w = cbz(at, *resolved, False)
            elif mnem == "cbz64":
                w = cbz(at, *resolved, True)
            elif mnem == "cbnz32":
                w = cbnz(at, *resolved, False)
            elif mnem == "cbnz64":
                w = cbnz(at, *resolved, True)
            elif mnem == "tbnz":
                w = tbnz(at, *resolved)
            elif mnem == "tbz":
                w = tbz(at, *resolved)
            else:
                raise ValueError(mnem)
            self.words[idx] = (at, w)
        return b"".join(w.to_bytes(4, "little") for _, w in self.words)

    def show(self, name):
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        blob = b"".join(w.to_bytes(4, "little") for _, w in self.words)
        dis = list(md.disasm(blob, self.words[0][0]))
        print(f"== {name} ==")
        for (pc, w), ins in zip(self.words, dis):
            print(f"  {pc:#x}: {w:08x}  {ins.mnemonic:8} {ins.op_str}")
        assert len(dis) == len(self.words), (len(dis), len(self.words))


def read_words(so, start, count):
    return [(start + i * 4, int.from_bytes(so[start + i * 4:start + i * 4 + 4], "little"))
            for i in range(count)]


def emit_read_mask(a, zero_label, after_label):
    """Inline PlayerPrefs.GetInt(versionVerify_terra_battle_mistwalker, 0) -> w0."""
    a.emit(adrp(a.pc, 8, 0x2BDC000))
    a.emit(add64(8, 8, 0x668))
    a.emit(ldr64(1, 8, 0))
    a.ref("cbz64", 1, zero_label)
    a.emit(mov_x(0, 31))
    a.emit(movz32(2, 0))
    a.emit(mov_x(3, 31))
    a.ref("bl", 0x1FA6AB8)
    a.ref("b", after_label)
    a.label(zero_label)
    a.emit(movz32(0, 0))
    a.label(after_label)


def emit_write_mask(a, done_label, val_reg):
    """Inline PlayerPrefs.SetInt/Save(mask in val_reg)."""
    a.emit(adrp(a.pc, 8, 0x2BDC000))
    a.emit(add64(8, 8, 0x668))
    a.emit(ldr64(1, 8, 0))
    a.ref("cbz64", 1, done_label)
    a.emit(mov_x(0, 31))
    a.emit(mov_w(2, val_reg))
    a.emit(mov_x(3, 31))
    a.ref("bl", 0x1FA6A10)
    a.emit(mov_x(0, 31))
    a.emit(mov_x(1, 31))
    a.ref("bl", 0x1FA6EE4)
    a.label(done_label)


def main() -> int:
    so = SO.read_bytes()
    caves = {}

    def cave(name, base):
        a = Asm(base)
        caves[name] = (a, base)
        return a

    # ---- cave 1: time-limited chapters, skip currentRemainTime store ----
    a = cave("cave1", 0x20C8A20)
    a.emit(adrp(a.pc, 8, 0x2A99000))
    a.emit(ldr64(8, 8, 0x570))
    a.emit(ldr64(8, 8, 0x0))
    a.emit(ldr64(8, 8, 0xA0))
    a.ref("cbz64", 8, "store")
    a.emit(ldrb(9, 8, 0x11))
    a.ref("cbnz32", 9, "skip")
    a.label("store")
    a.emit(0xBD025A61)                 # str s1,[x19,#0x258]
    a.label("skip")
    a.ref("b", 0xCC84C4)
    a.finish(); a.show("cave1")

    # ---- cave 2: normal chapters, skip the drag-time path ----
    a = cave("cave2", 0x20C8A60)
    a.ref("bcond", 0xC, "run_limited")  # GT
    a.emit(adrp(a.pc, 8, 0x2A99000))
    a.emit(ldr64(8, 8, 0x570))
    a.emit(ldr64(8, 8, 0x0))
    a.emit(ldr64(8, 8, 0xA0))
    a.ref("cbz64", 8, "run_drag")
    a.emit(ldrb(9, 8, 0x11))
    a.ref("cbnz32", 9, "skip")
    a.label("run_drag")
    a.ref("b", 0xCC8594)
    a.label("skip")
    for _, w in read_words(so, 0xCC846C, 5):
        a.emit(w)
    a.emit(RET)
    a.label("run_limited")
    a.ref("b", 0xCC8494)
    a.finish(); a.show("cave2")

    # ---- cave 3: Everyplay gate, keep types 29/30 alive ----
    a = cave("cave3", 0x20C8AE0)
    a.ref("cbnz32", 8, "cont")
    a.emit(ldr32(8, 19, 0x28))
    a.emit(sub32(9, 8, 0x1C))
    a.emit(cmp32(9, 2))
    a.ref("bcond", 0x9, "cont")        # LS (28..30)
    a.ref("b", 0xE93AA0)
    a.label("cont")
    a.ref("b", 0xE939A0)
    a.finish(); a.show("cave3")

    # ---- cave 4: force available for types 29/30 ----
    a = cave("cave4", 0x20C8B00)
    a.emit(ldr32(8, 19, 0x28))
    a.emit(sub32(9, 8, 0x1C))
    a.emit(cmp32(9, 2))
    a.ref("bcond", 0x8, "store")       # HI -> not 28/29/30
    a.emit(movz32(20, 1))
    a.label("store")
    a.emit(strb(20, 19, 0x68))
    a.ref("b", 0xE93A44)
    a.finish(); a.show("cave4")

    # ---- cave 5: unified click (time + invincibility + auto stop) ----
    a = cave("cave5", 0x20C8D70)
    a.emit(ldr32(21, 19, 0x28))        # type -> w21
    emit_read_mask(a, "c5_zero", "c5_after")
    a.emit(mov_w(16, 0))               # mask
    a.emit(ubfx(8, 16, 3, 1))
    a.ref("cbnz32", 8, "auto_mode")
    a.ref("b", "normal")
    a.label("auto_mode")
    a.emit(cmp32(21, 0x1C))            # only the KILL button becomes STOP
    a.ref("bcond", 1, "normal")
    # STOP: clear bits 3/2, KILL byte 0, label back to KILL, white
    a.emit(movz32(17, 0xC))
    a.emit(bic32(16, 16, 17))
    a.emit(mov_w(0, 16))
    emit_write_mask(a, "c5_wdone", 16)
    a.emit(adrp(a.pc, 8, 0x2A99000))
    a.emit(ldr64(8, 8, 0x570))
    a.emit(ldr64(8, 8, 0x0))
    a.emit(ldr64(8, 8, 0xA0))
    a.ref("cbz64", 8, "c5_title")
    a.emit(strb(31, 8, 0x25))
    a.label("c5_title")
    a.emit(ldr64(9, 19, 0x20))
    a.ref("cbz64", 9, "c5_color")
    a.emit(movz32(10, 581))            # UI_KILL
    a.emit(str32(10, 9, 0x90))
    a.label("c5_color")
    a.emit(mov_x(0, 19))
    a.ref("bl", 0xE936A4)              # UpdateBtn -> refresh KILL label
    a.ref("bl", 0x20C9000)             # cave8 -> icon_attack (mask bit3 now 0)
    a.emit(movz32(20, 0))              # white
    a.ref("b", "color")
    a.label("normal")
    a.emit(adrp(a.pc, 8, 0x2A99000))
    a.emit(ldr64(8, 8, 0x570))
    a.emit(ldr64(8, 8, 0x0))
    a.emit(ldr64(8, 8, 0xA0))
    a.ref("cbz64", 8, "init")
    a.label("have")
    a.emit(cmp32(21, 0x1E))
    a.ref("bcond", 0x0, "time_flag")   # EQ
    a.emit(cmp32(21, 0x1C))
    a.ref("bcond", 0x0, "kill_flag")   # EQ (type 28)
    # type 29: flip higeMiniTest, then SetMutekiFlag(Party, flag)
    a.emit(ldrb(9, 8, 0x12))
    a.emit(eor32(9, 9, 1))
    a.emit(strb(9, 8, 0x12))
    a.emit(mov_w(20, 9))
    a.emit(adrp(a.pc, 8, 0x2A97000))
    a.emit(ldr64(8, 8, 0xFF0))
    a.emit(ldr64(8, 8, 0x0))
    a.emit(ldr64(8, 8, 0xA0))
    a.emit(ldr64(0, 8, 0x0))           # TutorialManager.instance
    a.ref("cbz64", 0, "color")
    a.emit(ldr64(9, 0, 0x20))          # bm
    a.ref("cbz64", 9, "color")
    a.emit(movz32(1, 0))               # Entity.Type.Party
    a.emit(mov_w(2, 20))
    a.ref("bl", 0x117CC70)             # SetMutekiFlag
    a.ref("b", "color")
    a.label("time_flag")
    a.emit(ldrb(9, 8, 0x11))
    a.emit(eor32(9, 9, 1))
    a.emit(strb(9, 8, 0x11))
    a.emit(mov_w(20, 9))
    a.ref("b", "color")
    a.label("kill_flag")
    a.emit(ldrb(9, 8, 0x25))           # enableTestZClass (one hit)
    a.emit(eor32(9, 9, 1))
    a.emit(strb(9, 8, 0x25))
    a.emit(mov_w(20, 9))
    a.label("color")
    a.ref("cbnz32", 20, "red")
    a.ref("bl", 0x1D64640)             # white
    a.ref("b", "apply")
    a.label("red")
    a.ref("bl", 0x1D64618)             # red
    a.label("apply")
    a.emit(mov_x(0, 19))
    a.ref("bl", 0xE93AD8)              # SetColor
    a.ref("bl", 0x20C9800)             # persist both flags (cave 11)
    a.ref("b", "ret")
    a.label("init")
    a.ref("bl", 0x10CF414)
    a.emit(adrp(a.pc, 8, 0x2A99000))
    a.emit(ldr64(8, 8, 0x570))
    a.emit(ldr64(8, 8, 0x0))
    a.emit(ldr64(8, 8, 0xA0))
    a.ref("cbnz64", 8, "have")
    a.label("ret")
    for _, w in read_words(so, 0xE953E4, 4):
        a.emit(w)
    a.emit(RET)
    a.finish(); a.show("cave5")

    # ---- cave 6: labels + icon on menu open (colour is cave 10) ----
    a = cave("cave6", 0x20C8F00)
    a.emit(ldr32(8, 19, 0x28))
    a.emit(cmp32(8, 0x1E))
    a.ref("bcond", 0x0, "time_color")  # EQ
    a.emit(cmp32(8, 0x1C))
    a.ref("bcond", 0x0, "kill_color")  # EQ (type 28)
    a.emit(cmp32(8, 0x1D))
    a.ref("bcond", 1, "original")      # NE
    # type 29: titles[29] = UI_HP (19)
    a.emit(ldr64(9, 19, 0x20))
    a.ref("cbz64", 9, "inv_icon")
    a.emit(movz32(10, 0x13))
    a.emit(str32(10, 9, 0x94))
    a.label("inv_icon")
    a.ref("bl", 0x20C9000)             # switch icon to the status atlas
    a.ref("b", "original")
    a.label("time_color")
    # type 30: titles[30] = UI_TIME (497)
    a.emit(ldr64(9, 19, 0x20))
    a.ref("cbz64", 9, "time_icon")
    a.emit(movz32(10, 0x1F1))
    a.emit(str32(10, 9, 0x98))
    a.label("time_icon")
    a.ref("bl", 0x20C9000)             # switch icon to the status atlas
    a.ref("b", "original")
    a.label("kill_color")
    # type 28: AUTO -> UI_BTN_KAMCORD_STOP (298), else UI_KILL (581)
    emit_read_mask(a, "c6_zero", "c6_after")
    a.emit(ubfx(8, 0, 3, 1))
    a.ref("cbnz32", 8, "kill_auto")
    a.emit(movz32(10, 0x245))          # UI_KILL
    a.ref("b", "kill_set")
    a.label("kill_auto")
    a.emit(movz32(10, 298))            # UI_BTN_KAMCORD_STOP
    a.label("kill_set")
    a.emit(ldr64(9, 19, 0x20))
    a.ref("cbz64", 9, "kill_icon")
    a.emit(str32(10, 9, 0x90))
    a.label("kill_icon")
    a.ref("bl", 0x20C9000)             # switch icon to the status atlas
    a.label("original")
    a.emit(mov_x(0, 19))
    a.ref("bl", 0xE93AD8)              # SetColor (cave 10 overrides 29/30)
    a.label("epilogue")
    for _, w in read_words(so, 0xE93A8C, 5):
        a.emit(w)
    a.finish(); a.show("cave6")

    # ---- cave 8: switch the icon's atlas to the status atlas ----
    # The button's spriteBG already references atlas 12740. Pick icon_time
    # (704,754), icon_HP (890,241), icon_attack (1003,800) and
    # icon_dungeon_02 (975,293, STOP while Auto is on) by scanning the atlas
    # sprite list, so no new string literals are needed.
    a = cave("cave8", 0x20C9000)
    a.emit(stp_pre(29, 30, 31, -0x60))
    a.emit(stp_off(20, 21, 31, 0x10))
    a.emit(stp_off(22, 23, 31, 0x20))
    a.emit(stp_off(24, 25, 31, 0x30))
    a.emit(stp_off(26, 27, 31, 0x40))
    a.emit(stp_off(28, 31, 31, 0x50))
    a.emit(ldr64(0, 19, 0x40))         # spriteBG UISprite
    a.ref("cbz64", 0, "out")
    a.emit(ldr64(20, 0, 0x1B0))        # mAtlas (status atlas 12740)
    a.ref("cbz64", 20, "out")
    a.emit(ldr64(21, 20, 0x20))        # mSprites List
    a.ref("cbnz64", 21, "have_list")
    a.emit(mov_x(0, 20))
    a.ref("bl", 0x1198AA4)             # get_spriteList()
    a.emit(mov_x(21, 0))
    a.label("have_list")
    a.ref("cbz64", 21, "out")
    a.emit(ldr64(22, 21, 0x10))        # _items array
    a.ref("cbz64", 22, "out")
    a.emit(ldr32(23, 21, 0x18))        # _size
    a.emit(ldr32(8, 19, 0x28))         # type
    a.emit(cmp32(8, 0x1E))
    a.ref("bcond", 0x0, "time_target")
    a.emit(cmp32(8, 0x1C))
    a.ref("bcond", 1, "hp_target")     # NE
    # type 28: STOP while Auto is on -> icon_dungeon_02, else icon_attack
    emit_read_mask(a, "c8_zero", "c8_after")
    a.emit(ubfx(9, 0, 3, 1))
    a.ref("cbz32", 9, "kill_target")
    a.emit(movz32(25, 975))            # icon_dungeon_02 x
    a.emit(movz32(26, 293))            # icon_dungeon_02 y
    a.ref("b", "loop_init")
    a.label("hp_target")
    a.emit(movz32(25, 890))            # icon_HP x
    a.emit(movz32(26, 241))            # icon_HP y
    a.ref("b", "loop_init")
    a.label("time_target")
    a.emit(movz32(25, 704))            # icon_time x
    a.emit(movz32(26, 754))            # icon_time y
    a.ref("b", "loop_init")
    a.label("kill_target")
    a.emit(movz32(25, 1003))           # icon_attack x
    a.emit(movz32(26, 800))            # icon_attack y
    a.label("loop_init")
    a.emit(movz32(24, 0))              # i = 0
    a.emit(add64(27, 22, 0x20))        # &items[0]
    a.label("loop")
    a.emit(cmp_reg(24, 23))            # i >= size?
    a.ref("bcond", 0xA, "out")
    a.emit(ldr64(28, 27, 0))           # UISpriteData*
    a.emit(ldr32(8, 28, 0x18))         # x
    a.emit(cmp_reg(8, 25))
    a.ref("bcond", 1, "next")
    a.emit(ldr32(8, 28, 0x1C))         # y
    a.emit(cmp_reg(8, 26))
    a.ref("bcond", 0x0, "found")
    a.label("next")
    a.emit(add64(27, 27, 8))
    a.emit(add32(24, 24, 1))
    a.ref("b", "loop")
    a.label("found")
    a.emit(ldr64(1, 28, 0x10))         # name
    a.ref("cbz64", 1, "out")
    a.emit(ldr64(0, 19, 0x30))         # icon UISprite
    a.ref("cbz64", 0, "out")
    a.emit(mov_x(1, 20))               # status atlas
    a.ref("bl", 0xD55148)              # set_atlas
    a.emit(ldr64(0, 19, 0x30))
    a.emit(ldr64(1, 28, 0x10))
    a.ref("bl", 0xD5543C)              # set_spriteName
    a.label("out")
    a.emit(ldp_off(29, 30, 31, 0))
    a.emit(ldp_off(20, 21, 31, 0x10))
    a.emit(ldp_off(22, 23, 31, 0x20))
    a.emit(ldp_off(24, 25, 31, 0x30))
    a.emit(ldp_off(26, 27, 31, 0x40))
    a.emit(ldp_off(28, 31, 31, 0x50))
    a.emit(add_sp(0x60))
    a.emit(RET)
    a.finish(); a.show("cave8")

    # ---- cave 10: SetColor choke point ----
    a = cave("cave10", 0x20C9280)
    a.emit(ldr32(8, 0, 0x28))          # x0 = UIIconBtn
    a.emit(cmp32(8, 0x1E))
    a.ref("bcond", 0x0, "t")
    a.emit(cmp32(8, 0x1D))
    a.ref("bcond", 0x0, "i")
    a.emit(cmp32(8, 0x1C))
    a.ref("bcond", 0x0, "k")
    a.ref("b", "orig")
    a.label("t")
    a.emit(adrp(a.pc, 8, 0x2A99000))
    a.emit(ldr64(8, 8, 0x570))
    a.emit(ldr64(8, 8, 0x0))
    a.emit(ldr64(8, 8, 0xA0))
    a.ref("cbz64", 8, "white")
    a.emit(ldrb(9, 8, 0x11))
    a.ref("cbnz32", 9, "red")
    a.ref("b", "white")
    a.label("i")
    a.emit(adrp(a.pc, 8, 0x2A99000))
    a.emit(ldr64(8, 8, 0x570))
    a.emit(ldr64(8, 8, 0x0))
    a.emit(ldr64(8, 8, 0xA0))
    a.ref("cbz64", 8, "white")
    a.emit(ldrb(9, 8, 0x12))
    a.ref("cbnz32", 9, "red")
    a.ref("b", "white")
    a.label("k")
    a.emit(adrp(a.pc, 8, 0x2A99000))
    a.emit(ldr64(8, 8, 0x570))
    a.emit(ldr64(8, 8, 0x0))
    a.emit(ldr64(8, 8, 0xA0))
    a.ref("cbz64", 8, "white")
    a.emit(ldrb(9, 8, 0x25))
    a.ref("cbnz32", 9, "red")
    a.ref("b", "white")
    a.label("red")
    a.emit(stp_pre(0, 30, 31, -0x10))  # stp x0,x30,[sp,#-0x10]!
    a.ref("bl", 0x1D64618)
    a.emit(ldp_post(0, 30, 31, 0x10))  # ldp x0,x30,[sp],#0x10
    a.ref("b", "orig")
    a.label("white")
    a.emit(stp_pre(0, 30, 31, -0x10))
    a.ref("bl", 0x1D64640)
    a.emit(ldp_post(0, 30, 31, 0x10))
    a.label("orig")
    for _, w in read_words(so, 0xE93AD8, 1):
        a.emit(w)                      # stp d15,d14,[sp,#-0x60]!
    a.ref("b", 0xE93ADC)
    a.finish(); a.show("cave10")

    # ---- cave 11: persist the flags as a bitmask under a private key ----
    # Key literal "versionVerify_terra_battle_mistwalker" (cell 0x2BDC668).
    # Do NOT use ShowedFirstEvelyplayUploadWindow: its setter
    # (UserData.SetShowedFirstEveryplayUploadWindow, 0x19DDA30) writes only
    # `v & 1` at the title, which wipes bits 2/3 of our mask. The verifier
    # string is only hashed by the version check; no PlayerPrefs code uses it.
    # bit 0 = TIME, bit 1 = HP, bit 2 = KILL, bit 3 = AUTO.
    a = cave("cave11", 0x20C9800)
    a.emit(stp_pre(29, 30, 31, -0x10))
    emit_read_mask(a, "c11_zero", "c11_after")
    a.emit(mov_w(16, 0))               # current mask
    a.emit(adrp(a.pc, 8, 0x2A99000))
    a.emit(ldr64(8, 8, 0x570))
    a.emit(ldr64(8, 8, 0x0))
    a.emit(ldr64(8, 8, 0xA0))
    a.ref("cbz64", 8, "done")
    a.emit(ldrb(9, 8, 0x11))           # higeTest -> bit 0
    a.emit(ldrb(10, 8, 0x12))          # higeMiniTest -> bit 1
    a.emit(add_reg32(10, 10, 10))
    a.emit(orr32(9, 9, 10))
    a.emit(ldrb(10, 8, 0x25))          # enableTestZClass -> bit 2
    a.emit(add_reg32(10, 10, 10))
    a.emit(add_reg32(10, 10, 10))
    a.emit(orr32(9, 9, 10))
    # preserve AUTO (bit 3) from the current mask
    a.emit(ubfx(17, 16, 3, 1))
    a.emit(add_reg32(17, 17, 17))
    a.emit(add_reg32(17, 17, 17))
    a.emit(add_reg32(17, 17, 17))
    a.emit(orr32(9, 9, 17))
    # if AUTO is on, manual defeat (bit 2) stays off.
    # w17 (IP1) is used here, never w18: x18 is the Android platform register.
    a.emit(ubfx(17, 16, 3, 1))
    a.ref("cbz32", 17, "c11_key")
    a.emit(movz32(17, 4))
    a.emit(bic32(9, 9, 17))
    a.label("c11_key")
    a.emit(adrp(a.pc, 8, 0x2BDC000))
    a.emit(add64(8, 8, 0x668))
    a.emit(ldr64(1, 8, 0))
    a.ref("cbz64", 1, "done")
    a.emit(mov_x(0, 31))
    a.emit(mov_w(2, 9))
    a.emit(mov_x(3, 31))
    a.ref("bl", 0x1FA6A10)             # PlayerPrefs.SetInt(key, mask)
    a.emit(mov_x(0, 31))
    a.emit(mov_x(1, 31))
    a.ref("bl", 0x1FA6EE4)             # PlayerPrefs.Save()
    a.label("done")
    a.emit(ldp_post(29, 30, 31, 0x10))
    a.emit(RET)
    a.finish(); a.show("cave11")

    # ---- cave 12: restore both flags at battle start ----
    # Hooked over the (already nop'd) SetDisableFlag(30) call in
    # BattleManager.<StartBattle> state 12, which runs once per battle after
    # the party exists. Re-applies muteki here because SetMutekiFlag only
    # marks entities alive at the time of the call.
    a = cave("cave12", 0x20C9900)
    a.emit(adrp(a.pc, 8, 0x2BDC000))
    a.emit(add64(8, 8, 0x668))
    a.emit(ldr64(1, 8, 0))
    a.ref("cbz64", 1, "done")
    a.emit(mov_x(0, 31))
    a.emit(mov_w(2, 31))
    a.emit(mov_x(3, 31))
    a.ref("bl", 0x1FA6AB8)             # PlayerPrefs.GetInt(key, 0)
    a.emit(mov_w(16, 0))               # mask
    a.emit(adrp(a.pc, 8, 0x2A99000))
    a.emit(ldr64(8, 8, 0x570))
    a.emit(ldr64(8, 8, 0x0))
    a.emit(ldr64(8, 8, 0xA0))
    a.ref("cbz64", 8, "done")
    a.emit(ubfx(9, 16, 0, 1))
    a.emit(strb(9, 8, 0x11))           # higeTest
    a.emit(ubfx(9, 16, 1, 1))
    a.emit(strb(9, 8, 0x12))           # higeMiniTest
    # AUTO keeps one-hit on (KILL byte 1) but manual defeat (bit 2) is off
    a.emit(ubfx(17, 16, 3, 1))
    a.ref("cbnz32", 17, "auto25")
    a.emit(ubfx(10, 16, 2, 1))
    a.ref("b", "store25")
    a.label("auto25")
    a.emit(movz32(10, 1))
    a.label("store25")
    a.emit(strb(10, 8, 0x25))          # enableTestZClass
    a.ref("cbz32", 9, "done")          # HP off
    a.emit(adrp(a.pc, 8, 0x2A97000))
    a.emit(ldr64(8, 8, 0xFF0))
    a.emit(ldr64(8, 8, 0x0))
    a.emit(ldr64(8, 8, 0xA0))
    a.emit(ldr64(0, 8, 0x0))           # TutorialManager.instance
    a.ref("cbz64", 0, "done")
    a.emit(ldr64(9, 0, 0x20))          # bm
    a.ref("cbz64", 9, "done")
    a.emit(movz32(1, 0))               # Entity.Type.Party
    a.emit(movz32(2, 1))
    a.ref("bl", 0x117CC70)             # SetMutekiFlag(Party, true)
    a.label("done")
    a.ref("b", 0xCFA054)
    a.finish(); a.show("cave12")

    # ---- cave 13: party invincibility at damage time ----
    # Entity.Damage only clamps a lethal hit to 1 HP when Entity.isMuteki is
    # set, and SetMutekiFlag only marks entities alive at the call. Checking
    # the global flag here makes the restored toggle effective for every
    # party entity from the first hit, whoever created it and whenever.
    # Entity.status (+0x38) -> Status.type (+0x2C); Party == 0.
    a = cave("cave13", 0x20C9A50)
    a.emit(stp_pre(9, 10, 31, -0x10))
    a.emit(ldrb(8, 19, 0x234))         # Entity.isMuteki
    a.ref("cbnz32", 8, "one")
    a.emit(adrp(a.pc, 9, 0x2A99000))
    a.emit(ldr64(9, 9, 0x570))
    a.emit(ldr64(9, 9, 0x0))
    a.emit(ldr64(9, 9, 0xA0))
    a.ref("cbz64", 9, "out")
    a.emit(ldrb(9, 9, 0x12))           # higeMiniTest
    a.ref("cbz32", 9, "out")
    a.emit(ldr64(10, 19, 0x38))        # Entity.status
    a.ref("cbz64", 10, "out")
    a.emit(ldr32(10, 10, 0x2C))        # Status.type
    a.ref("cbnz32", 10, "out")         # not Party
    a.label("one")
    a.emit(movz32(23, 1))              # damage = 1
    a.label("out")
    a.emit(ldp_post(9, 10, 31, 0x10))
    a.ref("b", 0x1091210)
    a.finish(); a.show("cave13")

    # ---- cave 14: one-hit kill enemies ----
    # 0x10911F8 computes the resulting HP into w23. Forcing it to 0 makes any
    # hit lethal; only Status.type == Enemy (1) is affected.
    a = cave("cave14", 0x20C9D00)
    a.emit(stp_pre(9, 10, 31, -0x10))
    a.emit(adrp(a.pc, 9, 0x2A99000))
    a.emit(ldr64(9, 9, 0x570))
    a.emit(ldr64(9, 9, 0x0))
    a.emit(ldr64(9, 9, 0xA0))
    a.ref("cbz64", 9, "normal")
    a.emit(ldrb(9, 9, 0x25))           # enableTestZClass
    a.ref("cbz32", 9, "normal")
    a.emit(ldr64(10, 19, 0x38))        # Entity.status
    a.ref("cbz64", 10, "normal")
    a.emit(ldr32(10, 10, 0x2C))        # Status.type
    a.emit(cmp32(10, 1))
    a.ref("bcond", 1, "normal")        # NE -> not Enemy
    a.emit(movz32(23, 0))              # resulting HP = 0
    a.emit(ldp_post(9, 10, 31, 0x10))
    a.ref("b", 0x1091210)
    a.label("normal")
    a.emit(ldp_post(9, 10, 31, 0x10))
    a.emit(cmp32(23, 0))
    a.ref("bcond", 0xC, "survived")    # GT -> survived
    a.ref("b", 0x1091200)
    a.label("survived")
    a.ref("b", 0x1091210)
    a.finish(); a.show("cave14")

    patch_sites = [
        ("0xCC8490", "2d080054", b(0xCC8490, 0x20C8A60), "normal chapters: b.le drag path -> cave 2"),
        ("0xCC84C0", "615a02bd", b(0xCC84C0, 0x20C8A20), "time-limited chapters: remain store -> cave 1"),
        ("0xE9399C", "28080036", b(0xE9399C, 0x20C8AE0), "Everyplay gate -> cave 3 (types 28/29/30)"),
        ("0xE93A40", "74a20139", b(0xE93A40, 0x20C8B00), "force available for types 28/29/30 -> cave 4"),
        ("0xE95268", "88de00b0", b(0xE95268, 0x20C8D70), "type-28 click -> cave 5"),
        ("0xE952C4", "b5de00f0", b(0xE952C4, 0x20C8D70), "type-29 click -> cave 5"),
        ("0xE95384", "a8de00f0", b(0xE95384, 0x20C8D70), "type-30 click -> cave 5"),
        ("0xE93A88", "14000094", b(0xE93A88, 0x20C8F00), "labels + icon on menu open -> cave 6"),
        ("0xE93AD8", "ef3bba6d", b(0xE93AD8, 0x20C9280), "SetColor choke: red/white for 28/29/30 -> cave 10"),
        ("0xCFA050", "6f420694", b(0xCFA050, 0x20C9900), "StartBattle: restore flags from PlayerPrefs -> cave 12"),
        ("0xCFA040", "73420694", 0xD503201F, "StartBattle: nop SetDisableFlag(28)"),
        ("0xCFA060", "6b420694", 0xD503201F, "StartBattle: nop SetDisableFlag(29)"),
        ("0x1091200", "68d24839", b(0x1091200, 0x20C9A50), "Entity.Damage: party muteki at damage time -> cave 13"),
        ("0x10911F8", "ff020071", b(0x10911F8, 0x20C9D00), "Entity.Damage: one-hit enemies -> cave 14"),
    ]
    patches = []
    for off, orig, w, note in patch_sites:
        patches.append({"offset": off, **guard(bytes.fromhex(orig)),
                        "patch": w.to_bytes(4, "little").hex(), "note": note})
    for name, (a, base) in caves.items():
        blob = a.finish()
        patches.append({"offset": hex(base), **guard(b"\x00" * len(blob)),
                        "patch": blob.hex(), "note": name})

    spec = {
        "_comment": (
            "In-battle Kamcord toggles. Share (28) one-hit-kills enemies via "
            "DebugManager.enableTestZClass (+0x25). StartRec (30) freezes the turn "
            "timer via higeTest (+0x11). StopRec (29) toggles party invincibility via "
            "higeMiniTest (+0x12) -> TutorialManager.SetMutekiFlag -> Entity.isMuteki. "
            "All three survive the Everyplay gate and the StartBattle disable flags, "
            "re-colour red/white when the menu reopens, and persist across restarts "
            "as a bitmask under the version-verifier literal (the Everyplay key "
            "cannot be used: its 0/1 setter wipes the mask at the title)."
        ),
        "enabled": True,
        "patches": patches,
    }
    annotate(spec)
    (ROOT / "patches" / "native_time.json").write_text(
        json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    print("\nwrote patches/native_time.json")
    for name, (a, base) in caves.items():
        print(f"  {name}: {len(a.words)*4} bytes @ {base:#x} ends {base + len(a.words)*4:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
