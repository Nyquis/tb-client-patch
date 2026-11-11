#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Generate patches/native_killstart.json.

One way to clear the trash: Auto Play (PlayerPrefs mask bit 3), at the
enemy-turn state entry of BattleManager._advance (0xCE92E0), killing visible
non-boss enemies. There is no move sweep: the in-battle 1-Hit toggle only
affects damage, so an enemy dies when it is pincered or damaged.

Mask layout (version-verifier literal "versionVerify_terra_battle_mistwalker",
cell 0x2BDC668; the old Everyplay key is unusable because its setter writes only
0/1 at the title): bit 0 TIME, bit 1 HP, bit 2 the one-hit byte mirror, bit 3
AUTO.

Per enemy: skip dead, skip isBoss (safe mode), muteki -> SetHP(1), else
CheckForDrops(e, false, deadCombo) + Die().
"""

from __future__ import annotations

import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from hooks import annotate
from sites import guard

ROOT = Path(__file__).resolve().parents[2]   # repo root (tools/patchgen/)
SO = ROOT / "work" / "il2cpp" / "libil2cpp.so"

AUTO_HOOK = 0xCE92E0       # ldr x20,[x21] in _advance enemy-turn state
AUTO_RESUME = 0xCE92E4
SWEEP_BASE = 0x20C9D60

GET_ENTITIES = 0xCAC7FC
GET_IS_BOSS = 0x1079B20
SET_HP = 0x1087E88
CHECK_FOR_DROPS = 0xCC92AC
DIE = 0x107C158
PREF_GET_INT = 0x1FA6AB8
MASK_CELL_HI = 0x2BDC000
MASK_CELL_LO = 0x668
IN_PLAYER_TURN = 0x33B


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
    return (0xB4000000 if wide else 0x34000000) | (((off >> 2) & 0x7FFFF) << 5) | rt


def cbnz(pc, rt, target, wide):
    off = target - pc
    return (0xB5000000 if wide else 0x35000000) | (((off >> 2) & 0x7FFFF) << 5) | rt


def tbnz(pc, rt, bit, target):
    off = target - pc
    assert off % 4 == 0 and -(1 << 14) <= (off >> 2) < (1 << 14)
    return 0x37000000 | (bit << 26) | (((off >> 2) & 0x3FFF) << 5) | rt


def adrp(pc, rd, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def ldr64(rt, rn, imm):
    return 0xF9400000 | ((imm // 8) << 10) | (rn << 5) | rt


def ldr32(rt, rn, imm):
    return 0xB9400000 | ((imm // 4) << 10) | (rn << 5) | rt


def ldrb(rt, rn, imm):
    return 0x39400000 | ((imm & 0xFFF) << 10) | (rn << 5) | rt


def movz32(rd, imm):
    return 0x52800000 | ((imm & 0xFFFF) << 5) | rd


def mov_x(rd, rn):
    return 0xAA0003E0 | (rn << 16) | rd


def cmp32(rn, imm):
    return 0x71000000 | ((imm & 0xFFF) << 10) | (rn << 5) | 31


def sub32(rd, rn, imm):
    return 0x51000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def add64(rd, rn, imm):
    return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def ubfx(rd, rn, lsb, width):
    return 0x53000000 | ((lsb & 0x1F) << 16) | (((lsb + width - 1) & 0x1F) << 10) | (rn << 5) | rd


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
            elif mnem == "tbnz":
                w = tbnz(at, r[0], r[1], r[2])
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


def read_mask(a):
    """Inline READ_MASK: returns w0 = mask (0 if key cell null)."""
    a.emit(adrp(a.pc, 8, MASK_CELL_HI))
    a.emit(add64(8, 8, MASK_CELL_LO))
    a.emit(ldr64(1, 8, 0))
    a.ref("cbz64", 1, "rm_zero")
    a.emit(mov_x(0, 31))
    a.emit(movz32(2, 0))
    a.emit(mov_x(3, 31))
    a.ref("bl", PREF_GET_INT)
    a.ref("b", "rm_after")
    a.label("rm_zero")
    a.emit(movz32(0, 0))
    a.label("rm_after")


def build_sweep(base):
    a = Asm(base)
    a.emit(stp_pre(29, 30, 31, -0x50))
    a.emit(stp_off(20, 21, 31, 0x10))
    a.emit(stp_off(22, 23, 31, 0x20))
    a.emit(stp_off(24, 25, 31, 0x30))
    a.emit(mov_x(20, 0))                 # bm
    a.emit(mov_x(0, 20))
    a.emit(movz32(1, 1))                 # Entity.Type.Enemy
    a.emit(mov_x(2, 31))
    a.ref("bl", GET_ENTITIES)
    a.ref("cbz64", 0, "done")
    a.emit(mov_x(21, 0))
    a.emit(ldr32(22, 21, 0x18))
    a.emit(ldr64(23, 21, 0x10))
    a.ref("cbz64", 23, "done")
    a.emit(add64(23, 23, 0x20))
    a.label("loop")
    a.ref("cbz32", 22, "done")
    a.emit(ldr64(24, 23, 0))
    a.emit(add64(23, 23, 8))
    a.ref("cbz64", 24, "next")
    a.emit(ldr64(25, 24, 0x38))
    a.ref("cbz64", 25, "next")
    a.emit(ldr32(8, 25, 0x2C))
    a.emit(cmp32(8, 1))
    a.ref("bcond", 1, "next")            # NE
    a.emit(ldrb(8, 25, 0x36))
    a.ref("cbnz32", 8, "next")
    a.emit(mov_x(0, 24))
    a.emit(mov_x(1, 31))
    a.ref("bl", GET_IS_BOSS)
    a.ref("cbnz32", 0, "next")
    a.emit(ldrb(8, 24, 0x234))
    a.ref("cbz32", 8, "kill")
    a.emit(mov_x(0, 24))
    a.emit(movz32(1, 1))
    a.emit(mov_x(2, 31))
    a.ref("bl", SET_HP)
    a.ref("b", "next")
    a.label("kill")
    a.emit(mov_x(0, 20))
    a.emit(mov_x(1, 24))
    a.emit(movz32(2, 0))
    a.emit(ldr32(3, 20, 0x358))
    a.emit(mov_x(4, 31))
    a.ref("bl", CHECK_FOR_DROPS)
    a.emit(mov_x(0, 24))
    a.emit(mov_x(1, 31))
    a.ref("bl", DIE)
    a.label("next")
    a.emit(sub32(22, 22, 1))
    a.ref("b", "loop")
    a.label("done")
    a.emit(ldp_off(24, 25, 31, 0x30))
    a.emit(ldp_off(22, 23, 31, 0x20))
    a.emit(ldp_off(20, 21, 31, 0x10))
    a.emit(ldp_post(29, 30, 31, 0x50))
    a.emit(0xD65F03C0)                   # ret
    return a


def build_auto_stub(base, sweep):
    a = Asm(base)
    a.emit(stp_pre(29, 30, 31, -0x10))
    read_mask(a)
    a.emit(ubfx(8, 0, 3, 1))
    a.ref("cbnz32", 8, "sweep")
    a.ref("b", "skip")
    a.label("sweep")
    a.emit(ldr64(0, 19, 0xE0))
    a.ref("bl", sweep)
    a.label("skip")
    a.emit(ldp_post(29, 30, 31, 0x10))
    a.emit(add64(21, 19, 0xE0))
    a.emit(ldr64(20, 21, 0))
    a.ref("b", AUTO_RESUME)
    return a


def main() -> int:
    so = SO.read_bytes()
    assert so[AUTO_HOOK:AUTO_HOOK + 4] == bytes.fromhex("b40240f9"), "AUTO hook bytes"
    assert all(x == 0 for x in so[SWEEP_BASE:SWEEP_BASE + 400]), "cave not zero"

    sweep_a = build_sweep(SWEEP_BASE)
    sweep = sweep_a.finish()
    s1 = (SWEEP_BASE + len(sweep) + 0xF) & ~0xF
    auto_a = build_auto_stub(s1, SWEEP_BASE)
    auto_blob = auto_a.finish()
    end = s1 + len(auto_blob)
    assert end <= 0x20C9F2E, hex(end)

    sweep_a.show("sweep")
    auto_a.show("auto stub")

    spec = {
        "_comment": (
            "One trash-clearing mode: Auto Play (pre-battle Options row, mask "
            "bit 3), hooked at the enemy-turn state entry 0xCE92E0 "
            "(unconditional, before the onEnemyTurn delegate). The sweep is "
            "shared: visible, alive, non-boss enemies; muteki -> SetHP(1); else "
            "CheckForDrops(e,false,expBonusCnt) + Die(). The old manual-defeat "
            "sweep (Entity.EndDrag 0x108DE34, armed by the 1-Hit byte) is gone: "
            "1-Hit now only affects damage, so killing an enemy requires a "
            "pincer or any other damage. Bit 2 of the mask survives as the "
            "mirror of the one-hit byte so the state still persists. Auto keeps "
            "the one-hit byte set (cave 12) so bosses, which the sweep skips, "
            "still die in one hit."
        ),
        "enabled": True,
        "patches": [
            {
                "offset": hex(AUTO_HOOK),
                **guard(so[AUTO_HOOK:AUTO_HOOK + 4]),
                "patch": b(AUTO_HOOK, s1).to_bytes(4, "little").hex(),
                "note": "enemy-turn Auto Play sweep -> auto stub",
            },
            {
                "offset": hex(SWEEP_BASE),
                **guard(b"\x00" * len(sweep)),
                "patch": sweep.hex(),
                "note": "shared sweep subroutine",
            },
            {
                "offset": hex(s1),
                **guard(b"\x00" * len(auto_blob)),
                "patch": auto_blob.hex(),
                "note": "auto stub (mask bit 3)",
            },
        ],
    }
    out = ROOT / "patches" / "native_killstart.json"
    annotate(spec)
    out.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {out.relative_to(ROOT)}")
    print(f"  sweep {len(sweep)}B @ {SWEEP_BASE:#x}")
    print(f"  auto  {len(auto_blob)}B @ {s1:#x} end {end:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
