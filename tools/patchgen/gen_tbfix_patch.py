#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""High-address soak: keep the game's allocations below 4 GB.

Terra Battle is a 2019 Unity build that truncates a pointer to 32 bits
somewhere in its startup path.  On Android layouts where the allocator hands
out addresses above 4 GB the truncated value becomes garbage, and the process
dies with SIGSEGV a few dozen milliseconds into `il2cpp_init` - reproducible
on a Galaxy S25 running Android 17, invisible on the emulator and on the S23.

The fix is a *soak*: reserve the high address space in coarse-to-fine chunks
until the kernel starts returning sub-4 GB addresses, then leave the
reservations in place (`PROT_NONE` + `MAP_NORESERVE`, so no physical memory is
committed).  Everything the game allocates afterwards lands low.

This generator emits `patches/native_tbfix.json`:

  * a cave in `libil2cpp.so` that runs the four soak tiers and then branches
    to the original initialiser, and
  * an 8-byte edit of the first `R_AARCH64_RELATIVE` addend in `.rela.dyn`,
    which retargets `DT_INIT_ARRAY[0]` from that initialiser to the cave.

Because the entry point runs at `dlopen`, this is earlier than
`il2cpp_init` and needs no change to `libunity`.  The relocation addend is
plain file data, so `verify` reproduces it like any other byte patch.

Windows that the soak reserves are never released: releasing them would let
the allocator reuse high addresses and reintroduce the bug.
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path

from hooks import annotate
from sites import guard

ROOT = Path(__file__).resolve().parents[2]      # repo root (tools/patchgen/)
SO = ROOT / "work" / "il2cpp" / "libil2cpp.so"
UNITY = ROOT / "work" / "libunity.so"
OUT = ROOT / "patches" / "native_tbfix.json"

# DT_INIT_ARRAY[0]: R_AARCH64_RELATIVE at file offset 0x9c98, addend 0x913f1c.
INIT_ADDEND_OFF = 0x9C98
INIT_ENTRY = 0x913F1C

# libunity has 2616 init entries; entry[0] is the earliest code in the process
# that we can reach, and it runs before libil2cpp is dlopened at all.
UNITY_ADDEND_OFF = 0x16D70
UNITY_ENTRY = 0x8D4DC

# mmap/munmap syscall numbers on arm64.
SYS_MMAP = 222
SYS_MUNMAP = 215
PROT_NONE = 0
MAP_FLAGS = 0x4022          # MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE

# Coarse to fine: 1 GiB, 64 MiB, 2 MiB, 64 KiB.
# caps must fit the 12-bit cmp immediate
TIERS = ((0x4000, 1, 512),      # (imm16, hw shift, iteration cap)
         (0x0400, 1, 4095),
         (0x0020, 1, 4095),
         (0x0001, 1, 4095))

COND_EQ, COND_LO = 0, 3

# Allocation window for the cave: verified-zero padding in the executable
# segment, after the caves the other generators already claim.
CAVE_LO, CAVE_HI = 0x20D0000, 0x2140000


# --- encoders ---------------------------------------------------------------
def movz64(rd: int, imm16: int, hw: int = 0) -> int:
    return 0xD2800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | rd


def movn64(rd: int, imm16: int = 0, hw: int = 0) -> int:
    return 0x92800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | rd


def mov_x(rd: int, rn: int) -> int:
    return 0xAA0003E0 | (rn << 16) | rd


def add_imm(rd: int, rn: int, imm: int) -> int:
    return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def sub_sp(imm: int) -> int:
    return 0xD10003FF | ((imm & 0xFFF) << 10)


def add_sp(imm: int) -> int:
    return 0x910003FF | ((imm & 0xFFF) << 10)


def cmp_imm(rn: int, imm: int) -> int:
    return 0xF1000000 | ((imm & 0xFFF) << 10) | (rn << 5) | 31


SVC = 0xD4000001
CMN_X0_1 = 0xB100041F          # cmn x0, #1  (mmap returned -1)
LSR_X9_X0_32 = 0xD360FC09      # lsr x9, x0, #32


def cbnz(rt: int, off: int) -> int:
    assert off % 4 == 0 and -(1 << 20) <= off < (1 << 20), hex(off)
    return 0xB5000000 | (((off >> 2) & 0x7FFFF) << 5) | rt


def bcond(cond: int, off: int) -> int:
    assert off % 4 == 0 and -(1 << 20) <= off < (1 << 20), hex(off)
    return 0x54000000 | (((off >> 2) & 0x7FFFF) << 5) | cond


def b(off: int) -> int:
    assert off % 4 == 0 and -(1 << 27) <= off < (1 << 27), hex(off)
    return 0x14000000 | ((off >> 2) & 0x03FFFFFF)


class Asm:
    """Tiny two-pass assembler: words, plus branches to named labels."""

    def __init__(self, base: int) -> None:
        self.base = base
        self.items: list = []
        self.labels: dict[str, int] = {}

    def label(self, name: str) -> None:
        self.labels[name] = self.pc()

    def pc(self) -> int:
        return self.base + 4 * len(self.items)

    def emit(self, word: int) -> None:
        self.items.append(("word", word))

    def branch(self, kind: str, target: str, cond: int = 0) -> None:
        self.items.append((kind, target, cond))

    def bytes(self) -> bytes:
        out = bytearray()
        for item in self.items:
            if item[0] == "word":
                out += struct.pack("<I", item[1])
                continue
            kind, target, cond = item
            here = self.base + len(out)
            off = self.labels[target] - here
            word = b(off) if kind == "b" else bcond(cond, off) if kind == "cond" else cbnz(cond, off)
            out += struct.pack("<I", word)
        return bytes(out)


def soak_tier(a: Asm, idx: int, imm16: int, hw: int, cap: int) -> None:
    """One tier: reserve `size` chunks while they land above 4 GB."""
    a.emit(movz64(10, imm16, hw))          # x10 = chunk size
    a.emit(movz64(11, cap))                # x11 = iteration counter
    a.label(f"t{idx}_loop")
    a.emit(mov_x(0, 31))                   # x0 = NULL (let the kernel choose)
    a.emit(mov_x(1, 10))                   # x1 = size
    a.emit(mov_x(2, 31))                   # x2 = PROT_NONE
    a.emit(movz64(3, MAP_FLAGS))           # x3 = MAP_PRIVATE|ANON|NORESERVE
    a.emit(movn64(4))                      # x4 = -1 (fd)
    a.emit(mov_x(5, 31))                   # x5 = 0 (offset)
    a.emit(movz64(8, SYS_MMAP))
    a.emit(SVC)
    a.emit(CMN_X0_1)
    a.branch("cond", f"t{idx}_done", COND_EQ)      # failed: no more VA
    a.emit(LSR_X9_X0_32)
    if os.environ.get("TB_TBFIX_ALWAYS") == "1":
        a.branch("b", f"t{idx}_keep")              # diagnostic: keep regardless
    else:
        a.branch("cbnz", f"t{idx}_keep", 9)        # above 4 GB: keep it
    a.emit(mov_x(1, 10))                           # landed low: release it
    a.emit(movz64(8, SYS_MUNMAP))
    a.emit(SVC)
    a.branch("b", f"t{idx}_done")
    a.label(f"t{idx}_keep")
    a.emit(add_imm(11, 11, 1))
    a.emit(cmp_imm(11, cap))
    a.branch("cond", f"t{idx}_loop", COND_LO)
    a.label(f"t{idx}_done")


def force_low_blob(base: int) -> bytes:
    """Diagnostic: saturate 0..4 GB so the allocator must go high."""
    a = Asm(base)
    a.emit(sub_sp(16))
    a.emit(movz64(10, 0x1000, 1))          # x10 = 0x10000000 (start)
    a.emit(movz64(13, 1, 2))               # x13 = 0x100000000 (4 GB)
    a.label("fl_loop")
    a.emit(0xEB0D015F)                     # cmp x10, x13
    a.branch("cond", "fl_done", 2)         # b.hs
    a.emit(mov_x(0, 10))                   # x0 = addr
    a.emit(movz64(1, 0x0400, 1))           # x1 = 64 MiB
    a.emit(mov_x(2, 31))                   # PROT_NONE
    a.emit(movz64(3, 0x4022))              # PRIVATE|ANON|NORESERVE
    a.emit(movz64(9, 0x0010, 1))           # 0x100000
    a.emit(0xAA090063)                     # orr x3, x3, x9 -> MAP_FIXED_NOREPLACE
    a.emit(movn64(4))                      # fd = -1
    a.emit(mov_x(5, 31))
    a.emit(movz64(8, SYS_MMAP))
    a.emit(SVC)
    a.emit(movz64(9, 0x0400, 1))           # x9 = 64 MiB
    a.emit(0x8B09014A)                     # add x10, x10, x9
    a.branch("b", "fl_loop")
    a.label("fl_done")
    a.emit(add_sp(16))
    here = a.pc()
    a.emit(b(target - here))
    return a.bytes()


def soak_blob(base: int, target: int = INIT_ENTRY) -> bytes:
    if os.environ.get("TB_TBFIX_FORCE_LOW") == "1":
        return force_low_blob(base)
    a = Asm(base)
    a.emit(sub_sp(16))                     # keep our own frame out of the callee's
    for idx, (imm16, hw, cap) in enumerate(TIERS):
        soak_tier(a, idx, imm16, hw, cap)
    a.emit(add_sp(16))
    here = a.pc()
    a.emit(b(target - here))           # chain to the original initialiser
    return a.bytes()


def main() -> int:
    so = SO.read_bytes()
    assert so[INIT_ADDEND_OFF:INIT_ADDEND_OFF + 8] == struct.pack("<Q", INIT_ENTRY), \
        "init-array addend moved: re-derive INIT_ADDEND_OFF/INIT_ENTRY"

    # mark ranges taken by the other patch files
    used: list[tuple[int, int]] = []
    for f in sorted((ROOT / "patches").glob("native_*.json")):
        if f.name == "native_tbfix.json":
            continue
        for p in json.loads(f.read_text(encoding="utf-8")).get("patches", []):
            o = int(p["offset"], 16)
            used.append((o, o + len(p["patch"]) // 2))

    size = len(soak_blob(CAVE_LO))
    cave = None
    for off in range(CAVE_LO, CAVE_HI, 4):
        if off + size > CAVE_HI:
            break
        if any(a < off + size and off < b for a, b in used):
            continue
        if all(x == 0 for x in so[off:off + size]):
            cave = off
            break
    if cave is None:
        raise SystemExit(f"no free zero run for the soak cave ({size} bytes)")

    blob = soak_blob(cave)
    spec = {
        "_comment": (
            "High-address soak. Terra Battle truncates a pointer to 32 bits during "
            "startup; on Android layouts that hand out addresses above 4 GB that "
            "becomes a wild pointer and the process SIGSEGVs inside il2cpp init "
            "(reproduced on a Galaxy S25 / Android 17; the emulator and S23 never "
            "see it). DT_INIT_ARRAY[0] is retargeted to a cave that reserves high "
            "address space in 1 GiB / 64 MiB / 2 MiB / 64 KiB tiers until the "
            "kernel returns sub-4 GB addresses, keeps those reservations "
            "(PROT_NONE|MAP_NORESERVE, no physical memory) and then runs the "
            "original initialiser. The addend edit is plain file data in "
            ".rela.dyn, so verify reproduces it like any other byte patch."),
        "enabled": True,
        "patches": [
            {"offset": hex(INIT_ADDEND_OFF), **guard(so[INIT_ADDEND_OFF:INIT_ADDEND_OFF + 8]),
             "patch": struct.pack("<Q", cave).hex(),
             "note": "DT_INIT_ARRAY[0] addend -> soak cave",
             "kind": "reloc",
             "hook": False,
             "reason": "8-byte relocation addend in .rela.dyn, not a branch"},
            {"offset": hex(cave), **guard(so[cave:cave + len(blob)]),
             "patch": blob.hex(),
             "note": "soak cave: mmap/munmap tiers, then the original initialiser"},
        ],
    }
    annotate(spec)

    # --- libunity: same soak, one library earlier ---------------------------
    un = UNITY.read_bytes()
    assert un[UNITY_ADDEND_OFF:UNITY_ADDEND_OFF + 8] == struct.pack("<Q", UNITY_ENTRY), \
        "libunity init-array entry moved: re-derive UNITY_ADDEND_OFF/UNITY_ENTRY"
    # cave must live in an executable LOAD segment
    phoff, = struct.unpack_from("<Q", un, 0x20)
    phes, = struct.unpack_from("<H", un, 0x36)
    phn, = struct.unpack_from("<H", un, 0x38)
    exec_ranges = []
    for k in range(phn):
        o = phoff + k * phes
        t, fl = struct.unpack_from("<II", un, o)
        if t != 1 or not (fl & 1):
            continue
        off, va, pa, fsz, msz, al = struct.unpack_from("<QQQQQQ", un, o + 8)
        exec_ranges.append((off, off + fsz))
    size_u = len(soak_blob(0x100000, UNITY_ENTRY))
    cave_u = None
    for lo, hi in exec_ranges:
        for off in range(lo, hi - size_u, 4):
            if all(x == 0 for x in un[off:off + size_u]):
                cave_u = off
                break
        if cave_u:
            break
    if cave_u is None:
        raise SystemExit("no free zero run in libunity's executable segment")
    blob_u = soak_blob(cave_u, UNITY_ENTRY)
    spec["patches"] += [
        {"entry": "lib/arm64-v8a/libunity.so",
         "offset": hex(UNITY_ADDEND_OFF), **guard(un[UNITY_ADDEND_OFF:UNITY_ADDEND_OFF + 8]),
         "patch": struct.pack("<Q", cave_u).hex(),
         "note": "libunity DT_INIT_ARRAY[0] addend -> soak cave",
         "kind": "reloc", "hook": False,
         "reason": "8-byte relocation addend in .rela.dyn, not a branch"},
        {"entry": "lib/arm64-v8a/libunity.so",
         "offset": hex(cave_u), **guard(un[cave_u:cave_u + len(blob_u)]),
         "patch": blob_u.hex(),
         "note": "libunity soak cave: runs before libil2cpp is dlopened"},
    ]
    OUT.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    print(f"tbfix cave at 0x{cave:x} ({len(blob)} bytes), "
          f"init_array[0] 0x{INIT_ENTRY:x} -> 0x{cave:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
