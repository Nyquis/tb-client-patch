#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Enumerate code sites that reference a slot address, or that touch a field offset.

Decompilation answers "what does this site do". This answers "where are all the
sites", which is the question that kept turning into throwaway scripts.

Two modes:

    # every site that materialises or dereferences 0x2A508E0 (ADRP+LDR/ADD)
    pixi run find-refs --slot 0x2A508E0

    # every strb/str/ldr/... with immediate #0x88 on any base
    pixi run find-refs --imm 0x88 --insn strb,str

Output is bounded (--limit/--offset) and every hit is attributed to the enclosing
method using dump.cs RVAs. Attribution is nearest-preceding-RVA, not exact code
extent, so treat the method name as a strong hint.
"""

from __future__ import annotations

import argparse
import bisect
import re
import struct
import sys
import time
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

import il2cpp_index

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SO = ROOT / "work" / "il2cpp" / "libil2cpp.so"

ADRP_RE = re.compile(r"^(\w+),\s*#(-?0x[0-9a-f]+|-?\d+)")
ADD_RE = re.compile(r"^(\w+),\s*(\w+),\s*#(-?0x[0-9a-f]+|-?\d+)$")
MEM_RE = re.compile(r"^(\w+),\s*\[(\w+)(?:,\s*(?:#)?(-?0x[0-9a-f]+|-?\d+))?\]")
IMM_RE = re.compile(r"#(-?0x[0-9a-f]+|-?\d+)")


def executable_sections(blob: bytes) -> list[tuple[int, int, int]]:
    """(file offset, address, size) for every SHF_EXECINSTR section."""
    if blob[:4] != b"\x7fELF" or blob[4] != 2:
        raise SystemExit("not an ELF64 file")
    shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
    shnum = struct.unpack_from("<H", blob, 0x3C)[0]
    sections = []
    for index in range(shnum):
        base = shoff + index * shentsize
        sh_flags = struct.unpack_from("<Q", blob, base + 8)[0]
        sh_addr = struct.unpack_from("<Q", blob, base + 16)[0]
        sh_offset = struct.unpack_from("<Q", blob, base + 24)[0]
        sh_size = struct.unpack_from("<Q", blob, base + 32)[0]
        if (sh_flags & 0x4) and sh_size:
            sections.append((sh_offset, sh_addr, sh_size))
    if not sections:
        raise SystemExit("no executable sections found")
    return sections


def walk(md, data: bytes, base: int, step: int = 4):
    """Yield instructions, resynchronising after undecodable bytes.

    Capstone's generator stops at the first invalid instruction, and .text holds
    literal pools and jump tables, so a plain disasm() pass ends almost at once.
    """
    position = 0
    total = len(data)
    while position < total:
        yielded = False
        for insn in md.disasm(data[position:], base + position):
            yielded = True
            yield insn
            position = insn.address - base + insn.size
        if not yielded:
            position += step
        else:
            position += step


def number(text: str) -> int:
    return int(text, 16) if text.lower().startswith(("0x", "-0x")) else int(text, 10)


def attribute(sorted_rvas: list[int], methods: dict[str, str], address: int) -> str:
    position = bisect.bisect_right(sorted_rvas, address) - 1
    if position < 0:
        return "?"
    key = f"0x{sorted_rvas[position]:X}"
    return methods.get(key, "?")


def find_slot_refs(blob: bytes, slot: int) -> list[tuple[int, int, str, str]]:
    """Every code site that materialises or dereferences `slot`.

    Returns (adrp_pc, ref_pc, mnemonic, operands). `adrp_pc` is the convention
    the patch JSONs use for a declared site; `ref_pc` is the actual load/add.
    Shared with tools/audit_patches.py so the gate and the sweep cannot disagree.
    """
    page = slot & ~0xFFF
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md_window = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    hits: list[tuple[int, int, str, str]] = []
    stops = ("b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz")

    for file_offset, vaddr, size in executable_sections(blob):
        data = blob[file_offset:file_offset + size]
        for insn in walk(md, data, vaddr):
            if insn.mnemonic != "adrp":
                continue
            match = ADRP_RE.match(insn.op_str)
            if not match:
                continue
            register, page_target = match.group(1), number(match.group(2))
            if page_target != page:
                continue

            window = data[insn.address - vaddr: insn.address - vaddr + 4 * 10]
            carried = None
            for probe in md_window.disasm(window, insn.address):
                if probe.address == insn.address:
                    continue
                if probe.mnemonic in stops or probe.mnemonic.startswith("b."):
                    break
                add = ADD_RE.match(probe.op_str)
                if add and probe.mnemonic == "add" and add.group(2) == register:
                    target = page_target + number(add.group(3))
                    if target == slot:
                        hits.append((insn.address, probe.address, probe.mnemonic, probe.op_str))
                    else:
                        carried = (add.group(1), target)
                    continue
                mem = MEM_RE.match(probe.op_str)
                if mem:
                    base = mem.group(2)
                    disp = number(mem.group(3)) if mem.group(3) else 0
                    if base == register and page_target + disp == slot:
                        hits.append((insn.address, probe.address, probe.mnemonic, probe.op_str))
                    elif carried and base == carried[0] and carried[1] + disp == slot:
                        hits.append((insn.address, probe.address, probe.mnemonic, probe.op_str))

    return hits


def find_slot(blob: bytes, slot: int, limit: int, offset: int, methods, sorted_rvas):
    hits = find_slot_refs(blob, slot)
    total = len(hits)
    page_hits = hits[offset:offset + limit]
    return total, page_hits, attribute(sorted_rvas, methods, 0)


def find_immediate(blob: bytes, immediate: int, mnemonics: set[str], limit: int, offset: int, methods, sorted_rvas):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    hits = []
    for file_offset, vaddr, size in executable_sections(blob):
        data = blob[file_offset:file_offset + size]
        for insn in walk(md, data, vaddr):
            if mnemonics and insn.mnemonic not in mnemonics:
                continue
            if not insn.op_str.startswith(("x", "w")):
                continue
            # Stack slots match every offset; they are never what this query means.
            if ", [sp" in insn.op_str or ", [wsp" in insn.op_str:
                continue
            for match in IMM_RE.finditer(insn.op_str):
                if number(match.group(1)) == immediate:
                    hits.append((insn.address, insn.mnemonic, insn.op_str))
                    break
    return len(hits), hits[offset:offset + limit]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--slot", help="slot address to find references to, e.g. 0x2A508E0")
    target.add_argument("--imm", help="immediate offset to find, e.g. 0x88")
    parser.add_argument("--insn", default="strb,str,ldr,strh,ldrh,ldrsw",
                        help="comma-separated mnemonics for --imm mode")
    parser.add_argument("--so", type=Path, default=DEFAULT_SO)
    parser.add_argument("--index-dir", type=Path, default=None, help="override the shared index directory")
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--offset", type=int, default=0)
    args = parser.parse_args()

    started = time.time()
    blob = args.so.read_bytes()
    index = il2cpp_index.load(args.so, args.index_dir)
    methods = index["methods"]
    sorted_rvas = sorted(int(key, 16) for key in methods)

    if args.slot:
        slot = number(args.slot)
        total, hits, _ = find_slot(blob, slot, args.limit, args.offset, methods, sorted_rvas)
        title = f"slot 0x{slot:X}"
    else:
        immediate = number(args.imm)
        names = {name.strip() for name in args.insn.split(",") if name.strip()}
        total, hits = find_immediate(blob, immediate, names, args.limit, args.offset, methods, sorted_rvas)
        title = f"immediate #0x{immediate:X} ({','.join(sorted(names))})"

    print(f"{title}  refs {total}  (showing {args.offset + 1}..{args.offset + len(hits)})  [addresses are RVAs]")
    for hit in hits:
        if args.slot:
            adrp_pc, ref_pc, mnemonic, operands = hit
            where = attribute(sorted_rvas, methods, ref_pc)
            print(f"0x{adrp_pc:08X}  {mnemonic:<7} {operands:<34} {where}   (+0x{ref_pc - adrp_pc:x})")
        else:
            address, mnemonic, operands = hit
            where = attribute(sorted_rvas, methods, address)
            print(f"0x{address:08X}  {mnemonic:<7} {operands:<34} {where}")
    elided = total - (args.offset + len(hits))
    if elided > 0:
        print(f"[+{elided} elided - use --offset {args.offset + len(hits)}]")
    print(f"[{time.time() - started:.1f}s over {args.so.name}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
