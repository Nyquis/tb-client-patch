#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Dump an ARM64 switch/jump table and resolve its cases.

Written for questions decompilation cannot answer, such as "which type ids take
the branch that sets isToggleBtn" - that is a table read, not a code read.

    pixi run jumptable --at 0x1A2B3C --count 40
    pixi run jumptable --at 0x1A2B3C --count 40 --mode rel-table --peek 3

Modes: abs (entries are addresses), rel-table (entry = table_va + value),
rel-each (entry = entry_va + value). Sizes 8/4/2/1 bytes.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

import il2cpp_index

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SO = ROOT / "work" / "il2cpp" / "libil2cpp.so"


def load_segments(blob: bytes) -> list[tuple[int, int, int]]:
    if blob[:4] != b"\x7fELF" or blob[4] != 2:
        raise SystemExit("not an ELF64 file")
    phoff = struct.unpack_from("<Q", blob, 0x20)[0]
    entsize = struct.unpack_from("<H", blob, 0x36)[0]
    count = struct.unpack_from("<H", blob, 0x38)[0]
    segments = []
    for index in range(count):
        base = phoff + index * entsize
        p_type = struct.unpack_from("<I", blob, base)[0]
        p_offset, p_vaddr = struct.unpack_from("<QQ", blob, base + 8)
        p_filesz = struct.unpack_from("<Q", blob, base + 32)[0]
        if p_type == 1 and p_filesz:
            segments.append((p_offset, p_vaddr, p_filesz))
    return segments


def va_to_offset(segments, va: int) -> int | None:
    for offset, vaddr, size in segments:
        if vaddr <= va < vaddr + size:
            return offset + (va - vaddr)
    return None


def hexint(value: int) -> str:
    return f"-0x{-value:X}" if value < 0 else f"0x{value:X}"


def method_for(rvas, methods, address: int) -> str:
    import bisect
    position = bisect.bisect_right(rvas, address) - 1
    if position < 0:
        return "?"
    return methods.get(f"0x{rvas[position]:X}", "?")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--at", required=True, help="table address (RVA)")
    parser.add_argument("--count", type=int, required=True, help="number of entries")
    parser.add_argument("--size", type=int, default=4, choices=[8, 4, 2, 1])
    parser.add_argument("--mode", default="abs", choices=["abs", "rel-table", "rel-each"])
    parser.add_argument("--peek", type=int, default=0, help="instructions to disassemble at each target")
    sign = parser.add_mutually_exclusive_group()
    sign.add_argument("--signed", action="store_true", help="force signed entries (default for rel-* modes)")
    sign.add_argument("--unsigned", action="store_true", help="force unsigned entries (default for abs)")
    parser.add_argument("--limit", type=int, default=64)
    parser.add_argument("--so", type=Path, default=DEFAULT_SO)
    parser.add_argument("--index-dir", type=Path, default=None, help="override the shared index directory")
    args = parser.parse_args()

    blob = args.so.read_bytes()
    segments = load_segments(blob)
    table_va = int(args.at, 16) if args.at.lower().startswith("0x") else int(args.at, 10)
    table_offset = va_to_offset(segments, table_va)
    if table_offset is None:
        raise SystemExit(f"table address 0x{table_va:X} is not in a mapped segment")

    # ARM64 switch tables reached by ldrsw hold *signed* 32-bit offsets from the
    # table base. Reading them unsigned lands 2-4 GB away and every row then
    # attributes to the wrong method, so the sign is not a preference: it follows
    # from the mode unless the caller overrides it.
    signed = args.signed or (not args.unsigned and args.mode != "abs")

    index = il2cpp_index.load(args.so, args.index_dir)
    methods = index["methods"]
    rvas = sorted(int(key, 16) for key in methods)
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    rows = min(args.count, args.limit)
    print(f"table 0x{table_va:X}  entries {args.count}  size {args.size}  mode {args.mode}  "
          f"{'signed' if signed else 'unsigned'}  (targets are RVAs)")
    for entry in range(rows):
        entry_va = table_va + entry * args.size
        offset = table_offset + entry * args.size
        chunk = blob[offset:offset + args.size]
        raw = int.from_bytes(chunk, "little", signed=signed)

        if args.mode == "abs":
            target = raw & ((1 << 64) - 1)
        elif args.mode == "rel-table":
            target = table_va + raw
        else:
            target = entry_va + raw

        mapped = va_to_offset(segments, target)
        if mapped is not None:
            label = method_for(rvas, methods, target)
            line = f"  [{entry:>3}] raw {hexint(raw):>14}  ->  0x{target:08X}  {label}"
        else:
            # Report, never guess: an unmapped target has no honest attribution.
            hint = ""
            alternate = int.from_bytes(chunk, "little", signed=not signed)
            alternate_target = (table_va + alternate if args.mode == "rel-table"
                                else entry_va + alternate if args.mode == "rel-each"
                                else alternate & ((1 << 64) - 1))
            if args.mode != "abs" and va_to_offset(segments, alternate_target) is not None:
                hint = f"  (as {'unsigned' if signed else 'signed'}: 0x{alternate_target:08X})"
            label = "unmapped" + hint
            line = f"  [{entry:>3}] raw {hexint(raw):>14}  ->  [unmapped]{hint}"
        print(line)

        if args.peek > 0:
            if mapped is None:
                print("        [target not mapped - nothing to disassemble]")
                continue
            window = blob[mapped:mapped + 4 * args.peek]
            shown = 0
            for insn in disassembler.disasm(window, target):
                print(f"        {insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}")
                shown += 1
                if shown >= args.peek:
                    break

    if args.count > rows:
        print(f"[+{args.count - rows} entries elided - raise --limit]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
