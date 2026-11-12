#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Structural audit of the enabled native cave patch sets.

``build_patch.py`` proves the original bytes still match and that a patch was
applied; ``verify.py`` proves nothing else in the APK moved.  Neither can see
whether a *cave* is coherent.  This audit disassembles what the JSON actually
declares and fails on the defects that have already cost us builds:

* a hook whose branch still points at a stale/empty cave;
* a hook that branches into the middle of another patch;
* a cave that overlaps another patch;
* a cave that writes a register the caller still needs afterwards (the x8
  clobber that turned ``PlayerPrefs.SetInt``'s key into a GameManager object);
* a pref key whose value domain was widened but whose readers were only
  partially patched (the speed key has two sites: the saver and InitBtn's
  ``value == 1`` loader);
* a cave whose branch leaves it to an unexpected address, lands inside another
  patch, or calls an address that is not a method entry;
* a cave that dereferences a literal/usage slot the replaced code never used
  (the uninitialised ``" / "`` / ``[ffffff]`` slots) unless acknowledged;
* any use of ``x18``, which is the platform register on Android/AArch64.

Inputs are read-only: ``patches/native_*.json``, the reference
``work/il2cpp/libil2cpp.so`` and ``work/dump/script.json``.  Exit code 0 means
every check passed.  ``tools/audit_selftest.py`` proves this file still fails on
each of those defects.
"""

from __future__ import annotations

import bisect
import glob
import json
import re
import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

from find_refs import find_slot_refs

ROOT = Path(__file__).resolve().parent.parent
REFERENCE = ROOT / "work" / "il2cpp" / "libil2cpp.so"

# libil2cpp code range scanned for metadata-usage references
CODE_LO, CODE_HI = 0xD00000, 0x2100000

WRITE_DEST = {
    "mov", "movz", "movk", "movn", "add", "adds", "sub", "subs", "and", "ands",
    "orr", "eor", "ubfx", "sbfx", "csel", "cset", "lsl", "lsr", "asr", "sxtw",
    "uxtb", "uxth", "ldr", "ldrb", "ldrh", "ldrsw", "ldrsb", "ldrsh", "adrp",
    "adr", "mrs",
}

STORE_DEST = {
    "str", "strb", "strh", "stp", "stur", "sturb", "sturh", "sturq", "strq",
    "strs", "strd", "stp",
}

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"FAIL: {msg}")


def norm(reg: str | None) -> str | None:
    if reg and reg[0] == "w":
        return "x" + reg[1:]
    return reg


def written_regs(code: bytes, base: int) -> set[str]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    out: set[str] = set()
    saved: set[str] = set()      # regs stored to [sp, ...]
    restored: set[str] = set()   # regs loaded from [sp, ...]
    for ins in md.disasm(code, base):
        if ins.mnemonic in STORE_DEST and len(ins.operands) >= 2:
            dst, mem = ins.operands[0], ins.operands[1]
            if (dst.type == ARM64_OP_REG and mem.type == ARM64_OP_MEM
                    and ins.reg_name(mem.mem.base) == 'sp'):
                saved.add(norm(ins.reg_name(dst.reg)) or "")
        if ins.mnemonic in WRITE_DEST and ins.operands:
            op = ins.operands[0]
            if op.type == ARM64_OP_REG:
                out.add(norm(ins.reg_name(op.reg)) or "")
                if (len(ins.operands) >= 2
                        and ins.operands[1].type == ARM64_OP_MEM
                        and ins.reg_name(ins.operands[1].mem.base) == 'sp'):
                    restored.add(norm(ins.reg_name(op.reg)) or "")
    # A register the cave saves to the stack and reloads is preserved: the hook
    # contract is about the value on return, not about never touching it.
    return out - (saved & restored)


def adrp_target(pc: int, word: int) -> int:
    imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def slot_refs(reference: bytes, slot: int) -> list[int]:
    """ADRP addresses that materialise the metadata-usage slot `slot`.

    Real binaries go through find_refs.find_slot_refs: the sweep and this gate
    must agree, or a site can be patched, invisible to the audit, and silently
    unaccounted for (exactly how the speed key's third reader stayed hidden).
    The selftest fixtures are synthetic buffers rather than ELF images, so they
    fall back to a flat word scan over the configured code range.
    """
    if reference[:4] == b"\x7fELF" and len(reference) > 5 and reference[4] == 2:
        return [adrp_pc for adrp_pc, _ref_pc, _mnemonic, _operands in find_slot_refs(reference, slot)]
    return legacy_slot_refs(reference, slot)


def legacy_slot_refs(reference: bytes, slot: int) -> list[int]:
    """Adjacent adrp+ldr scan used only for the synthetic selftest fixtures."""
    page = slot & ~0xFFF
    out: list[int] = []
    for pc in range(CODE_LO, CODE_HI, 4):
        word = struct.unpack_from("<I", reference, pc)[0]
        if (word & 0x9F000000) != 0x90000000:
            continue
        if adrp_target(pc, word) != page:
            continue
        nxt = struct.unpack_from("<I", reference, pc + 4)[0]
        if (nxt & 0xFFC00000) != 0xF9400000:
            continue
        if ((nxt >> 5) & 31) != (word & 31):
            continue
        if page + ((nxt >> 10) & 0xFFF) * 8 == slot:
            out.append(pc)
    return out


def branch_target(code: bytes, rva: int) -> int | None:
    """Resolve an unconditional b/bl, else None."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    ins = next(md.disasm(code, rva), None)
    if ins is None or ins.mnemonic not in ("b", "bl"):
        return None
    ops = ins.op_str.split("#")
    if len(ops) < 2:
        return None
    return int(ops[1], 16)


def mentions_x18(code: bytes, base: int) -> list[int]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    hits = []
    for ins in md.disasm(code, base):
        hit = False
        for op in ins.operands:
            if op.type == ARM64_OP_REG and ins.reg_name(op.reg) in ("x18", "w18"):
                hit = True
            elif op.type == ARM64_OP_MEM and ins.reg_name(op.mem.base) in ("x18", "w18"):
                hit = True
        if hit:
            hits.append(ins.address)
    return hits


def audit_prefs_keys(path: Path, spec: dict, by_offset: dict, reference: bytes) -> None:
    """Every reference to a widened pref key must be accounted for.

    Changing a stored value from 0/1 to 0/1/2 is only safe if *every* reader
    and writer of that key is patched.  The speed key (0x2AAA660) has three
    sites: InitBtn loads it with a `value == 1` bool conversion, OnClickBtn
    saves it, and the BattleManager StartBattle iterator re-reads it.  The
    loader was missed once and x4 came back as x2 on restart; the iterator was
    missed by this audit for a long time because the old matcher only accepted
    an adrp *immediately* followed by its ldr.  Both matchers now share
    find_refs.find_slot_refs.
    """
    for key in spec.get("prefs_keys") or []:
        slot = int(key["slot"], 16)
        sites = key.get("sites") or []
        declared = {int(s["ref"], 16) for s in sites}
        actual = set(slot_refs(reference, slot))
        if actual != declared:
            missing = sorted(actual - declared)
            stale = sorted(declared - actual)
            fail(f"{path.name}: prefs key 0x{slot:x} site mismatch "
                 f"missing={[hex(a) for a in missing]} stale={[hex(a) for a in stale]}")
        for s in sites:
            ref = int(s["ref"], 16)
            patched = int(s["patched"], 16)
            if patched not in by_offset:
                fail(f"{path.name}: prefs key 0x{slot:x} site 0x{ref:x} declares "
                     f"0x{patched:x} but that address is not patched")
            elif not (ref <= patched < ref + 0x80):
                fail(f"{path.name}: prefs key 0x{slot:x} site 0x{ref:x} patch "
                     f"0x{patched:x} is not near enough to be its consumer")
        print(f"prefs 0x{slot:x}: {len(sites)} site(s) patched - {key['name']}")


def cave_slots(code: bytes, base: int) -> list[int]:
    """Metadata-usage / literal slots loaded by an adrp+ldr pair in `code`."""
    words = [struct.unpack_from("<I", code, i)[0] for i in range(0, len(code) - 3, 4)]
    out: list[int] = []
    for i, word in enumerate(words[:-1]):
        if (word & 0x9F000000) != 0x90000000:
            continue
        nxt = words[i + 1]
        if (nxt & 0xFFC00000) != 0xF9400000:
            continue
        if ((nxt >> 5) & 31) != (word & 31):
            continue
        out.append(adrp_target(base + i * 4, word) + ((nxt >> 10) & 0xFFF) * 8)
    return out


def load_string_literals() -> set[int]:
    path = ROOT / "work" / "dump" / "stringliteral.json"
    if not path.is_file():
        return set()
    spec = json.loads(path.read_text(encoding="utf-8-sig"))
    return {int(e["address"], 16) for e in spec}


def load_methods() -> dict[int, str]:
    path = ROOT / "work" / "dump" / "script.json"
    if not path.is_file():
        return {}
    spec = json.loads(path.read_text(encoding="utf-8-sig"))
    return {int(e["Address"]): e["Name"] for e in spec["ScriptMethod"]}


def method_range(addr: int, methods: dict[int, str], limit: int) -> tuple[int, int]:
    starts = sorted(methods)
    if not starts:
        return addr, addr
    i = bisect.bisect_right(starts, addr) - 1
    lo = starts[max(i, 0)]
    hi = starts[i + 1] if i + 1 < len(starts) else limit
    return lo, hi


def insn_target(ins) -> int | None:
    """Branch target: the last immediate operand (tbz has a bit index first)."""
    if not ins.operands:
        return None
    op = ins.operands[-1]
    return op.imm if op.type == ARM64_OP_IMM else None


def audit_branches(path: Path, off: int, code: bytes, spans, allowed) -> None:
    """A cave may only leave itself through declared, aligned targets."""
    end = off + len(code)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    for ins in md.disasm(code, off):
        mn = ins.mnemonic
        if mn in ("bl", "br", "blr", "ret"):
            continue
        if mn not in ("b", "cbz", "cbnz", "tbz", "tbnz") and not mn.startswith("b."):
            continue
        target = insn_target(ins)
        if target is None:
            continue
        if ins.mnemonic == "b":
            if off <= target < end:
                continue
            if target % 4:
                fail(f"{path.name}: cave 0x{off:x} branches to unaligned 0x{target:x}")
                continue
            for s0, s1 in spans:
                if s0 < target < s1:
                    fail(f"{path.name}: cave 0x{off:x} branches into the middle of "
                         f"the patch at 0x{s0:x} (0x{target:x})")
            if allowed is not None and target not in allowed:
                fail(f"{path.name}: cave 0x{off:x} branches to undeclared 0x{target:x}")
        elif not (off <= target < end):
            fail(f"{path.name}: cave 0x{off:x} has a conditional exit to 0x{target:x}")


def audit_calls(path: Path, off: int, code: bytes, methods: dict[int, str],
                cave_offsets) -> None:
    if not methods:
        return
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    for ins in md.disasm(code, off):
        if ins.mnemonic != "bl":
            continue
        target = insn_target(ins)
        if target is None or target in methods or target in cave_offsets:
            continue
        if target < CODE_LO:
            # runtime support region (class init, allocators, ...): not scripted
            continue
        fail(f"{path.name}: cave 0x{off:x} calls 0x{target:x}, not a method entry")


def audit_literals(path: Path, cave_off: int, cave_code: bytes, hook_off: int,
                   reference: bytes, methods: dict[int, str], declared) -> None:
    """A cave should not dereference a slot the replaced code never touched.

    Literal/usage slots are filled lazily; a slot the surrounding method never
    loaded may still be null when the cave runs (that produced ``x3x4``).  Any
    such slot has to be acknowledged in the patch JSON (``literal_risk``).
    """
    lo, hi = method_range(hook_off, methods, len(reference))
    if hi <= lo:
        return
    used = set(cave_slots(reference[lo:hi], lo))
    literals = load_string_literals()
    risky = [s for s in cave_slots(cave_code, cave_off)
             if s in literals and s not in used]
    if not risky:
        return
    acked = {int(x, 16) for x in declared or []}
    for slot in risky:
        if slot in acked:
            print(f"literal 0x{slot:x}: acknowledged by hook 0x{hook_off:x}")
        else:
            fail(f"{path.name}: cave 0x{cave_off:x} uses slot 0x{slot:x} which "
                 f"the method at 0x{lo:x} never loads (acknowledge in literal_risk)")


def audit_file(path: Path, reference: bytes) -> int:
    spec = json.loads(path.read_text(encoding="utf-8"))
    patches = spec.get("patches") or []
    if not spec.get("enabled"):
        print(f"skip  {path.name} (disabled)")
        return 0

    entries = []
    for p in patches:
        off = int(p["offset"], 16)
        code = bytes.fromhex(p["patch"])
        entries.append((off, code, p))
    entries.sort(key=lambda e: e[0])

    by_offset = {off: (code, p) for off, code, p in entries}
    spans = [(off, off + len(code)) for off, code, _ in entries]

    # 1. no overlap between patches
    for (a0, a1), (b_off, _b1) in zip(spans, spans[1:]):
        if b_off < a1:
            fail(f"{path.name}: 0x{a0:x}..0x{a1:x} overlaps 0x{b_off:x}")

    # 2. caves start as zero-filled padding in the reference.
    #    A patch declared `kind: "reloc"` is not a cave: it rewrites a relocation
    #    addend (live data) on purpose, e.g. retargeting DT_INIT_ARRAY[0].
    for off, code, p in entries:
        if len(code) < 8:
            continue
        if p.get("kind") == "reloc":
            continue
        if reference[off:off + len(code)] != b"\x00" * len(code):
            fail(f"{path.name}: cave 0x{off:x} is not zero in the reference")

    # 3. hook targets + live registers
    hooks = 0
    cave_hook: dict[int, tuple[int, dict]] = {}
    for off, code, p in entries:
        if len(code) != 4:
            continue
        target = branch_target(code, off)
        if target is None or target not in by_offset:
            if p.get("hook"):
                where = "does not branch" if target is None else f"targets 0x{target:x}"
                fail(f"{path.name}: hook 0x{off:x} is marked as a hook but {where}, "
                     "which is not a cave in this set")
            continue
        # A 4-byte instruction that jumps into a declared cave is a hook by shape.
        # Require the declaration, so a patch set cannot quietly skip the
        # target/live-register checks by leaving the field out.
        if p.get("hook") is not True:
            reason = p.get("reason") or p.get("note")
            if p.get("hook") is False and reason:
                print(f"note  0x{off:x} -> 0x{target:x} declared hook:false ({reason})")
            else:
                fail(f"{path.name}: 0x{off:x} branches into cave 0x{target:x} but is not "
                     'declared hook: true (add "hook": true, or "hook": false plus a reason)')
                continue
        hooks += 1
        cave_hook[target] = (off, p)
        cave_code, _cave = by_offset[target]
        if target % 4:
            fail(f"{path.name}: hook 0x{off:x} targets unaligned 0x{target:x}")
        if not cave_code:
            fail(f"{path.name}: hook 0x{off:x} targets empty cave 0x{target:x}")
        live = {norm(x.strip()) for x in (p.get("live") or "").split(",") if x.strip()}
        if live:
            clash = written_regs(cave_code, target) & live
            if clash:
                fail(f"{path.name}: cave 0x{target:x} clobbers live {sorted(clash)} "
                     f"(hook 0x{off:x})")
        print(f"hook  0x{off:x} -> 0x{target:x}  live={sorted(live) or '-'}")

    # 4. platform register
    for off, code, _p in entries:
        if len(code) < 8:
            continue
        hits = mentions_x18(code, off)
        if hits:
            fail(f"{path.name}: cave 0x{off:x} uses x18/w18 at "
                 + ", ".join(hex(h) for h in hits))

    # 5. cave control flow, call targets and literal provenance
    methods = load_methods()
    for off, code, p in entries:
        if len(code) < 8:
            continue
        hook_off, hook_p = cave_hook.get(off, (None, {}))
        raw_targets = hook_p.get("targets") or p.get("targets")
        allowed = {int(x, 16) for x in raw_targets} if raw_targets else None
        audit_branches(path, off, code, spans, allowed)
        audit_calls(path, off, code, methods, by_offset)
        if hook_off is not None:
            declared = hook_p.get("literal_risk") or p.get("literal_risk")
            audit_literals(path, off, code, hook_off, reference, methods, declared)

    print(f"ok    {path.name}: {len(entries)} patches, {hooks} hooks")
    audit_prefs_keys(path, spec, by_offset, reference)
    return hooks


def main() -> int:
    if not REFERENCE.is_file():
        print(f"FAIL: reference not found: {REFERENCE}")
        return 2
    reference = REFERENCE.read_bytes()

    files = sorted(Path(p) for p in glob.glob(str(ROOT / "patches" / "native_*.json")))
    total = 0
    for f in files:
        if "payload" in f.name:
            continue
        total += audit_file(f, reference)

    print()
    if failures:
        print(f"AUDIT FAILED: {len(failures)} problem(s)")
        return 1
    print(f"PASS: {total} cave hooks audited across {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
