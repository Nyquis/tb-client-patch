#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Make a shipped ELF64/ARM64 shared library 16 KB page compatible.

Everything here is derived from the user's own APK: no third-party binary is
involved and no code is invented.

Two repairs, chosen per library:

1. **Alignment only** - every ``PT_LOAD`` gets ``p_align = 0x4000``. This is
   enough when the linker already placed the load segments in separate 16 KB
   pages (``libunity.so``: segments at ``0x0`` and ``0xd6c000``).

2. **Alignment + segment move** - when two ``PT_LOAD``s share one 16 KB page the
   loader would map that page twice with conflicting protections, so the later
   segment has to move to the next free page. Moving a segment means every
   address that points into it must follow, and that is all this module does:

   * ``p_offset``/``p_vaddr`` of the segment and of every program header that
     covers it (``PT_DYNAMIC``);
   * dynamic pointer tags (``DT_PLTGOT``, ``DT_INIT_ARRAY``, ...);
   * ``R_*`` relocation offsets and addends, ``DT_RELR`` entries;
   * dynamic symbol values;
   * ``ADRP`` instructions whose 4 KB target page is inside the moved
     segment (the ``.plt`` stubs and the handful of direct data references).

   Section headers are dropped afterwards: they would be stale, and the loader
   never reads them.

The move keeps the segment's low 12 bits, so ``#imm``/``ldr`` offsets in the
instructions stay valid; only the page changes. ``explain()`` re-derives every
changed word and classifies it, and ``verify`` uses that to prove nothing but
declared metadata and declared ADRP pages changed.

Usage:
    python tools/elf16k.py input.apk            # report every arm64 library
    python tools/elf16k.py libmain.so --out x.so
"""

from __future__ import annotations

import argparse
import struct
import sys
import zipfile
from pathlib import Path

PAGE = 0x4000
ADRP_PAGE = 0x1000
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
SHF_EXECINSTR = 0x4

# Dynamic tags whose value is a virtual address.
_PTR_TAGS = {
    3,            # DT_PLTGOT
    4,            # DT_HASH
    5,            # DT_STRTAB
    6,            # DT_SYMTAB
    7,            # DT_RELA
    12,           # DT_INIT
    13,           # DT_FINI
    17,           # DT_REL
    23,           # DT_JMPREL
    25,           # DT_INIT_ARRAY
    26,           # DT_FINI_ARRAY
    32,           # DT_PREINIT_ARRAY
    36,           # DT_RELR
    0x6FFFFFF0,   # DT_VERSYM
    0x6FFFFFFC,   # DT_VERDEF
    0x6FFFFFFE,   # DT_VERNEED
}

DT_HASH, DT_STRTAB, DT_SYMTAB, DT_SYMENT = 4, 5, 6, 11
DT_RELA, DT_RELASZ, DT_RELAENT = 7, 8, 9
DT_REL, DT_RELSZ, DT_RELENT = 17, 18, 19
DT_PLTRELSZ, DT_JMPREL = 2, 23
DT_RELR, DT_RELRSZ, DT_RELRENT = 36, 35, 37

ADRP_MASK, ADRP_OPCODE = 0x9F000000, 0x90000000


def _align_down(x: int, a: int = PAGE) -> int:
    return x - x % a


def _align_up(x: int, a: int = PAGE) -> int:
    return _align_down(x + a - 1, a)


def _adrp(word: int) -> tuple[int, int] | None:
    """Decode an ADRP: (rd, page delta relative to the instruction page)."""
    if word & ADRP_MASK != ADRP_OPCODE:
        return None
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return word & 0x1F, imm


def _encode_adrp(rd: int, imm: int) -> int:
    if not -(1 << 20) <= imm < (1 << 20):
        raise ValueError(f"ADRP page {imm} out of range")
    immlo = imm & 0x3
    immhi = (imm >> 2) & 0x7FFFF
    return ADRP_OPCODE | (immlo << 29) | (immhi << 5) | (rd & 0x1F)


class Elf:
    """Minimal ELF64-LE reader/writer over a mutable bytearray."""

    def __init__(self, data: bytes | bytearray):
        self.d = bytearray(data)
        if self.d[:4] != b"\x7fELF" or self.d[4] != 2 or self.d[5] != 1:
            raise ValueError("not a little-endian ELF64 file")
        (self.machine,) = struct.unpack_from("<H", self.d, 0x12)
        if self.machine != 0xB7:
            raise ValueError(f"not AArch64 (e_machine={self.machine:#x})")
        self.phoff, = struct.unpack_from("<Q", self.d, 0x20)
        self.shoff, = struct.unpack_from("<Q", self.d, 0x28)
        self.phentsize, = struct.unpack_from("<H", self.d, 0x36)
        self.phnum, = struct.unpack_from("<H", self.d, 0x38)
        self.shentsize, = struct.unpack_from("<H", self.d, 0x3A)
        self.shnum, = struct.unpack_from("<H", self.d, 0x3C)
        self.shstrndx, = struct.unpack_from("<H", self.d, 0x3E)
        if self.phentsize != 56:
            raise ValueError(f"unexpected e_phentsize {self.phentsize}")
        self.ph = [self.phdr(i) for i in range(self.phnum)]

    def phdr(self, i: int) -> dict:
        o = self.phoff + i * self.phentsize
        t, fl, off, va, pa, fs, ms, al = struct.unpack_from("<IIQQQQQQ", self.d, o)
        return {"type": t, "flags": fl, "off": off, "va": va, "pa": pa,
                "filesz": fs, "memsz": ms, "align": al, "at": o}

    def set_phdr(self, i: int, **kw) -> None:
        p = self.ph[i]
        p.update(kw)
        struct.pack_into("<IIQQQQQQ", self.d, p["at"], p["type"], p["flags"],
                         p["off"], p["va"], p["pa"], p["filesz"], p["memsz"],
                         p["align"])

    def loads(self) -> list[int]:
        return [i for i, p in enumerate(self.ph) if p["type"] == PT_LOAD]

    def va_to_off(self, va: int) -> int | None:
        for i in self.loads():
            p = self.ph[i]
            if p["va"] <= va < p["va"] + p["memsz"]:
                return p["off"] + (va - p["va"])
        return None

    def dynamic(self) -> tuple[int, int]:
        for p in self.ph:
            if p["type"] == PT_DYNAMIC:
                return p["off"], p["filesz"]
        raise ValueError("no PT_DYNAMIC")

    def dyn_entries(self) -> list[tuple[int, int, int]]:
        off, size = self.dynamic()
        out = []
        for k in range(0, size - 15, 16):
            tag, val = struct.unpack_from("<QQ", self.d, off + k)
            out.append((tag, val, off + k))
            if tag == 0:
                break
        return out

    def dyn_tag(self, tag: int) -> int | None:
        for t, v, _ in self.dyn_entries():
            if t == tag:
                return v
        return None

    def sections(self) -> list[dict]:
        """Section headers of the *original* file (empty when stripped)."""
        return [dict(zip(("name", "type", "flags", "addr", "off", "size",
                          "link", "info", "align", "entsize"), row))
                for row in self.raw_sections()]

    def raw_sections(self) -> list[tuple]:
        if not self.shoff or not self.shnum:
            return []
        out = []
        for i in range(self.shnum):
            o = self.shoff + i * self.shentsize
            out.append(struct.unpack_from("<IIQQQQIIQQ", self.d, o))
        return out

    def exec_ranges(self) -> list[tuple[int, int]]:
        """[addr, addr+size) of every SHF_EXECINSTR section, merged."""
        spans = sorted((s["addr"], s["addr"] + s["size"]) for s in self.sections()
                       if s["flags"] & SHF_EXECINSTR and s["type"] == 1 and s["size"])
        merged: list[list[int]] = []
        for lo, hi in spans:
            if merged and lo <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        return [(lo, hi) for lo, hi in merged]

    def reloc_tables(self) -> list[tuple[int, int, int]]:
        """(file offset, byte length, entry size) of every relocation table."""
        out = []
        for addr_tag, size_tag, ent_tag, default in (
            (DT_RELA, DT_RELASZ, DT_RELAENT, 24),
            (DT_REL, DT_RELSZ, DT_RELENT, 16),
            (DT_RELR, DT_RELRSZ, DT_RELRENT, 8),
        ):
            addr = self.dyn_tag(addr_tag)
            if addr is None:
                continue
            off = self.va_to_off(addr)
            if off is None:
                continue
            out.append((off, self.dyn_tag(size_tag) or 0,
                        self.dyn_tag(ent_tag) or default))
        plt = self.dyn_tag(DT_JMPREL)
        if plt is not None:
            off = self.va_to_off(plt)
            if off is not None:
                out.append((off, self.dyn_tag(DT_PLTRELSZ) or 0,
                            self.dyn_tag(DT_RELAENT) or 24))
        return out

    def dynsym_range(self) -> tuple[int, int] | None:
        sym = self.dyn_tag(DT_SYMTAB)
        if sym is None:
            return None
        off = self.va_to_off(sym)
        if off is None:
            return None
        ent = self.dyn_tag(DT_SYMENT) or 24
        count = None
        h = self.dyn_tag(DT_HASH)
        if h is not None:
            hoff = self.va_to_off(h)
            if hoff is not None:
                count = struct.unpack_from("<I", self.d, hoff + 4)[0]
        if not count:
            raise ValueError("no DT_HASH: cannot size .dynsym")
        return off, count * ent


def problems(blob: bytes) -> list[str]:
    """Every PT_LOAD must be 16 KB aligned, congruent and not share a page."""
    e = Elf(blob)
    bad = []
    cursor = 0
    for i in e.loads():
        p = e.ph[i]
        if p["align"] < PAGE:
            bad.append(f"LOAD{i} p_align {p['align']:#x} < 0x{PAGE:x}")
        if (p["off"] - p["va"]) % PAGE:
            bad.append(f"LOAD{i} p_offset {p['off']:#x} not congruent to "
                       f"p_vaddr {p['va']:#x} mod 0x{PAGE:x}")
        if _align_down(p["va"]) < cursor:
            bad.append(f"LOAD{i} va {p['va']:#x} shares a 16 KB page with the "
                       f"previous segment (ends {cursor:#x})")
        cursor = max(cursor, _align_up(p["va"] + p["memsz"]))
    return bad


def _fixup_relocs(e: Elf, lo: int, hi: int, delta: int) -> None:
    """Shift relocation offsets/addends, DT_RELR words and dynamic symbols."""
    for off, size, ent in e.reloc_tables():
        for o in range(off, off + size - (ent - 1), ent):
            if ent == 24:
                r_off, info, addend = struct.unpack_from("<QQq", e.d, o)
                new_off = r_off + delta if lo <= r_off < hi else r_off
                new_add = addend + delta if lo <= addend < hi else addend
                if (new_off, new_add) != (r_off, addend):
                    struct.pack_into("<QQq", e.d, o, new_off, info, new_add)
            elif ent == 16:
                r_off, info = struct.unpack_from("<QQ", e.d, o)
                if lo <= r_off < hi:
                    struct.pack_into("<QQ", e.d, o, r_off + delta, info)
            else:
                (val,) = struct.unpack_from("<Q", e.d, o)
                if lo <= val < hi:
                    struct.pack_into("<Q", e.d, o, val + delta)
    sym = e.dynsym_range()
    if sym:
        off, size = sym
        for o in range(off, off + size, 24):
            name, info, other, shndx, val, sz = struct.unpack_from("<IBBHQQ", e.d, o)
            if lo <= val < hi:
                struct.pack_into("<IBBHQQ", e.d, o, name, info, other, shndx,
                                 val + delta, sz)


def _rebase_adrp(e: Elf, old_range: tuple[int, int], delta: int) -> int:
    """Retarget ADRP instructions that point into the moved segment."""
    lo, hi = old_range
    lo_page, hi_page = _align_down(lo, ADRP_PAGE), _align_up(hi, ADRP_PAGE)
    # Only whole 4 KB pages may be retargeted, and no *other* segment may share
    # one of those pages (its references must not move).
    for page in range(lo_page, hi_page, ADRP_PAGE):
        for i in e.loads():
            p = e.ph[i]
            other = (p["va"], p["va"] + p["memsz"])
            if other == (lo, hi):
                continue
            if other[0] < page + ADRP_PAGE and other[1] > page:
                raise ValueError(f"page {page:#x} of the moved segment is "
                                 f"shared with LOAD{i} ({other[0]:#x}..{other[1]:#x})")
    changed = 0
    for sec_lo, sec_hi in e.exec_ranges():
        off = e.va_to_off(sec_lo)
        if off is None:
            raise ValueError(f"exec section at {sec_lo:#x} is not mapped")
        page_fixups = []
        for va in range(sec_lo, sec_hi, 4):
            (word,) = struct.unpack_from("<I", e.d, off + (va - sec_lo))
            dec = _adrp(word)
            if dec is None:
                continue
            rd, imm = dec
            target = (va & ~(ADRP_PAGE - 1)) + (imm << 12)
            if lo_page <= target < hi_page:
                page_fixups.append((va, rd, imm))
        for va, rd, imm in page_fixups:
            e.d[off + (va - sec_lo):off + (va - sec_lo) + 4] = \
                struct.pack("<I", _encode_adrp(rd, imm + delta // ADRP_PAGE))
            changed += 1
    return changed


def _metadata_spans(e: Elf) -> list[tuple[int, int, str]]:
    """File ranges a transform is allowed to rewrite, with a label."""
    spans = [(0, e.phoff + e.phnum * e.phentsize, "program headers")]
    for p in e.ph:
        if p["type"] == PT_DYNAMIC:
            spans.append((p["off"], p["off"] + p["filesz"], "dynamic table"))
    for off, size, _ent in e.reloc_tables():
        spans.append((off, off + size, "relocation table"))
    sym = e.dynsym_range()
    if sym:
        spans.append((sym[0], sym[0] + sym[1], "dynamic symbols"))
    return spans


def transform(blob: bytes, *, strip_sections: bool = False) -> bytes:
    """Return ``blob`` with every PT_LOAD 16 KB compatible."""
    original = bytes(blob)
    e = Elf(blob)
    if not problems(e.d):
        return _strip_sections(original) if strip_sections else original

    for i in e.loads():
        if e.ph[i]["align"] < PAGE:
            e.set_phdr(i, align=PAGE)

    cursor = 0
    moves: list[tuple[int, int, int]] = []      # (old_va, old_end, delta)
    for i in e.loads():
        p = e.ph[i]
        needs_move = (_align_down(p["va"]) < cursor) or ((p["off"] - p["va"]) % PAGE)
        if needs_move:
            new_va = max(_align_up(p["va"]), cursor)
            if new_va == p["va"]:
                new_va += PAGE
            delta = new_va - p["va"]
            old_va, old_off = p["va"], p["off"]
            old_end = old_va + p["memsz"]
            new_off = old_off + delta

            # 1. Move the bytes first so later reads see the new copy.
            data = bytes(e.d[old_off:old_off + p["filesz"]])
            if len(e.d) < new_off + len(data):
                e.d.extend(b"\0" * (new_off + len(data) - len(e.d)))
            e.d[new_off:new_off + len(data)] = data
            e.set_phdr(i, off=new_off, va=new_va, pa=p["pa"] + delta, align=PAGE)

            # 2. Program headers that cover the moved range follow it.
            for j, q in enumerate(e.ph):
                if j == i or q["type"] in (0, PT_INTERP):
                    continue
                if old_va <= q["va"] < old_end:
                    e.set_phdr(j, va=q["va"] + delta, pa=q["pa"] + delta,
                               off=q["off"] + delta,
                               align=(PAGE if q["type"] == PT_LOAD else q["align"]))

            # 3. Addresses stored in the file that point into the range.
            for tag, val, at in e.dyn_entries():
                if tag in _PTR_TAGS and old_va <= val < old_end:
                    struct.pack_into("<Q", e.d, at + 8, val + delta)
            _fixup_relocs(e, old_va, old_end, delta)
            _rebase_adrp(e, (old_va, old_end), delta)

            # 4. The vacated range keeps no stale copy.
            shared = any(q["type"] == PT_LOAD and q["off"] < old_off + len(data)
                         and q["off"] + q["filesz"] > old_off
                         for k, q in enumerate(e.ph) if k != i)
            if not shared:
                e.d[old_off:old_off + len(data)] = b"\0" * len(data)
            moves.append((old_va, old_end, delta))
        last = e.ph[i]
        cursor = max(cursor, _align_up(last["va"] + last["memsz"]))

    out = _rehome_sections(original, e, moves, strip=strip_sections)
    after = problems(out)
    if after:
        raise ValueError("transform did not converge: " + "; ".join(after))
    return out


def _rehome_sections(original: bytes, e: Elf, moves: list[tuple[int, int, int]],
                     *, strip: bool) -> bytes:
    """Keep section headers usable after a segment move.

    Artifact: some loaders (Houdini's ARM64 translator on x86 host emulators)
    walk the section table; a library whose sections were dropped will not
    load there. So sections are rewritten: allocated ones inside a moved
    segment follow it, the rest are copied after the last load and the section
    header table is rewritten at the end of the file.
    """
    if strip or not moves:
        d = bytearray(e.d)
        end = max(e.ph[i]["off"] + e.ph[i]["filesz"] for i in e.loads())
        if strip:
            del d[end:]
            struct.pack_into("<Q", d, 0x28, 0)
            struct.pack_into("<H", d, 0x3A, 0)
            struct.pack_into("<H", d, 0x3C, 0)
            struct.pack_into("<H", d, 0x3E, 0)
        return bytes(d)

    raw = Elf(original).raw_sections()
    d = bytearray(e.d)
    end = max(e.ph[i]["off"] + e.ph[i]["filesz"] for i in e.loads())
    del d[end:]

    rows = []
    for name, typ, flags, addr, off, size, link, info, align, entsize in raw:
        if flags & 0x2 or typ == 8:          # SHF_ALLOC or SHT_NOBITS
            addr2, off2 = addr, off
            for lo, hi, delta in moves:
                if lo <= addr < hi:
                    addr2, off2 = addr + delta, off + delta
                    break
            rows.append([name, typ, flags, addr2, off2, size, link, info, align, entsize])
            continue
        # Non-allocated section: copy it after the loadable data.
        pos = _align_up(len(d), max(1, align))
        d.extend(b"\0" * (pos - len(d)))
        d.extend(original[off:off + size])
        rows.append([name, typ, flags, addr, pos, size, link, info, align, entsize])

    table = _align_up(len(d), 8)
    d.extend(b"\0" * (table - len(d)))
    for row in rows:
        d.extend(struct.pack("<IIQQQQIIQQ", *row))
    struct.pack_into("<Q", d, 0x28, table)
    return bytes(d)


def _strip_sections(blob: bytes) -> bytes:
    d = bytearray(blob)
    e = Elf(d)
    end = max(e.ph[i]["off"] + e.ph[i]["filesz"] for i in e.loads())
    del d[end:]
    struct.pack_into("<Q", d, 0x28, 0)
    struct.pack_into("<H", d, 0x3A, 0)
    struct.pack_into("<H", d, 0x3C, 0)
    struct.pack_into("<H", d, 0x3E, 0)
    return bytes(d)


def explain(original: bytes, patched: bytes) -> list[tuple[str, str, int]]:
    """Classify every byte that differs, by virtual address.

    Returns ``(kind, library-relative note, va)`` records. ``kind`` is one of
    ``phdr``, ``dynamic``, ``reloc``, ``dynsym``, ``adrp`` - anything left over
    is returned as ``unexpected`` so the caller can fail.
    """
    a, b = Elf(original), Elf(patched)
    la, lb = a.loads(), b.loads()
    if len(la) != len(lb):
        return [("unexpected", f"PT_LOAD count {len(la)} -> {len(lb)}", 0)]

    allowed = [(lo, hi, {
        "program headers": "phdr", "dynamic table": "dynamic",
        "relocation table": "reloc", "dynamic symbols": "dynsym",
    }[label]) for lo, hi, label in _metadata_spans(a)]
    execranges = a.exec_ranges()

    out = []
    shift = next((b.ph[j]["va"] - a.ph[i]["va"]
                  for i, j in zip(la, lb)
                  if b.ph[j]["va"] != a.ph[i]["va"]), 0)
    for k, (i, j) in enumerate(zip(la, lb)):
        pa, pb = a.ph[i], b.ph[j]
        da = bytes(a.d[pa["off"]:pa["off"] + pa["filesz"]])
        db = bytes(b.d[pb["off"]:pb["off"] + pb["filesz"]])
        # Compare against the original VA space (the move shifts offsets too).
        off_a = 0
        while off_a < len(da):
            chunk = 0
            while (off_a + chunk < len(da)
                   and da[off_a + chunk:off_a + chunk + 4] == db[off_a + chunk:off_a + chunk + 4]):
                chunk += 4
            if off_a + chunk >= len(da):
                break
            start = off_a + chunk
            while (off_a + chunk < len(da)
                   and da[off_a + chunk:off_a + chunk + 4] != db[off_a + chunk:off_a + chunk + 4]):
                chunk += 4
            va = pa["va"] + start
            word_a = da[start:start + 4]
            word_b = db[start:start + 4]
            note = f"LOAD{k}+{start:#x}"
            if len(word_a) != 4 or len(word_b) != 4:
                out.append(("unexpected", note + " (partial word)", va))
            elif any(lo <= va < hi for lo, hi, _ in allowed):
                kind = next(kind for lo, hi, kind in allowed if lo <= va < hi)
                out.append((kind, note, va))
            elif any(lo <= va < hi for lo, hi in execranges) and _adrp_ok(word_a, word_b, va, shift):
                out.append(("adrp", note, va))
            else:
                out.append(("unexpected", note + f" {word_a.hex()}->{word_b.hex()}", va))
            off_a += chunk
    return out


def _adrp_ok(word_a: bytes, word_b: bytes, va: int, delta: int) -> bool:
    da = _adrp(struct.unpack("<I", word_a)[0])
    db = _adrp(struct.unpack("<I", word_b)[0])
    if da is None or db is None:
        return False
    rd_a, imm_a = da
    rd_b, imm_b = db
    return rd_a == rd_b and imm_b * ADRP_PAGE == imm_a * ADRP_PAGE + delta


def report(name: str, blob: bytes) -> None:
    e = Elf(blob)
    print(f"{name}: {len(blob)} bytes")
    for i in e.loads():
        p = e.ph[i]
        print(f"  LOAD{i} off={p['off']:#x} va={p['va']:#x} "
              f"filesz={p['filesz']:#x} memsz={p['memsz']:#x} align={p['align']:#x}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="an APK (reports every arm64 lib) or one .so")
    ap.add_argument("--out", help="write the transformed library here")
    args = ap.parse_args()
    path = Path(args.target)
    if path.suffix.lower() == ".apk":
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if not (name.startswith("lib/arm64-v8a/") and name.endswith(".so")):
                    continue
                blob = z.read(name)
                print(f"== {name}")
                bad = problems(blob)
                if not bad:
                    report(name, blob)
                    print("  already 16 KB compatible")
                    continue
                out = transform(blob)
                changes = explain(blob, out)
                kinds: dict[str, int] = {}
                for kind, _note, _va in changes:
                    kinds[kind] = kinds.get(kind, 0) + 1
                report(name, out)
                print(f"  repair: {kinds or 'alignment only'}")
                for kind, note, va in changes:
                    if kind == "unexpected":
                        print(f"  ! {note} at va {va:#x}")
        return 0
    blob = path.read_bytes()
    out = transform(blob)
    changes = explain(blob, out)
    kinds: dict[str, int] = {}
    for kind, _note, _va in changes:
        kinds[kind] = kinds.get(kind, 0) + 1
    report(path.name, out)
    print("changes:", kinds or "none")
    if args.out:
        Path(args.out).write_bytes(out)
        print("wrote", args.out)
    return 1 if kinds.get("unexpected") else 0


if __name__ == "__main__":
    sys.exit(main())
