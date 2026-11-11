#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Patch the client's ``classes.dex`` in place, from the original APK.

No apktool, no smali round-trip: this reads the DEX tables, finds the exact
method, and overwrites the *start* of its ``code_item`` with a fixed instruction
sequence, padding the rest with ``nop``. The instruction count never changes, so
every offset, reference and debug range stays valid; only the header checksum
and SHA-1 signature are recomputed.

What that buys:

* A patched method is still verified by ART like any other method (``nop`` and
  ``return`` are always legal), so no verifier metadata has to be maintained.
* The transform is deterministic: ``verify`` re-runs it on the original
  ``classes.dex`` and compares the hash.

Rules live in ``patches/dex.json``::

    {"class": "Lcom/onevcat/uniwebview/UniWebViewInterface;",
     "method": "init", "descriptor": "(Ljava/lang/String;IIII)V",
     "insns": "0e00", "comment": "..."}

``insns`` is a hex string of 16-bit **code unit values** (``000e`` is
``return-void``; ``0012 000f`` is ``const/4 v0, #0`` then ``return v0``).
Whitespace is ignored. The code unit is written little-endian, so the opcode
is the low byte - ``000e`` lands in the file as ``0e 00``.

Usage:
    python tools/dex_patch.py input.apk                # dry run, list matches
    python tools/dex_patch.py input.apk --out x.dex    # write the patched dex
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEX_RULES = ROOT / "patches" / "dex.json"


def _u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def _u16(d: bytes, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0]


def _uleb(d: bytes, o: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        b = d[o]
        o += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, o
        shift += 7


def _mutf8(d: bytes, o: int) -> str:
    n, o = _uleb(d, o)
    end = d.index(b"\x00", o)
    return d[o:end].decode("utf-8", "replace")


class Dex:
    """Just enough of the DEX format to find and rewrite a method body."""

    def __init__(self, data: bytes):
        if data[:4] != b"dex\n":
            raise ValueError("not a DEX file")
        self.d = data
        self.string_ids_size = _u32(data, 0x38)
        self.string_ids_off = _u32(data, 0x3C)
        self.type_ids_size = _u32(data, 0x40)
        self.type_ids_off = _u32(data, 0x44)
        self.proto_ids_size = _u32(data, 0x48)
        self.proto_ids_off = _u32(data, 0x4C)
        self.method_ids_size = _u32(data, 0x58)
        self.method_ids_off = _u32(data, 0x5C)
        self.class_defs_size = _u32(data, 0x60)
        self.class_defs_off = _u32(data, 0x64)

    def string(self, idx: int) -> str:
        return _mutf8(self.d, _u32(self.d, self.string_ids_off + idx * 4))

    def type_desc(self, idx: int) -> str:
        return self.string(_u32(self.d, self.type_ids_off + idx * 4))

    def method(self, idx: int) -> tuple[str, str, str]:
        o = self.method_ids_off + idx * 8
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHH", self.d, o)
        p = self.proto_ids_off + proto_idx * 12
        shorty_idx, ret_idx, params_off = struct.unpack_from("<III", self.d, p)
        desc = "("
        if params_off:
            (n,) = struct.unpack_from("<I", self.d, params_off)
            desc += "".join(self.type_desc(_u16(self.d, params_off + 4 + k * 2))
                            for k in range(n))
        desc += ")" + self.type_desc(ret_idx)
        return self.type_desc(class_idx), self.string(name_idx), desc


def iter_methods(dex: Dex):
    """Yield (class descriptor, name, descriptor, code_off).

    ``encoded_method`` stores a *diff* against the previous method id in the
    same list, which is why the running index is tracked here.
    """
    for c in range(dex.class_defs_size):
        o = dex.class_defs_off + c * 32
        class_idx, _access, _super, _ifaces, _src, _annot, class_data_off, _sv = \
            struct.unpack_from("<IIIIIIII", dex.d, o)
        if not class_data_off:
            continue
        cls = dex.type_desc(class_idx)
        p = class_data_off
        counts = []
        for _ in range(4):
            n, p = _uleb(dex.d, p)
            counts.append(n)
        for _ in range(counts[0] + counts[1]):
            _, p = _uleb(dex.d, p)
            _, p = _uleb(dex.d, p)
        for start, count in ((0, counts[2]), (0, counts[3])):
            idx = start
            for _ in range(count):
                diff, p = _uleb(dex.d, p)
                _, p = _uleb(dex.d, p)
                code_off, p = _uleb(dex.d, p)
                idx += diff
                _cls, name, desc = dex.method(idx)
                if code_off:
                    yield cls, name, desc, code_off


def _insns_location(dex: Dex, code_off: int) -> tuple[int, int]:
    """(file offset, instruction count) of a code_item's instructions."""
    size = _u32(dex.d, code_off + 12)
    return code_off + 16, size


def apply(dex_blob: bytes, rules: dict) -> tuple[bytes, list[str]]:
    """Apply ``patches/dex.json`` rules; return (new dex, per-rule log)."""
    dex = Dex(dex_blob)
    wanted = {}
    for rule in rules.get("rules", []):
        key = (rule["class"], rule["method"], rule.get("descriptor", ""))
        wanted.setdefault(key, []).append(rule)

    out = bytearray(dex_blob)
    log = []
    seen = set()
    for cls, name, desc, code_off in iter_methods(dex):
        key = (cls, name, desc)
        if key not in wanted:
            continue
        rule = wanted[key].pop()
        text = "".join(rule["insns"].split())
        if len(text) % 4:
            raise ValueError(f"{cls}->{name}{desc}: insns must be whole code units")
        words = [int(text[i:i + 4], 16) for i in range(0, len(text), 4)]
        off, count = _insns_location(dex, code_off)
        if not words:
            raise ValueError(f"{cls}->{name}{desc}: empty insns")
        if len(words) > count:
            raise ValueError(f"{cls}->{name}{desc}: {len(words)} words do not fit "
                             f"in {count}")
        struct.pack_into(f"<{count}H", out, off, *(words + [0] * (count - len(words))))
        log.append(f"{cls}->{name}{desc}: {count} words, first {len(words)} replaced")
        seen.add(key)

    missing = [k for k, v in wanted.items() if v]
    if missing:
        raise ValueError("rules matched no method: " + "; ".join(
            f"{c}->{m}{d}" for c, m, d in missing))
    if not seen and rules.get("rules"):
        raise ValueError("no rules applied")

    _resign(out)
    return bytes(out), log


def _resign(d: bytearray) -> None:
    """Recompute the DEX SHA-1 signature and adler32 checksum."""
    d[12:32] = hashlib.sha1(d[32:]).digest()
    struct.pack_into("<I", d, 8, zlib.adler32(bytes(d[12:])) & 0xFFFFFFFF)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="the original APK (reads classes.dex)")
    ap.add_argument("--rules", default=str(DEX_RULES))
    ap.add_argument("--out", help="write the patched classes.dex here")
    args = ap.parse_args()

    rules = json.loads(Path(args.rules).read_text(encoding="utf-8"))
    with zipfile.ZipFile(args.target) as z:
        blob = z.read("classes.dex")
    patched, log = apply(blob, rules)
    for line in log:
        print(" ", line)
    print(f"classes.dex: {len(blob)} -> {len(patched)} bytes, "
          f"sha256 {hashlib.sha256(patched).hexdigest()[:16]}")
    if args.out:
        Path(args.out).write_bytes(patched)
        print("wrote", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
