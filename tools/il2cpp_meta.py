#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Minimal IL2CPP global-metadata.dat string-literal editor.

IL2CPP metadata v24 stores string literals as a table of 8-byte entries
``(length, dataIndex)`` pointing into one packed data blob. The blob has no
separators, so a shorter replacement MUST also rewrite the entry's length --
otherwise the runtime keeps reading into the next literal.
"""

from __future__ import annotations

import struct
import sys

SANITY = 0xFAB11BAF
HEADER = struct.Struct("<iiiiii")  # sanity, version, tableOff, tableSize, dataOff, dataSize


class Metadata:
    def __init__(self, blob: bytes) -> None:
        self.blob = bytearray(blob)
        sanity, version, self.table_off, self.table_size, self.data_off, self.data_size = (
            HEADER.unpack_from(blob, 0)
        )
        if sanity & 0xFFFFFFFF != SANITY:
            raise ValueError(f"bad metadata magic: {sanity & 0xFFFFFFFF:#x}")
        if version != 24:
            raise ValueError(f"unsupported IL2CPP metadata version {version} (expected 24)")

    def literals(self) -> list[tuple[int, int, bytes]]:
        out = []
        for i in range(self.table_size // 8):
            length, index = struct.unpack_from("<II", self.blob, self.table_off + i * 8)
            out.append((length, index, bytes(self.blob[self.data_off + index:self.data_off + index + length])))
        return out

    def replace(self, old: bytes, new: bytes) -> int:
        """Replace every literal equal to ``old``; return how many were patched."""
        if len(new) > len(old):
            raise ValueError(f"replacement {new!r} does not fit in {old!r} ({len(old)} bytes)")
        patched = 0
        for i in range(self.table_size // 8):
            entry = self.table_off + i * 8
            length, index = struct.unpack_from("<II", self.blob, entry)
            start = self.data_off + index
            if bytes(self.blob[start:start + length]) != old:
                continue
            # Pad the tail so stale bytes cannot leak into any later literal, then
            # publish the new length.
            self.blob[start:start + len(old)] = new + b"\x00" * (len(old) - len(new))
            struct.pack_into("<I", self.blob, entry, len(new))
            patched += 1
        return patched


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: il2cpp_meta.py <metadata.dat> <old-string> <new-string>", file=sys.stderr)
        return 2
    meta = Metadata(open(sys.argv[1], "rb").read())
    n = meta.replace(sys.argv[2].encode(), sys.argv[3].encode())
    if n == 0:
        print("no matching literal", file=sys.stderr)
        return 1
    open(sys.argv[1], "wb").write(meta.blob)
    print(f"patched {n} literal(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
