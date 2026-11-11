#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Remove one childless element from an Android binary XML (AXML) document.

Only what the patch needs is implemented: a top-level XML chunk, a string pool,
and element chunks. Removing an element means dropping its START_ELEMENT and
END_ELEMENT chunks and shrinking the enclosing XML chunk header -- no string is
removed from the pool (unused strings are harmless).
"""

from __future__ import annotations

import struct

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103

CHUNK = struct.Struct("<HHI")          # type, headerSize, size
ATTR = struct.Struct("<IIIHBBI")       # ns, name, rawValue, size, res0, dataType, data


def _read_string_pool(data: bytes, offset: int) -> list[str]:
    _, header_size, _ = CHUNK.unpack_from(data, offset)
    count, _styles, flags, strings_start, _ = struct.unpack_from("<IIIII", data, offset + 8)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", data, offset + header_size)
    base = offset + strings_start
    out = []
    for rel in offsets:
        p = base + rel
        if utf8:
            # UTF-16 length (1 or 2 bytes) then UTF-8 length, both varint-ish.
            n = data[p]
            p += 2 if n & 0x80 else 1
            n = data[p]
            if n & 0x80:
                n = ((n & 0x7F) << 8) | data[p + 1]
                p += 2
            else:
                p += 1
            out.append(data[p:p + n].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", data, p)[0]
            out.append(data[p + 2:p + 2 + n * 2].decode("utf-16-le", "replace"))
    return out


def _element(data: bytes, offset: int) -> tuple[int, int, list[tuple[int, int, int, int]]]:
    """Return (name_index, next_offset, [(ns, name, rawValue, typedData), ...])."""
    _, header_size, size = CHUNK.unpack_from(data, offset)
    _line, _comment, _ns, name = struct.unpack_from("<IIII", data, offset + 8)
    attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, offset + 24)
    attrs = []
    # attributeStart is relative to the attrExt struct, which begins after the
    # 8-byte chunk header + lineNumber + comment = offset + 16.
    base = offset + 16 + attr_start
    for i in range(attr_count):
        ns_i, name_i, raw, _sz, _res0, data_type, value = struct.unpack_from(
            "<IIIHBBI", data, base + i * attr_size)
        attrs.append((ns_i, name_i, raw, value if data_type == 0x03 else -1))
    return name, offset + size, attrs


def remove_element(doc: bytes, element: str, attr: str, value_contains: str) -> bytes:
    """Drop the first childless ``<element attr="...value_contains...">``."""
    _, header_size, total = CHUNK.unpack_from(doc, 0)
    if CHUNK.unpack_from(doc, 0)[0] != RES_XML_TYPE:
        raise ValueError("not an AXML document")

    strings: list[str] = []
    pos = header_size
    target_start = target_end = None
    while pos < len(doc):
        ctype, _hsize, size = CHUNK.unpack_from(doc, pos)
        if ctype == RES_STRING_POOL_TYPE:
            strings = _read_string_pool(doc, pos)
        elif ctype == RES_XML_START_ELEMENT and strings:
            name_i, nxt, attrs = _element(doc, pos)
            if strings[name_i] == element:
                hit = any(
                    0 <= a_name < len(strings)
                    and strings[a_name] == attr
                    and any(0 <= idx < len(strings) and value_contains in strings[idx]
                            for idx in (a_raw, a_data))
                    for _ns, a_name, a_raw, a_data in attrs
                )
                if hit:
                    target_start = pos
                    # Providers are childless: the very next node is the matching END.
                    end_pos = nxt
                    while end_pos < len(doc):
                        etype, _eh, esize = CHUNK.unpack_from(doc, end_pos)
                        if etype == RES_XML_END_ELEMENT:
                            target_end = end_pos + esize
                            break
                        end_pos += esize
                    break
        pos += size

    if target_start is None or target_end is None:
        raise ValueError(f"{element} with {attr}~={value_contains!r} not found")

    out = bytearray(doc[:target_start] + doc[target_end:])
    struct.pack_into("<I", out, 4, total - (target_end - target_start))
    return bytes(out)
