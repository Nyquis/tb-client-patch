#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Derive the ``hook`` / ``targets`` declarations the audit requires.

A 4-byte patch that branches into a cave declared in the same file must say
``"hook": true``, and the cave's exits must be listed in ``targets`` (the audit
uses them to prove the cave leaves only where the author intended). Both are
properties of the emitted bytes, so they are computed here instead of being
hand-maintained in each generator:

* ``hook``    - the patch word is a B (not BL) whose target is a declared cave;
* ``targets`` - every branch target of that cave that lands outside the cave
  and outside every other cave. Calls are not exits; ``audit_calls`` checks
  them separately.

``annotate`` never overwrites an existing declaration, so authored lists keep
their order and a deliberate exception stays as written.
"""

from __future__ import annotations

import re
import struct

from capstone import CS_ARCH_ARM64, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_ARM, Cs

_MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
_MD.detail = True

_TARGET = re.compile(r"#(0x[0-9a-f]+)$")


def _branch(patch_hex: str, offset: int) -> tuple[int | None, bool]:
    """(target, is_call) for a B/BL patch word, else (None, False)."""
    (word,) = struct.unpack("<I", bytes.fromhex(patch_hex))
    op = word & 0xFC000000
    if op not in (0x14000000, 0x94000000):
        return None, False
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return offset + imm * 4, op == 0x94000000


def exits(cave: bytes, base: int, others: set[int]) -> list[str]:
    """Branch targets of ``cave`` that leave it, sorted, as ``0x...`` strings."""
    lo, hi = base, base + len(cave)
    out: set[int] = set()
    for ins in _MD.disasm(cave, base):
        if ins.group(CS_GRP_CALL) or not ins.group(CS_GRP_JUMP):
            continue
        match = _TARGET.search(ins.op_str)
        if not match:
            continue
        target = int(match.group(1), 16)
        if not lo <= target < hi and target not in others:
            out.add(target)
    return [hex(t) for t in sorted(out)]


def annotate(spec: dict) -> dict:
    """Fill in missing ``hook``/``targets`` on the spec's patches, in place."""
    patches = {int(p["offset"], 16): p for p in spec.get("patches", [])}
    caves = {off for off, p in patches.items() if len(p["patch"]) > 8}
    for off, p in patches.items():
        if "hook" in p or len(p["patch"]) != 8:
            continue
        target, is_call = _branch(p["patch"], off)
        if is_call or target not in caves:
            continue
        found = exits(bytes.fromhex(patches[target]["patch"]), target, caves)
        p["hook"] = True
        if found:
            p["targets"] = found
    return spec
