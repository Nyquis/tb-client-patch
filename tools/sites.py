#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""The per-site guard: what a patch expects to find before it writes.

A native patch never uses the original bytes to produce output - it writes only
``patch``. The expected value exists to catch a moved site (a different client
build) before the patch corrupts the wrong instruction.

Two forms are accepted, both produced by :func:`guard`:

* ``"original": "00000000"`` - a run of zero bytes (cave padding). Plain bytes
  because there is nothing to hide.
* ``"original_len": 4, "original_sha256": "..."`` - the digest of the site's
  current contents. This keeps game code out of the repository: the recipe
  records *that* a site is unchanged, not what the instruction is.
"""

from __future__ import annotations

import hashlib


def guard(data: bytes) -> dict:
    """JSON fragment pinning a site's original content."""
    if not data.strip(b"\x00"):
        return {"original": data.hex()}
    return {"original_len": len(data),
            "original_sha256": hashlib.sha256(data).hexdigest()}


def length(rule: dict) -> int:
    if "original_len" in rule:
        return int(rule["original_len"])
    return len(bytes.fromhex(rule["original"]))


def check(blob: bytes, offset: int, rule: dict) -> tuple[bool, str]:
    """(ok, message) for ``rule`` against ``blob`` at ``offset``."""
    size = length(rule)
    found = bytes(blob[offset:offset + size])
    if len(found) != size:
        return False, f"site 0x{offset:x}: past the end of the file"

    if "original_sha256" in rule:
        want = rule["original_sha256"].lower()
        got = hashlib.sha256(found).hexdigest()
        if got != want:
            return False, (f"site 0x{offset:x}: content changed since it was "
                           f"authored ({got[:16]}... != {want[:16]}...)")
        return True, ""

    want_bytes = bytes.fromhex(rule["original"])
    if found != want_bytes:
        return False, f"site 0x{offset:x}: expected {want_bytes.hex()}, found {found.hex()}"
    return True, ""
