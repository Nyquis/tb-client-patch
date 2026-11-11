#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""The complete classes.dex transform, shared by build and verify.

Chain: original dex -> smali edits (patches/smali.json) -> byte rules
(patches/dex.json). Keeping it in one function is what stops build and verify
from drifting apart.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dex_smali_patch
from dex_patch import apply as apply_rules

ROOT = Path(__file__).resolve().parent.parent
DEX_RULES = ROOT / "patches" / "dex.json"


def build(dex: bytes, manifest: bytes) -> tuple[bytes, list[str]]:
    """Return (patched dex, log lines)."""
    rules = json.loads(DEX_RULES.read_text(encoding="utf-8"))
    staged = dex_smali_patch.apply(dex, manifest)
    patched, log = apply_rules(staged, rules)
    return patched, log
