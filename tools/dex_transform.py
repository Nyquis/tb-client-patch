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

# Rule groups a build may exclude one at a time, for single-variable experiments
# (see docs/unverified.md). Keys are what a person types; values are the
# "group" fields in patches/dex.json and patches/smali.json.
EXPERIMENT_GROUPS = {
    "dex-ads": "ads",
    "dex-uniwebview": "uniwebview",
    "smali-jnibridge": "jnibridge",
}
SKIP_16KB = "16kb"


def parse_without(text: str | None) -> tuple[frozenset[str], bool]:
    """``--without`` value -> (rule groups to drop, skip the 16 KB repair)."""
    names = [x.strip() for x in (text or "").split(",") if x.strip()]
    known = sorted([*EXPERIMENT_GROUPS, SKIP_16KB])
    unknown = [n for n in names if n not in known]
    if unknown:
        raise ValueError(f"unknown --without target(s): {', '.join(unknown)} "
                         f"(known: {', '.join(known)})")
    groups = frozenset(EXPERIMENT_GROUPS[n] for n in names if n in EXPERIMENT_GROUPS)
    return groups, SKIP_16KB in names


def build(dex: bytes, manifest: bytes, without: frozenset[str] = frozenset()
          ) -> tuple[bytes, list[str]]:
    """Return (patched dex, log lines)."""
    rules = json.loads(DEX_RULES.read_text(encoding="utf-8"))
    if without:
        kept = [r for r in rules.get("rules", []) if r.get("group") not in without]
        dropped = len(rules.get("rules", [])) - len(kept)
        rules["rules"] = kept
        print(f"  without {sorted(without)}: {dropped} dex rule(s) skipped")
    staged = dex_smali_patch.apply(dex, manifest, without=without)
    patched, log = apply_rules(staged, rules)
    return patched, log
