#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the `uniwebview` rule group in patches/dex.json.

The game opens an in-app browser panel ("What's New") from the title screen.
`UniWebViewInterface` is the Java side of that plugin, and reaching it on a
modern device faults inside the native WebView stack: the process dies right
after Unity logs "Using memoryadresses from more that 16GB of memory".

Neutralising only `init` is not enough, because the other 60 entry points still
run their real bodies against a dialog that was never created. Make the whole
class inert instead, exactly as a comparison build of this client does: no
method can touch the framework, so the panel opens empty and the game continues
to the World Map.

Instruction choice is by return type, because a wrong return kind fails DEX
verification:

    V            return-void
    32-bit value const/4 v0, #0 ; return v0        (Z B S C I F)
    64-bit value const-wide/16 v0, #0 ; return-wide v0  (J D)
    object/array const/4 v0, #0 ; return-object v0 (L...; [...)

Usage:
    python tools/patchgen/gen_dex_uniwebview.py            # rewrite the group
    python tools/patchgen/gen_dex_uniwebview.py --check    # report drift only
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]        # repo root (tools/patchgen/)
sys.path.insert(0, str(ROOT / "tools"))

from dex_patch import Dex, iter_methods          # noqa: E402

APK = ROOT / "input" / "terra-battle-5.5.7-170-original.apk"
RULES = ROOT / "patches" / "dex.json"
TARGET = "Lcom/onevcat/uniwebview/UniWebViewInterface;"
GROUP = "uniwebview"

COMMENT = (
    "UniWebView is the game's in-app browser (the 'What's New' panel opened "
    "from the title screen). Every entry point is made inert, not just init: "
    "a half-initialised plugin still runs its real bodies against a dialog "
    "that was never created, and reaching it faults inside the native WebView "
    "stack - the process dies on the title-screen tap, right after Unity logs "
    "'Using memoryadresses from more that 16GB of memory'. With the whole "
    "surface stubbed the panel opens empty and the game continues. Return kind "
    "follows the descriptor, because a wrong one fails DEX verification."
)


def insns_for(returns: str) -> str:
    """DEX code units that return a constant of the method's return type."""
    if returns == "V":
        return "000e"
    if returns in "ZBSCIF":
        return "0012 000f"
    if returns in "JD":
        return "0013 0010"
    if returns.startswith("L") or returns.startswith("["):
        return "0012 0011"
    raise SystemExit(f"unhandled return type {returns!r}")


def rules_from(dex: bytes) -> list[dict]:
    d = Dex(dex)
    found = []
    for cls, name, desc, _code_off in iter_methods(d):
        if cls != TARGET:
            continue
        if name.startswith("<"):
            print(f"  skip {name}{desc}: a constructor must call super", file=sys.stderr)
            continue
        found.append((name, desc, desc[desc.rindex(")") + 1:]))
    if not found:
        raise SystemExit(f"no methods found for {TARGET}")

    out = []
    for name, desc, returns in sorted(found, key=lambda m: (m[0], m[1])):
        rule = {"class": TARGET, "method": name, "descriptor": desc,
                "insns": insns_for(returns), "group": GROUP}
        out.append(rule)
    out[0]["comment"] = COMMENT
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="report whether patches/dex.json is current")
    args = ap.parse_args()

    with zipfile.ZipFile(APK) as z:
        dex = z.read("classes.dex")
    fresh = rules_from(dex)

    spec = json.loads(RULES.read_text(encoding="utf-8"))
    kept = [r for r in spec.get("rules", []) if r.get("group") != GROUP]
    current = [r for r in spec.get("rules", []) if r.get("group") == GROUP]
    if args.check:
        same = current == fresh
        print(f"{GROUP}: {len(current)} rule(s) on file, {len(fresh)} expected"
              f" -> {'current' if same else 'STALE'}")
        return 0 if same else 1

    spec["rules"] = kept + fresh
    RULES.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n",
                     encoding="utf-8", newline="\n")
    kinds: dict[str, int] = {}
    for r in fresh:
        kinds[r["insns"]] = kinds.get(r["insns"], 0) + 1
    print(f"{GROUP}: wrote {len(fresh)} rules {kinds}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
