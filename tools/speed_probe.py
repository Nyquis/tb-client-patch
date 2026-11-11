#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Locate the battle-speed controls inside data.unity3d.

Read-only: extracts the bundle from the original APK into work/ (gitignored) and
reports the objects that carry the fast-forward / time-scale names, so we can
see whether 4x is a serialized value or compiled logic.
"""

from __future__ import annotations

import json
import re
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APK = ROOT / "input" / "terra-battle-5.5.7-170-original.apk"
BUNDLE = ROOT / "work" / "data.unity3d"
NEEDLES = ("MoreFasterFastForward", "timeScale1", "timeScale2", "FastForward", "fastForward")


def main() -> int:
    BUNDLE.parent.mkdir(exist_ok=True)
    if not BUNDLE.exists():
        with zipfile.ZipFile(APK) as z:
            BUNDLE.write_bytes(z.read("assets/bin/Data/data.unity3d"))
        print(f"extracted {BUNDLE} ({BUNDLE.stat().st_size / 1048576:.1f} MiB)")

    import UnityPy

    env = UnityPy.load(str(BUNDLE))
    types: Counter[str] = Counter()
    hits = []
    for obj in env.objects:
        types[obj.type.name] += 1
        if obj.type.name not in ("MonoBehaviour", "AnimatorController", "Animator"):
            continue
        try:
            tree = obj.read_typetree()
        except Exception:
            continue
        blob = json.dumps(tree, default=str)
        found = [n for n in NEEDLES if n in blob]
        if found:
            hits.append((obj.type.name, obj.path_id, found, tree))

    print("object types:", ", ".join(f"{k}={v}" for k, v in types.most_common(12)))
    print(f"hits: {len(hits)}")
    for typ, pid, found, tree in hits:
        name = tree.get("m_Name", "") if isinstance(tree, dict) else ""
        print(f"\n== {typ} path_id={pid} name={name!r} needles={found}")
        blob = json.dumps(tree, indent=1, default=str)
        for needle in found:
            for m in re.finditer(re.escape(needle), blob):
                start = max(0, m.start() - 300)
                print("...", blob[start:m.end() + 300].replace("\n", " ")[:700])
                break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
