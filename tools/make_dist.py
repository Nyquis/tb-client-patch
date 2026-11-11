#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Release helper: build -> verify -> dist/release/ with hashes and notes."""

from __future__ import annotations

import datetime as dt
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
BUILT = DIST / "TerraBattle-5.5.7-170-patched.apk"
RELEASE = DIST / "release"


def run(script: str) -> None:
    subprocess.run([sys.executable, str(ROOT / "tools" / script)], check=True, cwd=ROOT)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    run("audit_patches.py")
    run("build_patch.py")
    run("verify.py")

    RELEASE.mkdir(parents=True, exist_ok=True)
    target = RELEASE / BUILT.name
    shutil.copy2(BUILT, target)
    digest = sha256(target)

    (RELEASE / "SHA256SUMS.txt").write_text(f"{digest}  {target.name}\n", encoding="utf-8")

    import json

    natives = []
    for path in sorted((ROOT / "patches").glob("native_*.json")):
        spec = json.loads(path.read_text(encoding="utf-8"))
        natives.append(f"{path.stem.removeprefix('native_')}: "
                       f"{'enabled' if spec.get('enabled', True) else 'disabled'}")
    dex = json.loads((ROOT / "patches" / "dex.json").read_text(encoding="utf-8"))
    smali = json.loads((ROOT / "patches" / "smali.json").read_text(encoding="utf-8"))
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip() if (ROOT / "VERSION").is_file() else "unversioned"
    git = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
    notes = [
        f"# Terra Battle 5.5.7-170 patched client",
        "",
        f"- version: {version}",
        f"- built: {dt.datetime.now().isoformat(timespec='seconds')}",
        f"- git: {git}",
        f"- apk: {target.name} ({target.stat().st_size / 1048576:.1f} MiB)",
        f"- sha256: {digest}",
        "- derived from: the original 5.5.7-170 APK only (no reference APK)",
        "- native patches: " + (", ".join(natives) if natives else "none"),
        "- dex rules: " + (", ".join(f"{r['class'].split('/')[-1].rstrip(';')}.{r['method']}"
                                     for r in dex.get("rules", [])) or "none"),
        "- dex smali: " + (", ".join(f"{r['file'].split('/')[-1]}->{r['method'].split('(')[0]}"
                                     for r in smali.get("rules", [])) or "none"),
        "- 16 KB: libmain/libunity segments repaired in place, no injected library",
        "- endpoints: 127.0.0.1:8080 (API, gdresources, support/terms pages)",
        "",
        "Install over a build signed with the same key; otherwise uninstall first.",
    ]
    (RELEASE / "NOTES.md").write_text("\n".join(notes) + "\n", encoding="utf-8")

    print(f"\nrelease: {target}")
    print(f"sha256:  {digest}")
    print(f"notes:   {RELEASE / 'NOTES.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
