#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Read the shared IL2CPP index built by the Ghidra wrapper.

There is exactly one parser of dump.cs: the one in
``.tools/rea/bin/ghidra-method.ps1``. It writes, per target:

    .tools/ghidra/index/<so-name>_<sha8>.tsv         0xRVA<TAB>Class$$Method
    .tools/ghidra/index/<so-name>_<sha8>-fields.tsv  Class<TAB>0xOFF<TAB>field

This module only reads them, so the sweeps in this repo cannot drift from what
the decompiler annotations use.

    pixi run index          # verify the index exists, build it if possible
    python tools/il2cpp_index.py --stats

Overrides: --index-dir, or REA_TOOLS to relocate the .tools directory.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SO = ROOT / "work" / "il2cpp" / "libil2cpp.so"
TOOLS_ROOT = Path(os.environ.get("REA_TOOLS", ROOT.parent.parent / ".tools"))
INDEX_DIR = TOOLS_ROOT / "ghidra" / "index"
WRAPPER = TOOLS_ROOT / "rea" / "bin" / "ghidra-method.ps1"


def key_for(so_path: Path) -> str:
    """Same key the wrapper uses: <basename>_<first 8 hex of sha256>."""
    digest = hashlib.sha256()
    with so_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return f"{so_path.name}_{digest.hexdigest()[:8]}"


def paths_for(so_path: Path, index_dir: Path | None = None) -> tuple[Path, Path]:
    directory = Path(index_dir) if index_dir else INDEX_DIR
    key = key_for(so_path)
    return directory / f"{key}.tsv", directory / f"{key}-fields.tsv"


def ensure(so_path: Path, index_dir: Path | None = None) -> None:
    """Build the index through the wrapper if it is missing."""
    names, fields = paths_for(so_path, index_dir)
    if names.exists() and fields.exists():
        return
    if not WRAPPER.exists():
        raise SystemExit(
            f"index missing for {so_path.name} and no wrapper at {WRAPPER}; "
            "run ghidra-method.ps1 once against this target"
        )
    print(f"index missing, building via {WRAPPER.name} ...", file=sys.stderr)
    # Prefer PowerShell 7: the Windows PowerShell that a pixi subprocess resolves
    # does not initialise its module path, so cmdlets like Get-FileHash vanish.
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        raise SystemExit("no PowerShell on PATH; run the wrapper manually")
    subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(WRAPPER), "-Target", str(so_path), "-IndexOnly"],
        check=False,
    )
    if not names.exists():
        raise SystemExit(
            "index build failed; run manually:\n"
            f'  powershell -File "{WRAPPER}" -Target "{so_path}" -IndexOnly'
        )


def load(so_path: Path = DEFAULT_SO, index_dir: Path | None = None, build: bool = True) -> dict:
    names_path, fields_path = paths_for(so_path, index_dir)
    if build:
        ensure(so_path, index_dir)
    if not names_path.exists():
        raise SystemExit(f"index not found: {names_path}")

    methods: dict[str, str] = {}
    with names_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            tab = line.find("\t")
            if tab > 0:
                methods[line[:tab].strip().upper().replace("0X", "0x", 1)] = line[tab + 1:].strip()

    fields: dict[str, dict[str, str]] = {}
    if fields_path.exists():
        with fields_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 3:
                    fields.setdefault(parts[0], {})[parts[1].upper()] = parts[2]

    return {"source": str(so_path), "methods": methods, "fields": fields}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--so", type=Path, default=DEFAULT_SO)
    parser.add_argument("--index-dir", type=Path, default=None)
    parser.add_argument("--stats", action="store_true")
    args = parser.parse_args()

    index = load(args.so, args.index_dir, build=True)
    total_fields = sum(len(table) for table in index["fields"].values())
    print(f"methods {len(index['methods'])}  classes {len(index['fields'])}  fields {total_fields}")
    print(f"index {paths_for(args.so, args.index_dir)[0]}")
    if args.stats:
        for class_name, table in list(index["fields"].items())[:3]:
            print(f"  {class_name}: {len(table)} fields")
    return 0


if __name__ == "__main__":
    sys.exit(main())
