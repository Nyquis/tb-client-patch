#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Create the local signing key. Only needed if ``keys/`` was lost.

The password comes from ``keys/keystore.pass`` or ``TB_KEY_PASS`` (see
``tools/signing.py``); it is never stored in the repository. The new key's
certificate fingerprint is printed and must be recorded in
``patches/signing.json`` — otherwise every existing client must be uninstalled
before the next build can be installed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import signing

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    key = signing.keystore()
    if key.exists():
        print(f"{key.relative_to(ROOT)} already exists; refusing to overwrite "
              "(that would change the app identity)")
        return 0

    password = signing.password()
    key.parent.mkdir(exist_ok=True)
    subprocess.run([
        "keytool", "-genkeypair",
        "-keystore", str(key),
        "-alias", signing.alias(),
        "-storepass", password,
        "-keypass", password,
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-dname", signing.spec()["dn"],
    ], check=True)

    fingerprint = signing.keystore_sha256() or "unknown"
    print(f"\ncreated {key.relative_to(ROOT)}")
    print(f"  certificate SHA-256: {fingerprint}")
    print("  BACK UP NOW (encrypted, outside the repo):")
    print("    keys/tb-client.keystore  +  its password")
    print("  If this key is lost the app identity changes: uninstall the old")
    print("  client first, then update patches/signing.json with the fingerprint above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
