#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Verify that the local keystore is the pinned identity.

    pixi run keycheck

Run this after restoring ``keys/`` on a new machine. It reads the certificate
fingerprint with keytool and compares it to ``patches/signing.json``. A mismatch
means builds would carry a different app identity: the old client must be
uninstalled first, and the pin updated deliberately.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import signing


def main() -> int:
    key = signing.keystore()
    if not key.is_file():
        print(f"FAIL no keystore at {key.relative_to(signing.ROOT)}")
        print("     create one with 'pixi run newkey', or restore the backup")
        return 1

    actual = signing.keystore_sha256()
    if actual is None:
        print("FAIL could not read the keystore's certificate")
        print("     check the password source: keys/keystore.pass or TB_KEY_PASS")
        return 1

    expected = signing.pinned_cert_sha256()
    ok = actual == expected
    print(f"{'OK  ' if ok else 'FAIL'} keystore certificate {actual[:16]}... "
          f"{'==' if ok else '!='} pinned identity")
    if not ok:
        print(f"     pinned: {expected}")
        print("     this key is NOT the identity in patches/signing.json;"
              " builds signed with it cannot update the existing client")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
