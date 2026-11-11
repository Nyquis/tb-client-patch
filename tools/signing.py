#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""The local signing identity: where the key lives, its password, its pin.

The keystore is gitignored and never published. The password is read from, in
order:

1. ``TB_KEY_PASS`` environment variable,
2. ``keys/keystore.pass`` (gitignored, travels with the keystore backup),

and is never stored in the repository. ``patches/signing.json`` holds only the
public pin (certificate SHA-256), so a restored key can be validated with
``pixi run keycheck`` before a build.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIGNING = ROOT / "patches" / "signing.json"


def spec() -> dict:
    return json.loads(SIGNING.read_text(encoding="utf-8"))


def keystore() -> Path:
    return ROOT / spec()["keystore"]


def alias() -> str:
    return spec()["alias"]


def pinned_cert_sha256() -> str:
    return spec()["cert_sha256"].lower()


def password() -> str:
    value = os.environ.get("TB_KEY_PASS")
    if value:
        return value
    helper = ROOT / "keys" / "keystore.pass"
    if helper.is_file():
        text = helper.read_text(encoding="utf-8").strip()
        if text:
            return text
    raise SystemExit(
        "no keystore password: write it to keys/keystore.pass (gitignored) "
        "or set TB_KEY_PASS"
    )


def keystore_sha256() -> str | None:
    """SHA-256 of the keystore's certificate, or None when it cannot be read."""
    key = keystore()
    if not key.is_file():
        return None
    try:
        out = subprocess.run(
            ["keytool", "-list", "-v", "-keystore", str(key),
             "-alias", alias(), "-storepass", password()],
            capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    match = re.search(r"SHA256:\s*([0-9A-Fa-f:]+)", out)
    if not match:
        return None
    return match.group(1).replace(":", "").lower()
