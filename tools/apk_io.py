#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""APK container helpers: rewrite entries while preserving order/compression."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

METADATA = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
MANIFEST = "AndroidManifest.xml"


def rewrite(src: Path, dst: Path, overrides: dict[str, bytes], drop_signature: bool = True,
            drop_prefixes: tuple[str, ...] = ()) -> None:
    """Copy ``src`` to ``dst`` replacing the named entries.

    Entry order and per-entry compression are preserved so the result stays as
    close to the original as possible. ``META-INF`` signature files are dropped
    because the APK is re-signed afterwards.
    """
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zout:
        for info in zin.infolist():
            if drop_signature and info.filename.startswith("META-INF/"):
                continue
            if any(info.filename.startswith(pre) for pre in drop_prefixes):
                continue
            data = overrides.get(info.filename)
            if data is None:
                data = zin.read(info.filename)
            zi = zipfile.ZipInfo(info.filename, info.date_time)
            zi.compress_type = info.compress_type
            zi.external_attr = info.external_attr
            zi.internal_attr = info.internal_attr
            zi.create_system = info.create_system
            zout.writestr(zi, data)
        # Entries the original did not have (e.g. an injected native library).
        written = {i.filename for i in zin.infolist()}
        for name, data in overrides.items():
            if name in written:
                continue
            zi = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o100644 << 16
            zout.writestr(zi, data)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
