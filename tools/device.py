#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Project-specific device steps that REA's adb tools do not cover.

Inspection and evidence (device info, packages, logcat, screenshots, install,
launch, stop, pull/push) go through the REA MCP adb tools. This script keeps
only the three things REA has no tool for:

    pixi run device server        # launch reTB Host, tap Start server, wait for :8080
    pixi run device tap X Y       # raw UI input (no keyevent/tap in REA)
    pixi run device clear         # pm clear the client (fresh local state)
    pixi run device install       # adb install -r the built client APK

`clear` wipes the client's local state: do not use it while a restored account
is linked; `install -r` keeps data.

The adb serial comes from TB_ADB_SERIAL if set, otherwise the first attached
device, with a fallback connect to the MuMu ports in CONNECT_PORTS.

**Off-limits devices** are listed in DENY_SERIALS and refused before any adb
command runs, including when TB_ADB_SERIAL names one. They are never a fallback
target either: a denied serial is filtered out of `adb devices` and its port is
absent from CONNECT_PORTS. Keep the list in sync with `retb-build/AGENTS.md`,
which explains why each entry is there.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADB = Path(os.environ.get("TB_ADB", ROOT / ".android-sdk" / "platform-tools" / "adb.exe"))
HOST_PKG = "com.teamretb.host"
HOST_ACT = f"{HOST_PKG}/com.retb.host.vanilla.MainActivity"
CLIENT_PKG = "com.mistwalkercorp.guardians"
CLIENT_APK = ROOT / "dist" / "TerraBattle-5.5.7-170-patched.apk"

# Off limits by owner decision (see retb-build/AGENTS.md). Refused before any
# adb command runs, never used as an implicit fallback, and its port is not in
# CONNECT_PORTS. Fingerprints catch the same machine reappearing on another port
# or transport, and they are build strings rather than personal identifiers, so
# a published file can carry them.
DENY_SERIALS = frozenset({"127.0.0.1:7555", "10.10.2.48:5555"})
DENY_FINGERPRINTS = frozenset({
    "Samsung/q5q/q5q:12/V417IR/669:user/release-keys",                  # emulator
    "samsung/dm3qxeea/dm3q:17/CP2A.260605.016/S918BXXUAGZIF:user/release-keys",  # S23 Ultra
})
CONNECT_PORTS = (16384, 5555)


def _refuse_if_denied(serial: str) -> None:
    if serial in DENY_SERIALS:
        raise SystemExit(f"{serial}: off limits by owner decision "
                         f"(see retb-build/AGENTS.md)")


def _fingerprint(serial: str) -> str:
    return run(["-s", serial, "shell", "getprop", "ro.build.fingerprint"],
               timeout=30).stdout.strip()


def _refuse_if_denied_fingerprint(serial: str) -> None:
    fp = _fingerprint(serial)
    if fp in DENY_FINGERPRINTS:
        raise SystemExit(f"{serial}: off limits by owner decision "
                         f"(fingerprint {fp}; see retb-build/AGENTS.md)")


def run(args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run([str(ADB), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          timeout=timeout, check=False)


def ensure_device() -> str:
    serial = os.environ.get("TB_ADB_SERIAL")
    if serial:
        _refuse_if_denied(serial)
        _refuse_if_denied_fingerprint(serial)
        return serial
    for _ in range(2):
        for line in run(["devices"]).stdout.splitlines():
            if "\tdevice" in line:
                candidate = line.split("\t")[0]
                if candidate in DENY_SERIALS:
                    continue
                if _fingerprint(candidate) in DENY_FINGERPRINTS:
                    continue
                return candidate
        for port in CONNECT_PORTS:
            run(["connect", f"127.0.0.1:{port}"], timeout=30)
    raise SystemExit("no adb device: start the emulator, or set TB_ADB_SERIAL")


def adb(serial: str, args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    _refuse_if_denied(serial)
    return run(["-s", serial, *args], timeout=timeout)


def shell(serial: str, cmd: str, timeout: int = 120) -> str:
    return adb(serial, ["shell", cmd], timeout=timeout).stdout


def server_up(serial: str) -> bool:
    table = shell(serial, "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null")
    return bool(re.search(r":1F90\s+\S+\s+0A", table))


def cmd_server(serial: str) -> int:
    adb(serial, ["shell", "am", "start", "-n", HOST_ACT])
    time.sleep(3)
    if not server_up(serial):
        # "Start server" on the host screen (1080x1920 layout)
        x, y = os.environ.get("TB_START_XY", "540,447").split(",")
        adb(serial, ["shell", "input", "tap", x, y])
    for _ in range(25):
        if server_up(serial):
            print("server: listening on :8080")
            return 0
        time.sleep(1)
    print("server: still down - press Start server in the host UI", file=sys.stderr)
    return 2


def cmd_tap(serial: str, x: int, y: int) -> int:
    adb(serial, ["shell", "input", "tap", str(x), str(y)])
    print(f"tap {x},{y}")
    return 0


def cmd_clear(serial: str) -> int:
    adb(serial, ["shell", "pm", "clear", CLIENT_PKG])
    print("client data cleared (account link may need re-establishing)")
    return 0


def cmd_install(serial: str) -> int:
    if not CLIENT_APK.is_file():
        print(f"missing {CLIENT_APK}: run `pixi run build` first", file=sys.stderr)
        return 2
    r = adb(serial, ["install", "-r", str(CLIENT_APK)], timeout=1800)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode:
        print(f"adb install failed (exit {r.returncode})", file=sys.stderr)
    return r.returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("server")
    t = sub.add_parser("tap")
    t.add_argument("x", type=int)
    t.add_argument("y", type=int)
    sub.add_parser("clear")
    sub.add_parser("install")
    args = ap.parse_args()

    serial = ensure_device()
    if args.cmd == "server":
        return cmd_server(serial)
    if args.cmd == "tap":
        return cmd_tap(serial, args.x, args.y)
    if args.cmd == "clear":
        return cmd_clear(serial)
    if args.cmd == "install":
        return cmd_install(serial)
    return 1


if __name__ == "__main__":
    sys.exit(main())
