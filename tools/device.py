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

`clear` wipes the client's local state: do not use it while a restored account
is linked; `install -r` keeps data.

The adb serial comes from TB_ADB_SERIAL if set, otherwise the first attached
device, with a fallback connect to the MuMu default port.
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
MU_MU_PORTS = (7555, 16384, 5555)


def run(args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run([str(ADB), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          timeout=timeout, check=False)


def ensure_device() -> str:
    serial = os.environ.get("TB_ADB_SERIAL")
    if serial:
        return serial
    for _ in range(2):
        for line in run(["devices"]).stdout.splitlines():
            if "\tdevice" in line:
                return line.split("\t")[0]
        for port in MU_MU_PORTS:
            run(["connect", f"127.0.0.1:{port}"], timeout=30)
    raise SystemExit("no adb device: start the emulator, or set TB_ADB_SERIAL")


def adb(serial: str, args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("server")
    t = sub.add_parser("tap")
    t.add_argument("x", type=int)
    t.add_argument("y", type=int)
    sub.add_parser("clear")
    args = ap.parse_args()

    serial = ensure_device()
    if args.cmd == "server":
        return cmd_server(serial)
    if args.cmd == "tap":
        return cmd_tap(serial, args.x, args.y)
    if args.cmd == "clear":
        return cmd_clear(serial)
    return 1


if __name__ == "__main__":
    sys.exit(main())
