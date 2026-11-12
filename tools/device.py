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
    pixi run device allow S --hours 4 --purpose "..."   # one-device experiment
    pixi run device status        # deny lists + current allowances
    pixi run device revoke S      # drop an allowance (all when S is omitted)
    pixi run device adb -- logcat -d                    # originals, still guarded

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
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
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
DENY_SERIALS = frozenset({"127.0.0.1:7555"})
DENY_FINGERPRINTS = frozenset({
    "Samsung/q5q/q5q:12/V417IR/669:user/release-keys",                  # emulator
    "samsung/dm3qxeea/dm3q:17/CP2A.260605.016/S918BXXUAGZIF:user/release-keys",  # S23 Ultra
})
CONNECT_PORTS = (16384, 5555)

# A filled allowance file narrows every repo device action to the devices it
# lists, for a bounded time. It lives under work/ (gitignored) so a device
# serial never reaches a tracked file, and it is how a one-off experiment is
# authorised without granting a permanent allow list:
#
#     pixi run device allow 10.0.0.5:5555 --hours 4 --purpose "crash frame"
#     pixi run device status
#     pixi run device revoke 10.0.0.5:5555
ALLOW_FILE = ROOT / "work" / "device-allow.json"


def _load_allow() -> list[dict]:
    if not ALLOW_FILE.is_file():
        return []
    try:
        return json.loads(ALLOW_FILE.read_text(encoding="utf-8")).get("allow", [])
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read {ALLOW_FILE}: {exc}")


def _expired(entry: dict) -> bool:
    try:
        until = datetime.fromisoformat(str(entry["until"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return True
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    return until < datetime.now(timezone.utc)


def _allowance(serial: str) -> dict | None:
    for entry in _load_allow():
        if entry.get("serial") == serial and not _expired(entry):
            return entry
    return None


def _require_allowance(serial: str) -> None:
    if not _load_allow():
        return
    if _allowance(serial) is None:
        raise SystemExit(f"{serial}: no allowance on file "
                         f"(see `pixi run device status`)")


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
        _require_allowance(serial)
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
                if _load_allow() and _allowance(candidate) is None:
                    continue
                return candidate
        for port in CONNECT_PORTS:
            run(["connect", f"127.0.0.1:{port}"], timeout=30)
    raise SystemExit("no adb device: start the emulator, or set TB_ADB_SERIAL")


def adb(serial: str, args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    _refuse_if_denied(serial)
    _require_allowance(serial)
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


def cmd_allow(serial: str, hours: float, purpose: str) -> int:
    """Authorise one device for a bounded experiment; deny still wins."""
    _refuse_if_denied(serial)
    fp = _fingerprint(serial)
    if fp in DENY_FINGERPRINTS:
        raise SystemExit(f"{serial}: off limits by owner decision "
                         f"(fingerprint {fp}; see retb-build/AGENTS.md)")
    until = datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() + hours * 3600, timezone.utc)
    entry = {"serial": serial, "fingerprint": fp, "purpose": purpose,
             "until": until.isoformat(timespec="seconds")}
    entries = [e for e in _load_allow() if e.get("serial") != serial] + [entry]
    ALLOW_FILE.parent.mkdir(parents=True, exist_ok=True)
    ALLOW_FILE.write_text(json.dumps({"allow": entries}, indent=2) + "\n",
                          encoding="utf-8")
    print(f"allow {serial} ({fp})")
    print(f"  until   {entry['until']}")
    print(f"  purpose {purpose}")
    return 0


def cmd_revoke(serial: str | None) -> int:
    entries = _load_allow()
    kept = [e for e in entries if e.get("serial") != serial] if serial else []
    ALLOW_FILE.parent.mkdir(parents=True, exist_ok=True)
    ALLOW_FILE.write_text(json.dumps({"allow": kept}, indent=2) + "\n",
                          encoding="utf-8")
    print(f"revoked {len(entries) - len(kept)} allowance(s)"
          + (f" for {serial}" if serial else " (all)"))
    return 0


def cmd_status() -> int:
    print("deny by serial:")
    for s in sorted(DENY_SERIALS):
        print(f"  {s}")
    print("deny by fingerprint:")
    for f in sorted(DENY_FINGERPRINTS):
        print(f"  {f}")
    entries = _load_allow()
    if not entries:
        print(f"allowance: none ({ALLOW_FILE} absent or empty)")
        return 0
    print(f"allowance ({ALLOW_FILE}):")
    for e in entries:
        state = "EXPIRED" if _expired(e) else "active"
        print(f"  {state:7s} {e.get('serial')}  until {e.get('until')}")
        print(f"          {e.get('fingerprint')}")
        print(f"          {e.get('purpose')}")
    return 0


def _emit(text: str, stream) -> None:
    """Write decoded subprocess output without choking on cp1252 consoles."""
    data = text.encode("utf-8", "replace")
    try:
        stream.buffer.write(data)
        stream.flush()
    except AttributeError:
        try:
            stream.write(data.decode("utf-8", "replace"))
        except OSError:
            pass
    except OSError:
        # A closed downstream pipe (piping into head/Select-Object) is not an
        # error for a passthrough command.
        pass


def cmd_adb_args(args: list[str]) -> int:
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        print("usage: pixi run device adb -- <adb arguments>", file=sys.stderr)
        return 2
    serial = ensure_device()
    r = adb(serial, args, timeout=1800)
    _emit(r.stdout, sys.stdout)
    _emit(r.stderr, sys.stderr)
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
    a = sub.add_parser("allow", help="authorise one device for a bounded experiment")
    a.add_argument("serial")
    a.add_argument("--hours", type=float, default=4.0)
    a.add_argument("--purpose", default="unspecified")
    r = sub.add_parser("revoke", help="drop an allowance (all of them when no serial)")
    r.add_argument("serial", nargs="?")
    sub.add_parser("status", help="show deny lists and current allowances")
    sub.add_parser("adb", help="run adb for the allowed device: -- <args>")

    args, extra = ap.parse_known_args()

    if args.cmd == "allow":
        return cmd_allow(args.serial, args.hours, args.purpose)
    if args.cmd == "revoke":
        return cmd_revoke(args.serial)
    if args.cmd == "status":
        return cmd_status()
    if args.cmd == "adb":
        return cmd_adb_args(extra)

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
