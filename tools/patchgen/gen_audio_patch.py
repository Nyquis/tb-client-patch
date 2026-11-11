#!/usr/bin/env python3
# Copyright 2026 Nyquis
# SPDX-License-Identifier: Apache-2.0
"""Generate patches/native_audio.json - attack/spell SE survive minimise/resume.

Master Audio's `AudioObject` (libil2cpp.so) keeps a frame-loop flag
`_applicationPaused` at +0x65.  `OnApplicationPause` (0xCA63F0) is the only
writer that clears it on resume; `_OnPlay` (0xCA5450) never does.  `Update`
(0xCA5594) reads `_paused | _applicationPaused` as a halfword and, when either
is set, jumps straight to `_UpdateFadeVolume` and returns - skipping completion
detection and the `completelyPlayedDelegate` that returns the object to the
capped `ObjectPoolController` pool (maxPoolSize at PoolableObject +0x18).

When the resume message does not reach the pooled objects they stay flagged.
Every attack then leaks one AudioObject; once the pool hits maxPoolSize,
`GetPooledInstance` returns null (0xEFA6C8) and every Master Audio SE goes
silent - across battles, until the app restarts and rebuilds the pool.  BGM is
unaffected because it is the separate MusicManager system.

Two safe changes:

* 0xCA5468  strb wzr,[x0,#0x64] -> strh wzr,[x0,#0x64]
  A new play clears `_paused` AND `_applicationPaused` on that object.
* 0xCA55A4  b.hi 0xCA58A4 -> nop
  Update always runs its main body, so a stale flag can never strand an object.

Neither change alters real pausing: Unity does not call Update while the app is
actually paused, so the branch only ever mattered after resume.
"""

from __future__ import annotations

import json
from pathlib import Path
from hooks import annotate
from sites import guard

ROOT = Path(__file__).resolve().parents[2]   # repo root (tools/patchgen/)
SO = ROOT / "work" / "il2cpp" / "libil2cpp.so"

PLAY_CLEAR = 0xCA5468   # strb wzr,[x0,#0x64] in AudioObject._OnPlay
UPDATE_GATE = 0xCA55A4  # b.hi 0xCA58A4 in AudioObject.Update

# strh wzr,[x0,#0x64]: same store, 16-bit, so it also clears +0x65.
STRH_WZR_X0_0X64 = 0x79000000 | ((0x64 // 2) << 10) | 31
NOP = 0xD503201F


def main() -> int:
    so = SO.read_bytes()

    assert so[PLAY_CLEAR:PLAY_CLEAR + 4] == bytes.fromhex("1f900139"), "play-clear site"
    assert so[UPDATE_GATE:UPDATE_GATE + 4] == bytes.fromhex("08180054"), "update-gate site"

    spec = {
        "_comment": (
            "Attack/spell SE stop after minimise/resume. AudioObject._OnPlay "
            "never clears _applicationPaused (+0x65), and Update skips "
            "completion/pool-return while it is set; the capped AudioObject pool "
            "then runs dry (ObjectPoolController.GetPooledInstance returns null) "
            "and every Master Audio SE stays silent until an app restart. "
            "0xCA5468 clears both pause bytes on every play; 0xCA55A4 removes the "
            "Update gate. BGM is unaffected (separate MusicManager)."
        ),
        "enabled": True,
        "patches": [
            {
                "offset": hex(PLAY_CLEAR),
                **guard(so[PLAY_CLEAR:PLAY_CLEAR + 4]),
                "patch": STRH_WZR_X0_0X64.to_bytes(4, "little").hex(),
                "note": "AudioObject._OnPlay: clear _paused and _applicationPaused",
            },
            {
                "offset": hex(UPDATE_GATE),
                **guard(so[UPDATE_GATE:UPDATE_GATE + 4]),
                "patch": NOP.to_bytes(4, "little").hex(),
                "note": "AudioObject.Update: ignore a stale _applicationPaused",
            },
        ],
    }
    annotate(spec)
    (ROOT / "patches" / "native_audio.json").write_text(
        json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    print("wrote patches/native_audio.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
