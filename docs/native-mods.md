# Native mods

Every patch below is declared in `patches/native_*.json` and reverted by
`pixi run verify`. Caves live in verified-zero padding in
`lib/arm64-v8a/libil2cpp.so`.

## Battle speed (2x / 3x / 4x)

The options speed row (`UIIconBtn.Type.MoreFasterFastForward = 63`) selects the
FF multiplier: 2x -> 3x -> 4x -> 2x. The in-battle FF button still toggles FF
on/off. The row's label now shows x4 on the third state; the engine already
mapped state 2 to `timeScale * 4.0`.

`GameManager` (TypeDefIndex 4121) holds the mechanism:

- statics: `timeScale` (+0x8), `deltaTime` (+0x10), `gameDeltaTime` (+0x14),
  `fastForward` (+0x1E), `disableFastForward` (+0x1F),
  `moreFasterFastForward` (+0x20)
- `Update` at RVA `0xD9CCD8` picks the multiplier: the `moreFasterFastForward`
  byte is the **state** (0 = 2x, 1 = 3x, 2 = 4x).
- The options list is code-generated (`UIOptions.InitItems`), and
  `UIIconBtn.Type` is full (0..77, `NumberOfTypes = 78`), so a *fourth button*
  would need new art and array growth. Instead the existing speed option
  **cycles 2x -> 3x -> 4x -> 2x**.

Patch set (`patches/native_speed.json`, all in `lib/arm64-v8a/libil2cpp.so`):

| Site | Change |
|---|---|
| `0xD9CF68` | original `cbz w11,2x` -> `b caveA` |
| `0xE94958` | original `eor w8,w8,#1` (toggle) -> `b caveB` |
| `0xCF9E78..80` | loader: `moreFF = (value==1)` -> `strb w20` (store raw 0..2) |
| `0x20C88D8` | **cave A**: `state==0 -> 2x`, `==1 -> 3x` (existing code), `>=2 -> 4x` |
| `0x20D3500` | **cave B**: type 63 cycles `(state+1) % 3`; other toggles keep `toggle ^= 1`, then `bl UpdateBtn` |
| `0xE93738` | original `ldrh w8,[x19,#0x48]` -> `b caveL` |
| `0x20D1300` | **cave L**: type 63 builds `x2 / x3 / x4` in all states, taking the separator and colour tags from the live 2x/3x suffix strings |
| `0xE95DB0` | original `ldrb w2,[x19,#0x49]` (speed save) -> `b caveS` |
| `0x20D3540` | **cave S**: type 63 writes the raw state to `[GameManager+0xA0]+0x20` before `PlayerPrefs.Save`, so 4x applies without a restart |
| `0xE93690..98` | `InitBtn`: `GetInt(key)` -> `cmp w0,#1` / `cset` / `strb` replaced by `b caveP` + 2 NOPs |
| `0x20D3568` | **cave P**: type 63 restores the stored value verbatim (clamped to 0..2); other toggles keep the original `value == 1` conversion |

Why the caves: the padding runs are zero-filled alignment after a `b` in the
executable segment; each is verified zero in the original, so `verify.py`
reverts them to the reference bytes like any other patch. Cave L deliberately
does **not** read the standalone `" / "` / `[rrggbb]` literal slots: they are
not initialized when `UpdateBtn` runs, so it takes them from the live 2x/3x
suffix strings with `String.IndexOf`/`Substring`. No metadata literal is
edited or added.

Persistence: the click handler saves the raw byte with `PlayerPrefs.SetInt`;
cave S also writes the live state field, and the `StartBattle` loader restores it
from PlayerPrefs on the next battle. The *key* (`0x2AAA660`) has exactly two
sites in the binary and both had to be patched: `OnClickBtn` saves it (cave S),
and `UIIconBtn.InitBtn` loads it at `0xE93674` with `toggle = (value == 1)`.
Leaving that second one alone made a saved `2` come back as `0` (x4 reverted to
x2) even though x2/x3 round-tripped. Cave P now stores the loaded value
verbatim for type 63 and replays the original boolean conversion for every
other toggle. `prefs_keys` in the patch JSON declares the key's sites, and
`pixi run audit` rescans the binary and fails if the reference set changes or a
declared site is not patched.

Cave S must **not** touch `x8`. `OnClickBtn` loads the PlayerPrefs key slot into
`x8` at `0xE95DA8` and re-reads it at `0xE95DBC` (`ldr x1,[x8]`); an earlier
version reused `x8` for the GameManager chain, so `SetInt` received
`*(static_fields)` — the `GameManager` instance (`static GameManager instance` is
field `0x0`) — as the key string and the process died on the first click. The
cave uses `x9`/`x10` instead. Live registers per hook are declared in the patch
JSON (`"live": "x8,x19"`) and enforced twice: by the generator and by
`pixi run audit` (`tools/audit_patches.py`), which also rejects stale hook
targets, overlapping caves and any use of `x18`.

Caveats:

- arm64 only (armv7 untouched).
- The button's icon is still a 2-state on/off sprite; the label now carries the
  2x/x3/x4 distinction. A distinct icon is not possible without a new
  `UIIconBtn.Type` slot and art.
- `verify.py` reverts every declared patch and requires the rest of the binary
  to be byte-identical to the reference.

## Infinite time, invincibility, one-hit

Three dead Kamcord buttons in the in-battle menu (`UIInBattleMenu`) are
repurposed:

| Button | Type | Flag | Effect |
|---|---|---|---|
| `shareButton` | 28 `KamcordShare` | `DebugManager.enableTestZClass` (+0x25) | one-hit kill enemies |
| `recButton` | 30 `KamcordStartRec` | `DebugManager.higeTest` (+0x11) | freezes the turn-time gauge |
| `stopRecButton` | 29 `KamcordStopRec` | `DebugManager.higeMiniTest` (+0x12) | party invincibility |

All three toggle on click: red = on, white = off. The colour is re-synced when
the in-battle menu is reopened, and all three persist across restarts.

### Patch set (`patches/native_time.json`, enabled)

| Site | Original | Change |
|---|---|---|
| `0xCC8490` | `b.le 0xCC8594` | normal chapters (`battleTimelimit <= 0`) -> cave 2 |
| `0xCC84C0` | `str s1,[x19,#0x258]` | time-limited chapters: remaining-time store -> cave 1 |
| `0xE9399C` | `tbz w8,#0,0xE93AA0` | Everyplay gate: allow types **28/29/30** -> cave 3 |
| `0xE93A40` | `strb w20,[x19,#0x68]` | force `available=1` for types 28/29/30 -> cave 4 |
| `0xE95268` | `adrp x8,#0x2a66000` | type-28 click -> cave 5 |
| `0xE952C4` | `adrp x21,#0x2a6c000` | type-29 click -> cave 5 |
| `0xE95384` | `adrp x8,#0x2a6c000` | type-30 click -> cave 5 |
| `0xE93A88` | `bl 0xE93AD8` (`SetColor`) | labels + icon on menu open -> cave 6 |
| `0xE93AD8` | `stp d15,d14,[sp,#-0x60]!` | SetColor choke: red/white for 28/29/30 -> cave 10 |
| `0xCFA050` | `bl SetDisableFlag` | restore flags from PlayerPrefs -> cave 12 (also skips `SetDisableFlag(30)`) |
| `0xCFA040` | `bl SetDisableFlag` | nop `SetDisableFlag(28)` in `StartBattle` |
| `0xCFA060` | `bl SetDisableFlag` | nop `SetDisableFlag(29)` in `StartBattle` |
| `0x1091200` | `ldrb w8,[x19,#0x234]` | `Entity.Damage`: party muteki at damage time -> cave 13 |
| `0x10911F8` | `cmp w23,#0` (resulting HP) | `Entity.Damage`: one-hit enemies -> cave 14 |
| `0x20C8A20` | zeros | cave 1: skip the `currentRemainTime` store |
| `0x20C8A60` | zeros | cave 2: skip the live drag-time path |
| `0x20C8AE0` | zeros | cave 3: Everyplay/type-28/29/30 gate |
| `0x20C8B00` | zeros | cave 4: force available |
| `0x20C8D70` | zeros | cave 5: unified click (time/invincibility/one-hit + colour) |
| `0x20C8F00` | zeros | cave 6: `titles[30]=UI_TIME`, `[29]=UI_HP`, `[28]=UI_KILL`, icon switch |
| `0x20C9000` | zeros | cave 8: switch icon atlas to 12740, pick `icon_time`/`icon_HP`/`icon_attack`/`icon_dungeon_02` (STOP) by rect |
| `0x20C9280` | zeros | cave 10: SetColor choke (red/white for 28/29/30) |
| `0x20C9800` | zeros | cave 11: save all three flags to PlayerPrefs |
| `0x20C9900` | zeros | cave 12: restore all three flags at battle start |
| `0x20C9A50` | zeros | cave 13: party muteki at damage time |
| `0x20C9D00` | zeros | cave 14: one-hit kill enemies at damage time |

Flags: `DebugManager.higeTest` (+0x11), `higeMiniTest` (+0x12) and
`enableTestZClass` (+0x25). A scan of the 35 `DebugManager` class-pointer loads
(29 methods) found **no** access to any of them, so they are dead in the shipped
build. Access from caves is `[[0x2a99570]] + 0xa0 -> +offset`.

### Timer paths

- Normal chapters (`battleTimelimit <= 0`): `UpdateTimeGuage` takes
  `b.le 0xCC8594`, the live drag-time path, which tail-calls
  `SetTimeGuageAmount` at `0xCC86C4`; that stores the new value into
  `currentRemainTime` at `0xCC80E8` and updates the gauge/label. Cave 2 restores
  `UpdateTimeGuage`'s frame and returns when the flag is set, freezing the
  gauge, label and expiry check.
- Time-limited chapters: the `battleTimelimit > 0` path decrements
  `currentRemainTime` at `0xCC84C0`; cave 1 skips that store.
- `ReduceRemainTime` (`0xCC912C`) only adjusts `dragBeginTime`; it is not the
  countdown.

### Invincibility

`Entity.isMuteki` (`+0x234`) is read by `Entity.Damage` (`0x10910C4`, check at
`0x1091200`): when the post-hit HP would be <= 0 it is clamped to **1**, so the
entity survives. The click cave calls
`TutorialManager.SetMutekiFlag(Entity.Type.Party, flag)` (`0x117CC70`), which
iterates `bm.GetEntities(Party)` and calls `Entity.set_muteki`.
`DebugManager.partyMuteki`/`enemyMuteki` are dead (0 code references).
`TutorialManager.instance` is a real static (`+0x0`); the bundle ships one
TutorialManager object. This is the game's "survive at 1 HP" muteki, not
zero-damage immunity.

Cave 13 widens the same check: at `0x1091200` a lethal hit is clamped to 1 when
`isMuteki` **or** (`higeMiniTest` && `Entity.status (+0x38) -> Status.type
(+0x2C) == 0`). `Status.type == 0` is `Entity.Type.Party`, the same test
`Entity.IsFriendParty` uses. This is what makes a *restored* invincibility flag
take effect from the first hit: `SetMutekiFlag` only marks entities alive at the
moment of the call, and the `StartBattle` hook runs before
`WaitForBattleSetup`.

### One-hit kill

`Entity.Damage` computes the **resulting HP** into `w23` at
`0x10911DC`..`0x10911F4` (`w23 = status.HP - max(damage, 0)`), then tests it at
`0x10911F8`. Cave 14 hooks there: when `enableTestZClass` (+0x25) is set and
`Entity.status (+0x38) -> Status.type (+0x2C) == 1` (`Entity.Type.Enemy`), it
forces `w23 = 0`, so any hit kills. Every other case replays the original
`cmp w23,#0 / b.gt / -> 0x1091200` flow, so party muteki (cave 13) is
unaffected.

This runs per hit, so entities spawned mid-battle are covered and no re-apply is
needed after a restart - cave 12 only has to restore the flag byte.

Caveat: it also bypasses scripted invulnerability, so chapters that require a
boss to survive to a cutscene can behave oddly while it is on.

### Persistence (caves 11/12/13/14)

All three toggles survive restarts, stored as a 4-bit mask under the
**`versionVerify_terra_battle_mistwalker`** literal (cell `0x2BDC668`; bit 0 =
TIME, bit 1 = HP, bit 2 = KILL, bit 3 = AUTO).

- **Do not use `ShowedFirstEvelyplayUploadWindow`.** Its setter
  `UserData.SetShowedFirstEveryplayUploadWindow` (`0x19DDA30`) writes only
  `v & 1` (`and w2,w19,#1`) and runs at the title; it wipes bits 2/3 of the
  mask, so Auto reverted on every screen change and never reached
  `StartBattle`. The verifier string is only hashed by the version check; no
  PlayerPrefs code reads or writes it. Existing toggles reset once on upgrade
  (the old key's value is no longer read).
- PlayerPrefs are app-private, so this adds no compatibility requirement: same
  package, same signer, no metadata change, and a stock client ignores it.
- `tools/check_mask_keys.py` (run by `build` and as `pixi run checkmask`)
  disassembles every cave in `native_killstart`, `native_time` and
  `native_options` and fails if any of them still references the retired key.
  This is the guard for the key change: all three families must move together.
- **Save** (cave 11, `0x20C9800`): called from cave 5 after every toggle. It
  rebuilds the mask from `higeTest`/`higeMiniTest`/`enableTestZClass` and calls
  `PlayerPrefs.SetInt` + `PlayerPrefs.Save`.
- **Load** (cave 12, `0x20C9900`): hooked over the old `SetDisableFlag(30)` nop
  at `0xCFA050`, in `BattleManager.<StartBattle>c__Iterator6.MoveNext` state 12
  (once per battle). It reads the mask, writes all three `DebugManager` bytes,
  and re-applies `SetMutekiFlag(Party, true)` when bit 1 is set.

Calling convention gotcha: this build passes PlayerPrefs keys in **`x1`** (`x0`
zeroed, value in `x2`, `x3` zeroed). The caves copy the exact shape of
`UIIconBtn.OnClickBtn`'s speed save at `0xE95DC0`. The literal cell is loaded
with `adrp`+`add` directly, bypassing the per-method metadata usage slot; the
9717 literals form one contiguous pointer table (`0x2BD1A90`..`0x2BE4A30`,
8-byte stride) that IL2CPP fills when the owning module's metadata usages
initialise. The key's reader is `UserData.GetShowedFirstEveyplayUploadWindow`,
so the cell is populated long before any battle; both caves still guard the
load with `cbz` and skip persistence rather than call `PlayerPrefs` with null.

### Why the buttons need three extra hooks

- `SetKamcordButtonAvailable` calls `EventManager.IsEveryplayEnable()`; when
  false it jumps to `0xE93AA0` and `SetActive(false)`s the whole button. Cave 3
  lets types 28/29/30 through.
- `KamcordManager.IsEnable()` is hardcoded `false`; cave 4 forces `available = 1`
  for the same three types.
- `BattleManager.<StartBattle>` calls `SetDisableFlag(28/30/29)`. The 30 call is
  replaced by the persistence load (cave 12); the 28 and 29 calls are nop'd
  (`0xCFA040`/`0xCFA060`) so the buttons stay clickable.
- `ShowMenu -> InitBtn -> SetKamcordButtonAvailable` repaints white at
  `0xE93A88`; cave 6 re-reads the right flag and paints red/white.

### Useful addresses / patterns

- `UIIconBtn.Type`: `KamcordStopRec=29`, `KamcordStartRec=30`, `KamcordShare=28`.
- Click path: prefab `UIButtonMessage(functionName="OnClickBtn", target=<UIIconBtn go>)`
  -> `UIIconBtn.OnClickBtn` jump table (`t1 = 0x21C6CD0`, `t2 = 0x21C6A80`).
- `UIIconBtn.SetColor` `0xE93AD8`; `Color.get_red` `0x1D64618`,
  `Color.get_white` `0x1D64640`.
- `DebugManager` static block: `[[0x2a99570]] + 0xa0`. `TutorialManager` static
  block: `[[0x2a97ff0]] + 0xa0` (`instance` at +0x0).
- Cave area: zeros after the last method RVA (`0x201215C`). Current caves live
  at `0x20C8A20..0x20C9D54` (cave 6 at `0x20C8F00`, cave 10 at `0x20C9280`,
  persistence at `0x20C9800`/`0x20C9900`, damage checks at `0x20C9A50`/
  `0x20C9D00`). Always verify the original bytes are zero before placing a cave.
- `Entity.Damage` `0x10910C4`, `Entity.get/set_muteki` `0x107908C`/`0x1079094`.

## Trash-clear mode (Auto Play)

`patches/native_killstart.json` + `patches/native_options.json` (both enabled).
The sweep takes visible, alive, **non-boss** enemies; `isMuteki` -> `SetHP(1)`;
else `CheckForDrops(e,false,deadCombo)` + `Die()`, with `deadCombo =
BattleManager.expBonusCnt` (+0x358), the value `StartDeadAnim -> IllustDeadAnim`
uses.

- **Auto Play** (Options item, mask bit 3, set **before** battle): hooked at the
  enemy-turn state entry `0xCE92E0` (`ldr x20,[x21]`), **before** the
  null-guarded `onEnemyTurn` delegate. The cave loads `bm = [x19+0xE0]`, sweeps,
  restores `x21 = x19+0xE0`, replays the instruction and resumes at `0xCE92E4`.
  This is why it works in Metal Zone (`Chapter3003` registers only
  `onPlayerTurn` in `BattleCommon`). It keeps the one-hit byte set so **bosses**
  (which the sweep deliberately skips) still die in one hit when attacked.
- **No move sweep.** The old Manual Defeat hook at `Entity.EndDrag`'s
  real-move commit `0x108DE34` is gone. `1-Hit` (the in-battle KILL/share
  toggle) now only affects damage: an enemy dies when it is pincered or
  damaged in any other way, never because the player moved.
- **State mask** (version-verifier literal
  `versionVerify_terra_battle_mistwalker`, cell `0x2BDC668`; the Everyplay key
  is unusable because its 0/1 setter wipes the mask): bit 0 TIME, bit 1 HP,
  bit 2 the one-hit byte mirror, bit 3 AUTO. Cave11 preserves bit 3 and writes
  bit 2 = 0 while bit 3 is set; cave12 forces the KILL byte to 1 under bit 3 so
  **one-hit stays active** under Auto.
- **Mutual exclusion / STOP**: when Auto is on, the in-battle KILL button is
  red, labelled `UI_BTN_KAMCORD_STOP` (298), and tapping it stops Auto (clears
  bits 3/2, KILL byte 0, saves). When Auto is off the button is the normal
  KILL toggle (`UI_KILL`, 581). Cave6 chooses the label; cave5 handles the
  click; cave10 paints red/white from the KILL byte. While Auto is on the
  icon is `icon_dungeon_02` (status atlas, 975/293); cave8 selects it from
  mask bit 3, and cave5's STOP path calls cave8 again so the icon reverts to
  `icon_attack` (1003/800) immediately.
- **Options item**: the dead Help row (`UIIconBtn` type 27) is repurposed. Do
  **not** use the built-in toggle mode: `UIIconBtn.OnClickBtn`'s `isToggleBtn`
  prologue flips `toggle` and calls `UpdateBtn` **before** the type dispatch,
  and that toggle-specific path is what failed for type 27 while the plain
  Sound/Music rows worked. Instead, hook the `bl UpdateBtn` at the end of
  `InitBtn`'s default path (`0xE9349C`): for type 27 set `titles[27] =
  UI_MULTIPLAY_REGION_AUTO` (450, "Auto"), force `isToggleBtn = 0`, call
  `UpdateBtn` for the text, then paint red/white from mask bit 3. Hook the
  type-27 click case at `0xE95218`: toggle bit 3 from the **mask** (clear bit 2
  when enabling), save it, set `toggle`, keep `isToggleBtn = 0`, and repaint.
  `UIOptions.InitItems` adds type 27 unconditionally (the filter's default-add
  branch at `0xF9DCF4`), and `AddItem` stores `type` before calling `InitBtn`
  (`0xF9E044`), so the row is built with the Auto label and saved state. The
  same init-end cave swaps the icon to `icon_battle` (literal cell
  `0x2BE05C8`, same button atlas as the Options rows).
- Timing is deliberate: **not** during `WaitForBattleSetup`. At `0xCFC474` the
  sweep ran before the second `IllustAppear`, whose
  `IllustController.PlayAppear` calls `Entity.Register` and re-inserted killed
  units into `gridTable` as invisible blockers. At the enemy-turn/move boundary
  the appear pipeline is done, so `Entity.Die()`'s `Unregister()` is final.
- EXP/coins: `_CheckForDrops` uses `baseExp * (expMulti + expMultiByItem)` and
  `baseCoin * (coinMulti + coinMultiByItem)`; no chain term. The host-side
  boost and the result-screen/roster mismatch are documented in
  `docs/rewards.md`.
- Bosses are spared on purpose: several chapters script enemy retreats
  (`ChapterInterface.Escape` in 1002, 1300, 1301, 2003, 2014, 3004, 38, 4002,
  4003, 4102, 4103, 6002, 6003), phase changes (`CH30_NextForm`,
  `CH2016_NextForm`, `Chapter2014.DancePair`) and revival
  (`ChapterBase.ReviveOnEnemyTurn`).
- `verify` reverts every hook and cave like any other declared patch.

## Attack SE survive minimise/resume (`patches/native_audio.json`, enabled)

Vanilla bug: attack/spell sound effects stop after the app is backgrounded and
resumed; BGM and visuals are fine, and only an app restart brings the sounds
back.

Attack SE go through Master Audio (`AudioController.Play` -> `PlayAudioItem` ->
`PlayAudioSubItem` -> `AudioObject`), while BGM is the separate `MusicManager`
system with its own `AudioSource[]`, so only SE are affected.

- `AudioObject.OnApplicationPause` (`0xCA63F0`) sets `_applicationPaused`
  (`+0x65`); `_OnPlay` (`0xCA5450`) never clears it.
- `AudioObject.Update` (`0xCA5594`) reads `_paused | _applicationPaused` as a
  halfword; while set it jumps to `_UpdateFadeVolume` and returns, skipping
  completion detection and the `completelyPlayedDelegate` that returns the
  object to the pool.
- That pool is capped: `ObjectPoolController.ObjectPool.GetPooledInstance`
  does `pool.Count >= PoolableObject.maxPoolSize` -> return null (`0xEFA6C8`).
- Flagged objects therefore leak one pool slot per attack; once the pool is dry
  every Master Audio SE is silent - across battles, until a restart.

| Site | Change |
|---|---|
| `0xCA5468` | `strb wzr,[x0,#0x64]` -> `strh wzr,[x0,#0x64]`: clears `_paused` **and** `_applicationPaused` on every play |
| `0xCA55A4` | `b.hi 0xCA58A4` -> `nop`: `Update` ignores a stale `_applicationPaused` |

Unity does not call `Update` while the app is truly paused, so the removed
branch only ever mattered after resume. Generator: `work/gen_audio_patch.py`.

# Story skip button (`patches/native_story.json`, enabled)

The story window owns the button: `UIEventWindow.skipPanel` (field `0x80`) holds
it, and `showSkipPanel` (`0x88`) decides whether it is shown.
`<startEvent>c__IteratorA.MoveNext` reads the flag once per story:

```asm
strb wzr, [x20, #0xa0]      ; disableSkip = false
strb wzr, [x20, #0x89]      ; eventSkipped = false
ldrb w22, [x20, #0x88]      ; showSkipPanel
ldr  x20, [x8, #0x80]       ; skipPanel
cbz  w22, ...               ; hidden unless set
SetActive(true)
```

The click handler has no guard: `OnClickSkip` (`0xEC6CC0`) runs
`textFX.Skip(); eventSkipped = true;`. The flag is the only gate.

Apart from the `Awake` reset, only two instructions in the binary write
`showSkipPanel`, both in the generated chapter scripts and both shaped as
`showSkipPanel = chapter.<virtual bool>() & 1`:

| Site | Change |
|---|---|
| `0x1533770` | `and w8,w20,#1` -> `mov w8,#1`: normal chapter story |
| `0x1534BF0` | `and w8,w20,#1` -> `mov w8,#1`: in-battle story |

Effect: the existing Skip button appears for every chapter story and every
in-battle story, including the first viewing. No cave, no register or pref
interaction.

Not covered: the story archive (`UIBookListItem` -> `UIEventWindow.PopupEvents`).
That path never touches `skipPanel` (it only hides `controlPanel`), so it needs
its own patch instead of picking up this flag.

`disableSkip` (`0xA0`) is reset at the start of each story and is the target of
the `DisableSkip` text command (`TextFX.AddDisableSkipCommand`, `0x116F2E4`); no
reader of the field was found in the class.

# Battle-menu labels: 1-Hit / Stop (`patches/native_kill_label.json`, enabled)

Cave 6 (`native_time.json`) sets `titles[28]` for the repurposed Kamcord row:
`UIStrings.UI_KILL` (581) normally, or `UI_BTN_KAMCORD_STOP` (298, the Kamcord
"stop recording" string) while Auto Play is on. `UIIconBtn.UpdateBtn` resolves
that id through `StringSet.GetUIString`, and the UI text table is not in the APK,
so the strings cannot be edited directly.

Instead the load of `titles[type]` is hooked and two ids are answered locally:

| Site | Change |
|---|---|
| `0xE93710` | `ldr w1,[x8,#0x20]` -> `b 0x20C9F34` |
| `0x20C9F34` | **label cave**: id 581 -> `"1-Hit"`, id 298 -> `"Stop"`, else original path |

The cave stores `"1-Hit\0Stop\0"` in its own padding, calls the exported
`il2cpp_string_new` (`0xBE7908`, a thunk to `0xC064E8`) and `UILabel.set_text`
(`0xE89CD0`), then leaves through `UpdateBtn`'s epilogue (`0xE9386C`). Because it
never returns to the suffix logic at `0xE93738`, the result does not depend on
whether the row is a toggle.

No metadata literal is rewritten, so `verify.py` still sees zero semantic
literal differences. The strings are ASCII and NUL-terminated; length is bounded
by the cave blob (84 B used of a 118 B zero run) and by the button's fixed-width
label, which has no auto-fit (`SetFontSize` is only called from
`UIMain.SetLayout`).

# Drop Rate row (`patches/native_droprate.json`, enabled)

The Support button (`UIIconBtn.Type 23`, whose click case at `0xE9513C` used to
open a URL) becomes a three-state item-drop multiplier. Its state lives in the
same AppSettings key as the in-battle toggles (`0x2BDC668`), in **bits 4-5**,
which the existing writers leave alone because they clear only bits 2-3
(`bic #0xC`).

| State | Label | Effect |
|---|---|---|
| 0 | x1 | vanilla |
| 1 | x5 | final drop chance × 5 |
| 2 | Max | final drop chance = 200 (always above the roll) |

| Site | Change |
|---|---|
| `0xE95100` | type-23 click case -> cycle cave (type 24/TOS at `0xE9513C` is untouched) |
| `0x20C9728` | **click cave**: cycle bits 4-5, `PlayerPrefs.SetInt`+`Save`, `UpdateBtn`, epilogue |
| `0xE92EE0` | `InitBtn` `icons[type]` load -> icon cave |
| `0x20C922C` | **icon cave**: type 23 -> `icon_treasure_chest_03` (same atlas as `icon_support`, `path_id 12742`, so no atlas switch) |
| `0xCEA468` | final item drop chance store -> apply cave |
| `0x20C93E8` | **apply cave**: x1 / ×5.0 / 200.0 |

The label is rendered by the battle-label cave in `native_kill_label.json`,
which now branches to the drop-label cave (`0x20C9138`) for type 23 and builds
one of three pre-tagged strings:

```
[ffffff]Drop Rate x1[808080] / x5 / Max                (state 0)
[ffffff]Drop Rate [808080]x1[ffffff] / x5[808080] / Max (state 1)
[ffffff]Drop Rate [808080]x1 / x5[ffffff] / Max         (state 2)
```

The multiplier is applied where `BattleManager.<_CheckForDrops>c__Iterator0`
stores the final chance (`0xCEA468`). The roll compares that value against
`RandomRange(0,1000) × 0.1`, i.e. a threshold uniform in `[0,100)`, so the stored
value is a percentage: ×5 turns 1% into 5%, and `Max` (200) is guaranteed for
every item slot. Monster recruits and buddies are separate paths gated by
`ChrInfo.canDrop` / `BuddyData.canDrop` and are not affected.

Generator: `work/gen_drop_rate_patch.py` (also regenerates the battle-label
cave, so the two files stay in sync).


