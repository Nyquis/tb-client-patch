# EXP and coin rewards

How the client computes battle EXP/coins, how the `reTB` server boosts them,
and why the result screen and the characters/teams screen can disagree.
Nothing here is implemented yet; this records the verified sites and the fix
options.

## Client computation

`BattleManager.<_CheckForDrops>c__Iterator0.MoveNext` (`0xCE9D50`) computes the
reward for each defeated enemy. `$this` is the `BattleManager` at iterator
`+0xF0`.

- EXP (`0xCEA3AC`): `(int)(baseExp * (expMulti + expMultiByItem))`
- coins (`0xCEA3FC`): `(int)(baseCoin * (coinMulti + coinMultiByItem))`

`BattleManager` fields (dump offsets):

| Field | Offset |
|---|---|
| `coinMulti` | `+0x130` |
| `coinMultiByItem` | `+0x134` |
| `expMulti` | `+0x138` |
| `expMultiByItem` | `+0x13C` |

The fields are serialized on the prefab. A scan of every method in
`BattleManager` found no writer for them, so treat them as scene-configured
vanilla values (expected `1.0` / `0.0`; the result screen is not zero).

The result screen applies the gain with `UIBattleResultTeam.AddExp`
(`0xF4DEF8`). That method **loops**:

```
while (addExp >= expToNextLevel) {
    jobExp += expToNextLevel;
    SetJobLevel(job + 1);
    addExp -= expToNextLevel;
}
jobExp += addExp;
```

so a multi-level gain is handled correctly client-side.

## Server computation (`reTB`)

- `tb_server/handlers/userdata/userdata_merge.py::boost_job_exp` diffs the
  posted `jobLevels` against the held roster, multiplies the **gain** by
  `settings.exp_multiplier` (default `10.0`), re-derives the level with
  `level_for_exp`, and stores the boosted total.
- `boost_coin_gain` does the same for `valuables.coins` with
  `settings.coin_multiplier` (default `15.0`).
- `tb_server/handlers/userdata/quest.py::clear_quest` echoes the **full**
  boosted roster (`response.chrdata`) when a character was granted or
  `exp_multiplier != 1.0`; the client's clear callback calls
  `UserData.ResetChrData(...)`, replacing its roster with the boosted one.

## The mismatch

- The **result screen** shows the numbers the client computed during the battle
  (vanilla multipliers, e.g. `1x`).
- The **characters/teams screen** shows the boosted roster returned by
  `clear_quest`.
- The result screen's figures are computed at battle time, before the clear
  response replaces the roster, so they keep the vanilla totals; only
  restarting the app was reported to make the two views agree again.

## Fix options

### 1. Apply the boost on the client (recommended)

Make the client compute the boosted numbers and stop the server from applying
the multiplier, so the result screen, the uploaded `jobLevels`/coins and the
roster are the same values.

- Client: replace the two multiplier loads with constants:
  - `0xCEA3AC`: `ldr s0,[x21,#0x138]` (`a0 3a 41 bd`) -> `fmov s0,#10.0`
    (`00 90 24 1e`)
  - `0xCEA3FC`: `ldr s0,[x21,#0x130]` (`a0 32 41 bd`) -> `fmov s0,#15.0`
    (`00 d0 25 1e`)
- Server: add a config flag that makes `boost_job_exp` and `boost_coin_gain`
  no-ops while the client applies the values. Keep the roster echo (it still
  fixes the level-90 cap, recruit floors and daily-character grants).
- Trade-off: the multiplier is baked at build time, so changing it means
  rebuilding the client. `(expMulti + expMultiByItem)` means item bonuses stay
  additive (`10 + item`) rather than the old server math
  (`10 * (1 + item)`).

### 2. Display-only patch

Keep the server boost and rewrite the result screen's EXP/level/level-up values
from `ResetChrData`'s roster. More UI work: the "EXP gained" figure and the
level-up sequence have already been driven by the client computation, so they
would need replaying against the boosted roster.

### 3. Server multipliers = 1.0

Set `exp_multiplier` and `coin_multiplier` to `1.0`. The mismatch disappears
because the boost is gone; not useful if the tuning is wanted.

## Verification if option 1 is implemented

- `pixi run build` / `pixi run verify` must still print `PASS` (the two new
  bytes are a declared `native_*.json` patch).
- In-game: clear a quest with the boost on; the per-character EXP and level on
  the result screen must match the characters/teams screen, including
  multi-level gains.
- Keep the client constants and the `reTB` tuning in sync; they are one value
  split across two artifacts.
