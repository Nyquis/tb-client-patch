# Battle rate rows (Drop / Coin / EXP)

Three Options rows cycle a multiplier that the client applies while the battle
is still being scored. They reuse dead option entries, so no new art, enum
values or array growth was needed.

| Row | Type reused | States | Where the multiplier lands |
|---|---|---|---|
| Drop Rate | `23 Support` | x1 / x5 / Max | final item drop chance, `0xCEA468` |
| Coin Rate | `25 PrivacyPolicy` | x1 / x15 / x99 | coin formula, `0xCEA410` |
| EXP Rate | `22 Credits` | x1 / x10 / x99 | `earnedExp` accumulator, `0xCEB5F4` |

All three states live in the same AppSettings `PlayerPrefs` key the in-battle
toggles use (`0x2BDC668`), in bits the existing writers never touch:

| Bits | Owner |
|---|---|
| 0-3 | 1-Hit / Stop / Auto and the timer freeze |
| 4-5 | Drop Rate |
| 8-9 | Coin Rate |
| 10-11 | EXP Rate |

Every cave reads the mask through `PlayerPrefs.GetInt` on that key. The label
and click caves render and advance the row; the apply caves only read.

## Why the multipliers are where they are

The client computes all three values itself and the server stores what it is
given, so the multiplier has to sit *before* the client derives the derived
numbers (levels, wallet, drop list).

- **Coins** are computed once per pickup in `_CheckForDrops`.
- **EXP** is accumulated into `BattleManager.earnedExp` inside the same
  iterator (`w1 = get_earnedExp() + delta`). Scaling the delta means the
  in-battle counter, the results screen and the uploaded `jobLevels` all come
  from one number.
- **Drops** are rolled from the chance stored at `0xCEA468`, compared against
  `RandomRange(0,1000) × 0.1`; `Max` writes 200, which is above every roll.

## Two dead ends worth recording

**`UIBattleResultTeam.AddExp` is dead code.** It has zero call sites. The
results screen applies EXP through `UITeamStateItem.<AddExp>c__Iterator3`,
which `UIBattleResultTeam.<ShowAnim>` calls. Hooking `AddExp` produced no
effect at all, which cost a build and a device test to discover.

**"Max = jump to level 90" froze the results screen.** At the level cap the
curve's next-level step is 1 EXP (the vanilla "1 exp left" bar), so forcing
the level made every 1-EXP step re-enter the level-up loop - a Metal King
clear became hundreds of thousands of iterations. Level forcing was dropped;
`Max` is a x99 multiplier and levels rise naturally.

## Icons

The rows keep their original type icons. `icon_c` / `icon_exp` live in the
**status** atlas, not the atlas the option button's `UISprite` is bound to:
`UIIconBtn` only calls `UISprite.set_spriteName`, and NGUI resolves names
within the sprite's current atlas, so those names render nothing. The Drop
Rate row uses `icon_treasure_chest_03` precisely because it is in the same
atlas as `icon_support`.

Switching the atlas at runtime would need the status `UIAtlas` instance,
which this build does not expose through any global; it is left undone.

## Server side

`exp_multiplier` / `coin_multiplier` in reTB default to 1.0 for exactly this
reason - the client scales. Setting them as well multiplies twice (x10 there
on x10 here is x100). The knobs still work; they are simply not the default.
