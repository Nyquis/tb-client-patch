# AGENTS.md - tb-client-patch

Reproducible, fully local patcher that turns your own **Terra Battle 5.5.7
(170)** APK into a client that talks to the reTB server on `127.0.0.1:8080`
(reTB Host on the phone, or reTB on a PC). The repo holds the *recipe* only.

## Hard rules

- **Never commit game binaries or the signing key.** `input/`, `dist/`,
  `work/` and `keys/` are gitignored.
- **Never install system-wide.** Python/JDK come from `pixi`; SDK tools live in
  `.android-sdk/`; nothing is added to PATH globally.
- **Never delete `keys/`.** A new key = a new app identity = uninstall the old
  client first (the account lives on the server, so only local cache is lost).
- **Never distribute the patched APK.** Personal use only; see `NOTICE`.
- **The keystore password never enters the repo.** `tools/signing.py` reads it
  from `keys/keystore.pass` or `TB_KEY_PASS`.
- Local commits only, never push.

## Layout

| Path | What |
|---|---|
| `input/` | your APK: `*-original.apk` only (untracked) |
| `patches/` | the declarative recipe: endpoints, dex (byte rules), smali (inserts), native_*.json, inputs, signing |
| `tools/` | build, verify, doctor, keycheck, unpack, rebaseline, transforms, audit, analysis |
| `tools/patchgen/` | generators that emit `patches/native_*.json` (see its README) |
| `docs/` | reference: patcher, verification, native-mods, native-guards, signing, apk-internals, rewards, new-game-toggle, investigation |
| `work/` | extracted `il2cpp/*`, caches, analysis (untracked) |
| `keys/` | signing keystore + `keystore.pass` (untracked) |
| `.android-sdk/` | local build-tools 35 + platform-tools (`TB_BUILD_TOOLS`, `TB_ADB` override) |
| `.pixi/` | python 3.13 + openjdk 21 + pinned pip packages |

## Commands

```sh
pixi run unpack          # work/il2cpp/* from the input APK (once per APK)
pixi run doctor          # inputs, toolchain, apktool pin, key pin, patch data
pixi run keycheck        # keystore == patches/signing.json
pixi run build           # original + patches -> dist/TerraBattle-...-patched.apk
pixi run build --without dex-ads   # one-variable experiment; verify takes the same flag
                                   # (docs/unverified.md; never a release build)
pixi run verify          # every difference from the original is a declared transform
pixi run dist            # build -> verify -> dist/release (+ SHA256SUMS, NOTES)
pixi run audit           # caves: hook targets, overlaps, live regs, x18, literals
pixi run audit-selftest  # the audit must still reject every defect class
pixi run checkmask       # no cave still reads the retired Everyplay key
pixi run rebaseline --original input/other.apk   # check recipe, then re-pin inputs
pixi run install         # adb install -r the built APK
pixi run newkey          # only if keys/ was lost (changes the app identity)
pixi run index           # ensure the shared .tools index exists
pixi run find-refs --slot 0x2A508E0        # who references this slot
pixi run find-refs --imm 0x88 --insn strb  # which sites write this field offset
pixi run jumptable --at 0x1A2B3C --count 40
```

## Pipeline (build order)

1. **Endpoints** (`patches/endpoints.json`): 12 IL2CPP literals rewritten to
   `http://127.0.0.1:8080/...`; a shorter replacement also rewrites the length
   entry (`tools/il2cpp_meta.py`).
2. **Manifest**: `MobileAdsInitProvider` and `AdActivity` removed
   (`tools/axml.py`).
3. **classes.dex** (`tools/dex_transform.py`): *smali* inserts
   (`patches/smali.json`, needs apktool) then *byte* rules (`patches/dex.json`).
4. **16 KB** (`tools/elf16k.py`): `p_align` raised; `libmain`'s second segment
   moves to its own page with pointers, relocs, dynamic tags and `ADRP` fixed.
5. **Native byte patches** (`patches/native_*.json`).
6. **Repack** (original order/compression) -> `zipalign -P 16` -> `apksigner`.

## Signing identity

`keys/tb-client.keystore` is the only identity; its public half is pinned in
`patches/signing.json` (SHA-256 `62:AF:40:13:...:D8:A8`, `CN=tb-client-patch`).
`build` deletes the APK on a signer mismatch; `keycheck` verifies a restored
key. Backup, restore and recovery: `docs/signing.md`.

## Verification protocol

`pixi run verify` must print `PASS`:

- every entry not transformed is **byte-identical** to the original;
- every differing entry is **reproduced by re-running its declared transform**
  (literals, manifest removals, smali + byte rules, 16 KB repair + native
  patches);
- inside a repaired library every changed word classifies as headers, dynamic
  table, relocation, dynsym or a verified `ADRP` page move;
- arm64 `PT_LOAD`s are 16 KB aligned and congruent; `zipalign -P 16` passes;
  v2 signature from the pinned signer.

`pixi run doctor` must pass first, and `audit`/`audit-selftest`/`checkmask` must
stay green after touching a cave. Details: `docs/verification.md`.

## Gotchas

- **A 4-byte patch that branches into a cave must declare `hook: true`**, and a
  cave's exits belong in `targets`; `audit` fails otherwise. Deliberate
  exceptions use `"hook": false` plus a `reason`. Caves live in verified-zero
  padding and are emitted by `tools/patchgen/`, not hand-written.
- **Never use `x18` as scratch** (platform register on Android/AArch64); use
  `x16`/`x17` or a saved callee-saved register. `audit` rejects it.
- **Widening a stored value means patching every site of its pref key.** Declare
  them in `prefs_keys`; `find-refs` and `audit` re-derive them from the binary.
- **A native patch never stores the game's instructions.** Its site pin is
  `original_len` + `original_sha256` (`tools/sites.py`); only zero-padding caves
  keep plain zeros. A digest mismatch means the site moved: rebaseline and
  re-derive, do not edit the JSON by hand.
- **`UIBattleResultTeam.AddExp` is dead code** (zero call sites); the results
  screen applies EXP through `UITeamStateItem.<AddExp>c__Iterator3`. EXP is
  scaled at the `earnedExp` accumulator (`0xCEB5F4`), never by forcing a level:
  at the cap the next-level step is 1 EXP, so forcing 90 spins the results loop.
- **Option rows use the button's own atlas.** `UIIconBtn` only sets
  `UISprite.spriteName`, so a sprite from another atlas (`icon_c`, `icon_exp`
  in the status atlas) renders nothing - see `docs/options-rows.md`.
- **Dex code units are little-endian**: `return-void` is `0x000e` (bytes
  `0e 00`). `0e00` is a `nop` with a payload byte and ART rejects the class.
- **The startup WebView is AdMob's; the crash was the other one.** On the
  emulator, `MobileAds.initialize` / `getRewardedVideoAdInstance` pull GMS's
  "dynamite" module in and start Chromium ~15 ms later, and the original does the
  same; `patches/dex.json` neuters that path, so nothing touches GMS. Separately,
  the title screen opens the game's own in-app browser ("What's New"), and
  reaching it killed the process on Android 17 - that is what the `uniwebview`
  group's 60 stubs prevent (`tools/patchgen/gen_dex_uniwebview.py`). Do not
  confuse the two: one is a product decision, the other was the crash.
- **A DEX constructor cannot be neutralised with `return-void`.** The verifier
  requires every path to call `super.<init>`, so a constructor stub fails
  verification; only ordinary and static methods can be stubbed this way.
- **Android 16+ adds default interface methods** (`ServiceConnection`); Unity's
  JNI proxy throws `NoSuchMethodError` on them. `patches/smali.json` ignores
  default methods (gated on `SDK_INT >= 24`). Symptom: instant crash on 16/17
  only, never on the API 32 emulator.
- **Keep section headers when repairing a library.** Houdini's ARM64 translator
  refuses a library without them ("Unable to find main").
- **The smali step needs apktool 3.0.3** (`.tools/rea/bin`, `APKTOOL_JAR`
  overrides), pinned by SHA-256 in `patches/smali.json`; decoded trees are
  cached in `work/dex-cache/`.
- `il2cpp_meta.py` uses **signed** ints for the header (`0xFAB11BAF`); IL2CPP
  literal data has **no separators**; AXML values may be typed (`dataType 0x03`
  means a string-pool index).

## Reference

`docs/` holds the detail; `README.md` indexes it. Read `docs/native-guards.md`
before authoring or changing a cave.
