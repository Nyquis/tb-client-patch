# tb-client-patch

Turns your own Terra Battle **5.5.7 (170)** APK into a client that talks to a
**reTB** server at `127.0.0.1:8080` (reTB Host on the phone, or reTB on a PC).
Patch recipe only - no game files are stored in this repository.

```sh
pixi run unpack    # extract work/il2cpp/* from your APK (once per APK)
pixi run doctor    # validate inputs, toolchain, apktool pin, signing key, patch data
pixi run keycheck  # the keystore is the identity pinned in patches/signing.json
pixi run build     # -> dist/TerraBattle-5.5.7-170-patched.apk (arm64-only)
pixi run verify    # must print PASS (original APK in, every difference declared)
pixi run dist      # build + verify + dist/release/ (APK, SHA256SUMS, NOTES)
pixi run audit     # structural check of the declared caves (hooks, live regs, x18)
pixi run audit-selftest  # negative fixtures; the audit must reject each defect class
pixi run rebaseline --original input/new.apk   # check the recipe against another build
pixi run install   # adb install -r
```

## What it changes

- 12 endpoint literals rewritten to `http://127.0.0.1:8080` (API, assets,
  license and support pages) - see `patches/endpoints.json`
- Google Mobile Ads: init provider and `AdActivity` removed from the manifest
  (the provider's WebView traps at the splash on current WebView builds)
- UniWebView disabled: the plugin no longer creates a dialog/WebView - see
  `patches/dex.json`
- Unity's JNI proxy taught to ignore Android 16+ default interface methods,
  which otherwise kill the game when billing connects - see `patches/smali.json`
- 16 KB page-compatible `libmain.so`/`libunity.so`, derived from the original
- the modal "IAP error" dialog is skipped (`patches/native_iap.json`)
- three battle-rate rows in Options - Drop Rate, Coin Rate, EXP Rate - each
  x1 / mid / max, applied while the battle is scored - see
  `docs/options-rows.md` and `patches/native_rates.json`
- repacked, `zipalign -P 16`, signed with the local key in `keys/`

The signing identity is pinned in `patches/signing.json` and enforced by both
`build` and `verify`, so a rebuild can never silently change it.

Everything else is byte-identical to the original APK.

## Requirements

- `input/terra-battle-5.5.7-170-original.apk` (your own copy)
- pixi (Python 3.13 + JDK 21 come from `pixi.toml`; SDK tools from `.android-sdk/`)
- **apktool 3.0.3** for the smali step: referenced from the workspace
  (`.tools/rea/bin/apktool_3.0.3.jar`), or point `APKTOOL_JAR` at a copy. Its
  SHA-256 is pinned in `patches/smali.json` and checked by `pixi run doctor`.

That is the only game input. There is no reference APK, no stored delta and no
injected third-party binary: every transform is our own code applied to your
APK. `input/`, `dist/`, `work/` and `keys/` are gitignored, so game binaries and
signing material never enter the repository.

The signing key is **yours to keep**: `keys/` is gitignored, the password lives
in `keys/keystore.pass` or `TB_KEY_PASS`, and `pixi run keycheck` proves a
restored key is the pinned identity. See `docs/signing.md`.

### Toolchain

Nothing bulky is committed; all of it is re-obtainable:

| Need | How |
|---|---|
| Python 3.13, JDK 21, `keytool`, `capstone`, `UnityPy` | `pixi install` (pinned by `pixi.lock`) |
| Android build-tools 35.0.0 (`zipalign`, `apksigner`, `aapt2`) | unzip the SDK build-tools into `.android-sdk/build-tools/35.0.0`, or point `TB_BUILD_TOOLS` at an existing copy |
| `adb` (install only) | SDK platform-tools in `.android-sdk/platform-tools`, or set `TB_ADB` |
| apktool 3.0.3 (smali step) | set `APKTOOL_JAR` to your jar; digest is pinned in `patches/smali.json` |

`pixi run doctor` names whichever piece is missing.


## Status

Endpoint patch, signing and the battle-speed option are implemented:

- **16 KB**: `libmain.so`/`libunity.so` are repaired in place from the
  original APK (`tools/elf16k.py`): `p_align` is raised and `libmain`'s second
  load segment moves to its own page, with every pointer and `ADRP` that reaches
  it fixed up. No injected library, no shim. Verified on a 4 KB device; the
  16 KB path itself still needs a 16 KB Android image to test.
- **WebView / ads**: UniWebView is disabled (no dialog, no `WebView` instance);
  the ads init provider and `AdActivity` are gone, so no ad can render. The ad
  SDK still initialises lazily when the game asks for a rewarded video, and that
  request fails offline exactly as it did before.
- **Speed**: the options speed row cycles the FF multiplier 2x -> 3x -> 4x and
  shows all three values with the active one highlighted; the in-battle FF
  button still toggles FF on and off. The click also applies the new speed
  immediately. Only the speed row gets the 3-state cycle; other toggles keep
  0/1.
- **Story skip**: the Skip button is always shown in chapter stories and
  in-battle stories, including the first viewing. The story archive is not
  covered.
- **Battle labels**: the repurposed in-battle row reads `1-Hit` (one-hit kill)
  and `Stop` (while Auto Play is on) instead of the Kamcord strings.
- **Drop Rate**: the Support button cycles `Drop Rate x1 / x5 / Max` (item drop
  chance ×1 / ×5 / guaranteed), persists it, and shows a treasure-chest icon.
- **Trash clear**: *Auto Play* (Options > Auto, repurposed Help row, set before
  battle) clears visible non-boss enemies at each enemy turn and keeps one-hit
  on so bosses still die in one hit. Moving never kills anything: the in-battle
  `1-Hit` toggle only affects damage, so an enemy dies when you pincer or
  damage it. The Options row is deliberately kept as a plain (non-toggle) row,
  re-paints itself from the saved state when it is built, and uses the
  crossed-swords `icon_battle`. See `docs/native-mods.md`.
- **Attack SE fix**: Master Audio sound objects are no longer stranded by a
  stale `_applicationPaused` flag after the app is minimised and resumed, so
  attack/spell sounds keep playing instead of dying until a restart. BGM was
  already unaffected (separate player). See `docs/native-mods.md`.

## Legal

- The Apache License 2.0 in `LICENSE` covers **this repository only**: the
  patcher, its tools and its patch data. See `NOTICE`.
- Terra Battle and its assets are Copyright Mistwalker. They are **not**
  included and **not** licensed here. You must own the APK you patch, and no
  patched client may be redistributed. There is no affiliation with Mistwalker.
- The patch data contains no game code: each of the 67 native patch sites
  records an offset and a SHA-256 digest of the bytes it expects to find
  (39 sites), or a zero run for cave padding (28 sites), and the values a
  patch writes are this project's own instructions. Assets, metadata and native
  libraries are read from your APK at build time and never stored here.
- Nothing in the repository phones home, and the build never uses the network.

## Documentation

- `docs/patcher.md` - endpoint rewrites, manifest removals, dex + smali rules, 16 KB repair, repack/align/sign
- `docs/options-rows.md` - the Drop / Coin / EXP rate rows: state bits, apply sites, dead ends
- `docs/signing.md` - the signing identity: pin, backup, restore, `keycheck`
- `docs/native-mods.md` - battle speed, time/invincibility/one-hit, trash-clear, audio fix
- `docs/native-guards.md` - cave failure classes, `audit` checks, authoring rules, triage tree
- `docs/apk-internals.md` - artifact hashes, ELF layout, literal slots, class map, audio/reward systems
- `docs/rewards.md` - client EXP/coin math, server boost, results-screen mismatch
- `docs/verification.md` - what `verify` proves, 16 KB repair, in-place dex rules
- `docs/investigation.md` - Il2CppDumper workflow, options UI, anti-cheat audit
- `docs/new-toggle.md` - recipe for a new in-game toggle
