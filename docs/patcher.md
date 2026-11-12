# Patcher internals

What `pixi run build` does to the input APK, in order. Patch data lives in
`patches/`; the code is under `tools/`.

## 1. Endpoints

`patches/endpoints.json` rewrites 12 IL2CPP string literals to
`http://127.0.0.1:8080/...` (API, `gdresources` assets, license page and six
support pages). IL2CPP v24 stores literals as an 8-byte `(length, dataIndex)`
table over one packed blob, so a shorter replacement must also rewrite the
length entry - `tools/il2cpp_meta.py` does both.

## 2. Manifest removals

`patches/endpoints.json` lists the elements dropped from the binary manifest
(`tools/axml.py`):

- `<provider android:name="...MobileAdsInitProvider">` - the Google Mobile Ads
  init provider, useless offline and runs at process start;
- `<activity android:name="com.google.android.gms.ads.AdActivity">` - the only ad
  UI the SDK can launch. Without it no ad can put its WebView in front of the
  game. `com.google.android.gms.ads.APPLICATION_ID` is kept: the SDK reads it if
  the game's rewarded-video path ever initialises, and a missing id throws
  instead of failing gracefully.

## 3. classes.dex

Two ordered transforms (`tools/dex_transform.py` keeps them in one place so the
build and `verify` cannot drift):

1. **Smali** — `patches/smali.json` + `tools/dex_smali_patch.py`. The dex is
   decoded with the pinned apktool, the snippets are inserted at the start of
   the named methods, and it is reassembled:

   - `bitter.jnibridge.JNIBridge$a.invoke`: ignore *default* interface methods
     (`Method.isDefault()`, guarded by `SDK_INT >= 24`). Android 16 added
     `ServiceConnection.onServiceConnected(.., IBinderSession)` as a default
     method; Unity's proxy forwards it to C#, which has no implementation, and
     the native bridge throws `NoSuchMethodError` on the main thread when the
     billing service connects — an instant crash on Android 16/17 only.

   This needs extra instructions, so it cannot be a byte patch (the method has
   no spare code units). The apktool jar is referenced, not vendored, and its
   SHA-256 is pinned in `patches/smali.json`.

2. **Byte rules** — `patches/dex.json` + `tools/dex_patch.py`:

   - `UniWebViewInterface.init` becomes `return-void`, so the game's WebView is
     never created while the plugin classes stay for the C# JNI lookups.
   - the **ads path** is made inert: `MobileAds.initialize(..)` and
     `RewardBasedVideo$1.run` become `return-void`, and `RewardBasedVideo`'s
     `isLoaded`/`loadAd`/`show`/`destroy`/`setUserId`/
     `getMediationAdapterClassName` become constants. With the provider already
     gone from the manifest, this is what keeps GMS out of the process: measured
     on the emulator, the original pulls the ads "dynamite" module in and starts
     Chromium ~15 ms later, and this recipe does neither. The whole reward-video
     surface is stubbed because `RewardBasedVideo$1.run` is the only thing that
     fills its field - leaving the rest live would trade an SDK call for a
     `NullPointerException`.
   - **every** method of `UniWebViewInterface` becomes a constant return (60 of
     61; the constructor is skipped because the verifier requires it to call
     `super`). That is the game's in-app browser, which the title screen opens
     as the "What's New" panel, and reaching it on a modern device faults in the
     native WebView stack. `tools/patchgen/gen_dex_uniwebview.py` derives the
     rules from the dex and picks the return kind from the descriptor (`V`,
     32-bit, wide, object) so the class still verifies.

## 4. 16 KB repair

`tools/elf16k.py` derives 16 KB-compatible arm64 libraries from the original:

- `libunity.so` already has its load segments in separate 16 KB pages, so only
  `p_align` changes;
- `libmain.so` has two `PT_LOAD`s inside the first 16 KB page, so the second one
  moves to `0x4000` and everything that points at it follows: `p_offset`,
  `PT_DYNAMIC`, the dynamic pointer tags, relocations, dynamic symbols and the
  `ADRP` page of the `.plt` stubs. Section headers are rewritten, never dropped
  (Houdini refuses a library without them).

`libil2cpp.so`/`libgpg.so` are already `0x10000`-aligned; `verify` prints
`alignment only` for them.

## 5. Native byte patches

`patches/native_*.json` hold ARM64 byte patches and their cave code. Each site
records the length and SHA-256 of the bytes it expects to find (`sites.guard`),
never the instruction itself; the build refuses to write if a site no longer
matches. Caves live in zero padding and keep a plain zero `original`.

## 6. Repack / align / sign

Entries keep their original order and compression; `zipalign -P 16` then
`apksigner` with `keys/tb-client.keystore`.

The APK is **arm64-only by default** (drops `lib/armeabi-v7a/`, ~66 MB instead
of ~83 MB); pass `--with-armv7` to keep the 32-bit libraries.

## dist layout

`pixi run build` writes `dist/TerraBattle-5.5.7-170-patched.apk` (plus `.idsig`).
`pixi run dist` builds, verifies, then copies the APK into `dist/release/` with
`SHA256SUMS.txt` and `NOTES.md`. Ad-hoc builds (`--probe`, `--out ...`) stay in
`dist/`. Both directories are gitignored.
