# Verification internals

`pixi run verify` must print `PASS`. The original APK is the only oracle: there
is no reference/known-good APK and no stored delta.

## Assertions

For every entry in the built APK:

- if no transform declares it, its bytes must be **identical to the original**;
- if a transform declares it, that transform is **re-run from the original** and
  its output must match the built entry byte for byte.

The declared transforms:

| Entry | Proof |
|---|---|
| `assets/.../global-metadata.dat` | re-applying the `metadata_literals` of `patches/endpoints.json` reproduces it |
| `AndroidManifest.xml` | the declared `manifest_removals` are the only change (size shrinks by exactly those elements) |
| `classes.dex` | the smali inserts (`patches/smali.json`) plus the byte rules (`patches/dex.json`) re-applied to the original dex reproduce it |
| `lib/arm64-v8a/*.so` | the 16 KB repair of `tools/elf16k.py` (plus `patches/native_*.json` byte patches) reproduces it |

Each native patch site is pinned by a SHA-256 digest of its original content
(`original_len` + `original_sha256`; zero-padding caves keep plain zeros), so
the recipe never stores the game's instructions. A digest mismatch means the
site moved - rerun `pixi run rebaseline` against the new APK and re-derive it.

`elf16k.explain` additionally classifies every changed word inside a repaired
library. Anything that is not a program header, a dynamic table entry, a
relocation, a dynamic symbol or a verified `ADRP` page move fails the build and
the verify run - so a repair cannot quietly rewrite code.

Then the structural checks:

- every arm64 `PT_LOAD` has `p_align >= 0x4000`, `p_offset` congruent to
  `p_vaddr` modulo 0x4000, and no two segments share a 16 KB page;
- `zipalign -c -P 16` passes (shared libraries are 16 KB aligned in the zip);
- the APK is v2-signed by the pinned identity in `patches/signing.json`.

## Why there is no injected payload

The previously shipped build used BSDIFF deltas from a third-party
"known-good" APK to obtain 16 KB `libmain.so`/`libunity.so`, a
`libhighaddressfix.so` shim and a rebuilt `classes.dex`. All of it is gone:

- the 16 KB repair is derived from the user's own libraries (`tools/elf16k.py`);
- the high-address shim is ours: `tools/patchgen/gen_tbfix_patch.py` emits a
  soak cave (`patches/native_tbfix.json`) that `DT_INIT_ARRAY[0]` is retargeted
  to. It reserves high VA in 1 GiB / 64 MiB / 2 MiB / 64 KiB tiers until the
  kernel hands out sub-4 GB addresses, which keeps the game's 32-bit pointer
  truncation harmless. See `docs/options-rows.md` for the rows and
  `patches/native_tbfix.json` for the mechanism; the addend edit is declared
  `kind: "reloc"` because it rewrites live relocation data, not padding;
- the WebView/ads changes are our own declarative rules in `patches/dex.json`.

## In-place dex edits

Two kinds of dex transform, both derived from the original APK:

- **Byte rules** (`tools/dex_patch.py`) locate a method's `code_item`, overwrite
  the first code units and pad the rest with `nop`. The instruction count is
  unchanged, so nothing else in the file moves; only the header SHA-1 signature
  and adler32 checksum are recomputed.
- **Smali inserts** (`tools/dex_smali_patch.py`) are used when a fix needs
  *more* instructions than the method has room for. The dex is decoded with the
  pinned apktool 3.0.3, the snippet is inserted at the start of the method, and
  the dex is reassembled. Currently one rule: ignore default interface methods
  in `JNIBridge$a.invoke` (Android 16+). The jar is referenced from the
  workspace and pinned by SHA-256 in `patches/smali.json`; `pixi run doctor`
  checks it and the decoded tree is cached by input hash.

Both are deterministic — a cold rebuild reproduces the same APK hash.

Two traps, both hit while building this:

- **Code units are little-endian.** `return-void` is the code unit `0x000e`,
  written as the bytes `0e 00`. Writing `0e00` produces `nop` with a non-zero
  high byte, which ART rejects with "encountered data table in instruction
  stream".
- **Section headers must survive the 16 KB repair.** Houdini's ARM64 translator
  (used by x86 emulators) refuses a library whose section table was stripped:
  `System.loadLibrary("main")` fails and the game dies with "Unable to find
  main". `elf16k` therefore rewrites the section table instead of dropping it.
