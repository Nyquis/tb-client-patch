# The Android 17 startup crash (unresolved)

A Galaxy S25 (`SM-S931B`, Android 17 / SDK 37, 4 KB pages) kills the client
about 60 ms after `libil2cpp.so` is loaded:

```
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x1fb14 / 0x46227
x0 = 0, x25 = 0x1faf4, fault = x25 + 0x20
x6/x11/x17 identical across runs; pc differs only by ASLR
```

**The unmodified original APK crashes the same way**, at the same point, on the
same device. The client patch is therefore not the cause, and no repack of ours
can be the fix on its own.

The emulator (API 32) and an S23 Ultra never reproduce it.

This document records every attempt, including the ones that failed, so the
next person does not repeat them.

## What was tried, and why each failed

### 1. Hook the EXP/coin code early — not applicable

`UIBattleResultTeam.AddExp` has zero call sites (dead code) and the rate caves
only run in battle. None of them is reachable before the title screen, which is
where the crash happens.

### 2. High-address soak at `il2cpp_init`

Rationale: the fault looks like a pointer whose high half was discarded, so
keeping every allocation below 4 GB should make the truncated value valid
again. A cave retargeted `DT_INIT_ARRAY[0]` of `libil2cpp` (`0x913f1c`) to a
loop that reserves high VA in 1 GiB / 64 MiB / 2 MiB / 64 KiB tiers with
`PROT_NONE|MAP_NORESERVE` and keeps the reservations.

Verified to *run*: with the above-4 GB test disabled, the emulator process
gained 856 `PROT_NONE` regions, so the retarget, the cave and the raw
`mmap`/`munmap` syscalls all work under ARM translation.

Result: **no change on the affected device.** The soak is inert there.

### 3. Soak one library earlier: `libunity`

Reasoning: if the truncation is decided before `libil2cpp` is `dlopen`ed, the
soak has to be earlier. `libunity` has 2,616 init-array entries; entry 0
(`0x8d4dc`, relocation addend at file offset `0x16d70`) is the earliest code we
can reach without a new binary. Same cave, retargeted there.

Result: **no change.**

### 4. Tier caps were too small

Tier 1 was capped at 512 × 1 GiB. A 39-bit layout hands back addresses above
4 GB for roughly five hundred rounds, so the loop hit the cap and ended without
ever seeing a sub-4 GB address — the soak silently did nothing. Caps raised to
the largest value the 12-bit compare allows (4095).

Result: **no change.**

### 5. `RLIMIT_AS`

A finite soft address-space limit makes every `mmap` fail with `EAGAIN`, which
the tiers interpret as "no more VA". The cave now does
`getrlimit(RLIMIT_AS)` → raise a finite soft limit to the hard limit →
`setrlimit`.

Result: **no change.** (This also exposed a real encoding bug: `mov x1, sp` is
not expressible as `MOV` — `ORR` cannot name `SP` — and assembled to
`mov x1, xzr`, passing a null buffer.)

All of 2–5 were reverted; the shipped recipe keeps only the `libil2cpp` soak,
which is harmless and may help a different, later truncation.

## Comparison against a build that does boot

A 64-bit repack known to boot on the affected hardware was used **only as a
local comparison artifact**; no part of it is in this repository, and nothing
here is derived from it.

Findings:

| Component | Comparison | Grafted into our APK, result |
|---|---|---|
| high-address shim (`.so`) | present there, deleted in a test build | that test build **boots** — the shim is not what makes it work |
| `libunity.so` | `.dynamic` moved into its own segment (`off 0xdc0000 / va 0xeb0000 / align 0x10000`); ≈12 MB of code byte-identical | **crashes** |
| `libmain.so` | 7,232 vs 7,064 bytes, 1,359 changed words | **crashes** |
| `libil2cpp.so` | byte-identical to the original | n/a |
| `classes.dex` + `AndroidManifest.xml` | 6,452,888 vs 6,446,520 bytes | **boots** - see below |
| `resources.arsc` | identical | n/a |

So the difference is **not** in the game's code, not in the high-address shim,
not in `libunity`'s relayout, not in `libmain` - but it **is** in the Java side:
swapping `classes.dex` and `AndroidManifest.xml` into our APK makes it boot on
the affected device.

That is the one result that overturns the earlier reasoning. Everything native
was a dead end; the carrier is the dex (or the manifest, which differs too, but
`hardwareAccelerated`, the activity names and the usual layout flags compare
equal, and `extractNativeLibs` is absent from both). A dex change that alters
what runs before Unity initialises can change the process's address layout
without touching a byte of game code.

### Diffing the two dex files without decoding them

A byte diff of two dex files is useless: constant pools and offsets shift, so
every subsequent byte differs. What works is comparing the **string tables**,
which are the vocabulary of the compiled code. Parsing the header by hand
(`string_ids_size` at `0x38`, `string_ids_off` at `0x3C`, then uleb128 length +
MUTF-8) is about twenty lines and needs no toolchain:

```python
ours, theirs = strings("classes.dex"), strings("comparison classes.dex")
theirs - ours    # added vocabulary
ours - theirs    # removed vocabulary
```

Result on this pair:

| Direction | Count | Contents |
|---|---|---|
| added by the comparison build | **1** | `isDefault` |
| removed by it | **65** | the `UniWebView` plugin's classes and methods |

`isDefault` looked like a smoking gun and is not: `Method.isDefault()` is
already in our own JNIBridge guard (`patches/smali.json`), so the "addition" is
only an artefact of diffing against the *original* dex rather than against our
patched one. The genuine difference is the **65 removed UniWebView strings**:
that build deletes the plugin's classes outright, while this recipe neutralises
`UniWebViewInterface.init` and keeps the classes so that C# JNI lookups still
resolve.

That is the current leading hypothesis: a plugin kept-but-inert, whose C# side
still performs JNI lookups, faulting inside the proxy on Android 17.

### A wrong turn worth recording

Reading that `isDefault` string as new evidence, the SMALI guard was re-read and
the branch was taken to be inverted:

```
if-ge v0, v1, :jnibridge_sdk_ok     # v0 = SDK_INT, v1 = 24
```

`if-ge` jumps when `v0 >= v1`, so the guard *was* correct - `isDefault()` runs on
SDK 24+ and is skipped below. It was changed to `if-lt`, which does the exact
opposite, shipped as 0.2.2, and crashed on the affected device. Reverted in
`795e754`; the build returned to `fce65429`.

The lesson is narrow and mechanical: `if-ge`/`if-lt` are easy to read backwards
when the label names the *good* path. Before changing a branch, disassemble the
built method and read the control flow, do not read the source text.

## What has been ruled out

- the patch set (original APK fails identically)
- the signing identity (four different signers produce the same fault)
- client data (wiped, same fault)
- the server build (the crash precedes any network call)
- all four soak variants
- `libil2cpp`, `libunity`, `libmain` and the shim as the carrier of the fix
- the JNIBridge guard's *logic* - it is correct; see the wrong turn above

Still open: whether the dex half or the manifest half of that graft carries the
fix. The graft replaced both, and the manifest differs by 140 bytes with no
obvious flag change.

## What is left

The remaining untested variable is **packaging**: the comparison APK ships both
`arm64-v8a` and `armeabi-v7a`, is 86 MB, and lays its zip entries out
differently. That affects `extractNativeLibs`, the mapped file offsets, and
therefore where the loader places things at runtime.

Two experiments, in order:

1. **Split the successful graft**: their `classes.dex` alone (keeping our
   manifest), then their manifest alone. One install each, and it says which
   half matters.
2. **If it is the dex**: delete the UniWebView classes rather than neutralising
   `init`. That is a structural dex transform, not a byte rule, and `verify`
   will need to reproduce the class removal honestly.

The second experiment, if the first is inconclusive, is the inverse graft:
install the comparison APK with *our* `libmain`/`libunity`/`libil2cpp` swapped
in. If that still boots, packaging or the ABI split is the variable; if it
crashes, the earlier
grafts were measuring the wrong thing and the corpus needs re-reading.

No fix is claimed. Until this is resolved, the client is known-good on the
emulator and the S23 Ultra and known-bad on that S25.

## Method notes, so the next attempt costs hours instead of days

1. **Prove the layer before fixing inside it.** When a symptom lands in a layer
   that has already been patched, the first question is whether *that* patch
   executes - not what is wrong beneath it. A branch that never runs is
   indistinguishable from a layer that cannot be fixed.
2. **When the original fails too, start with a graft.** Swapping components
   between a build that boots and one that does not costs one install per
   component and settles the layer question immediately. It was done last here,
   after several days.
3. **Diff vocabularies, not bytes.** For dex, string-table set difference. For
   a native library, word diffs grouped by MiB, which separates relayout noise
   (dense, confined to headers/relocations) from real code changes (sparse).
   That is how `libunity` was shown to be byte-identical in its 12 MB of code
   and how `libil2cpp` was eliminated in one command.
4. **Distrust a plausible mechanism that has no test.** Each soak variant was
   locally coherent and none of them was observable on the target device. The
   soak that "worked" was measured on the emulator, where the bug does not
   exist - a test that could not fail.
5. **Record the failures while they are fresh.** Four of the five hypotheses in
   this document were written down within minutes of being disproved; without
   that, the same ground gets re-covered (it already was, twice).

## Status

- Client recipe: `0.2.1`, `fce65429...`, `verify`/`audit` green.
- The one libil2cpp soak cave remains in the recipe; it is inert on the
  affected device and harmless elsewhere. It should be deleted once the real
  cause is fixed.
- No fix is claimed for the Android 17 crash. The device remains the only
  known-bad target; the emulator and the S23 Ultra run the same APK.
