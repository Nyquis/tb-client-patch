# The Android 17 crash (resolved: the in-app browser panel)

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

All of 2-5 were reverted, and the last one was later removed from the recipe as
well. It was inert on the only device that fails, and unverified code that
rewrites a library is a diagnostic cost, not insurance: it makes every later
experiment harder to interpret.

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

- Client recipe: `0.2.3`, `verify`/`audit` green.
- The libil2cpp soak cave has been **removed** from the recipe, together with
  the `kind: "reloc"` audit exemption it needed. It was measured to execute and
  measured to change nothing on the affected device, so shipping it only
  rewrote a library for no benefit.
- No fix is claimed for the Android 17 crash. The device remains the only
  known-bad target; the emulator and the S23 Ultra run the same APK.

## Synthesis: the Java side is a perturbation, not a cause

> Superseded - see *The ads path* at the end. The measurements there explain the
> dex graft without invoking layout luck, and this section's "do not ship a dex
> change" conclusion does not apply to the ads transform.

Two facts look contradictory and are the key to the whole investigation:

- swapping `classes.dex` into this APK makes it boot on the device;
- the fault is native, inside `libil2cpp` init, before any Java code the game
  owns has run.

A dex cannot cause - or prevent - a segfault inside il2cpp init by its logic.
It can only do it by changing the process's **memory layout**: a different
class count changes verification work, heap and mapping order, and therefore
the addresses the runtime gets.

That single explanation covers every otherwise-inconsistent result: the
unmodified original crashing, the emulator and the S23 being fine, all four
soak variants being inert (they reserve address space but never move the
allocation that matters), the native grafts changing nothing (libraries do not
alter that allocation pattern) and the dex graft "fixing" it.

**Consequence: do not ship a dex change as the fix.** It is a coincidence that
moves the fault, and it will move again with any later dex edit - ours included.
The instability is the tell.

## What to do instead

1. Reproduce the fault where a backtrace is available (the emulator, with root).
   The forcing method tried here - `MAP_FIXED_NOREPLACE` blocks over 0..4 GB -
   did not reproduce it: the process booted with 860 `PROT_NONE` regions in
   place. The better method is to interpose the allocator's own `mmap` calls so
   its **requested sizes** are satisfied above 4 GB, rather than saturating
   fixed addresses it never asks for.
2. With a tombstone, take `pc - base`, resolve the offset through
   `script.json` (which already maps every IL2CPP method RVA) and read the
   faulting instruction. One frame is all that is missing.
3. Fix that instruction's 32-bit narrowing. The soak cave and the
   `kind: "reloc"` audit exemption it needed are already gone, so there is
   nothing left to unwind afterwards.

## The ads path: what the emulator settled

Two leads were pursued after the graft result and both are now **dead**. What
replaced them is the only startup code path that differs between the graft that
boots and this recipe.

### 1. "Our build creates a WebView at startup" - true, and not ours

Measured on the emulator (API 32, root) with a clean launch and no
instrumentation:

```
ours (all builds)   +2.37 s   WebViewFactory loads Chromium, :sandboxed_process0 starts
comparison dex      never
unmodified original +2.37 s   identical to ours
```

So the original does exactly the same thing: the WebView is **not** a product of
this patch set, and neutralising `UniWebViewInterface.init` neither creates nor
prevents it. The earlier read - "their dex stops a WebView that our patch
starts" - was wrong on both halves.

The creator is identified by a stack trace that AdMob prints itself, 15 ms
before the loader line:

```
+2.35 s  D/DynamitePackage  Instantiating ...ChimeraRewardedVideoAdCreatorImpl
+2.35 s  E/Ads  at com.google.android.gms.ads.MobileAds.getRewardedVideoAdInstance
+2.37 s  I/WebViewFactory  Loading com.android.webview ...
```

**AdMob creates the WebView**, first via `MobileAds.initialize` and then via
`getRewardedVideoAdInstance`, both of which enter the GMS "dynamite" singleton
`zzabc`. `UniWebView` never appears in the log at all.

A false start is worth recording: a `debuggerd -j` sampling loop left a Java
backtrace intercept armed, and the intercept held the process suspended so it
died with `SIGSEGV` at `0xdead1005`. That crash was the probe. Never treat a
suspend-based sampler as non-invasive, and check `tombstoned` for a non-matching
intercept before reading a fault.

### 2. The graft, re-read

The booting configuration is their `classes.dex` + manifest in our APK. The
manifest difference is a single `<activity AdActivity>` entry - our build already
removes `MobileAdsInitProvider`, so the manifest is not the carrier.

The dex difference is seven files, and `JNIBridge` is equivalent in both (both
call `Method.isDefault()`). What remains is: their build **guts every ads class**
(`MobileAds`, `MobileAdsInitProvider`, `Banner`, `Interstitial`,
`RewardBasedVideo`), ours leaves them live and only removes the provider.

That is not cosmetic. `MobileAdsInitProvider` is a ContentProvider, so with the
original manifest the ads SDK initialises *before the Application object exists*
- in the same few hundred milliseconds in which this device dies. Removing the
provider defers it, but the C# side still calls `MobileAds.initialize` and
`getRewardedVideoAdInstance` as soon as Unity comes up, so the same GMS code runs
in-process either way, just later.

This is also the first hypothesis that explains why two phones on the same
Android version behave differently: **the GMS ads module is updated per device**,
is loaded into the game's own process, and the S25 and S23 need not be running
the same build of it.

### 3. What changed in the recipe

`patches/dex.json` now makes the ads path inert - no GMS, no WebView, no network,
which is also what this recipe wants:

| Method | Becomes |
|---|---|
| `MobileAds.initialize(Context, String, Settings)` | `return-void` (the other overloads funnel here) |
| `RewardBasedVideo$1.run` | `return-void` - the call that actually reaches GMS |
| `RewardBasedVideo.{isLoaded,loadAd,show,destroy,setUserId,getMediationAdapterClassName}` | inert (`false` / null / no-op) |

The last row exists because `RewardBasedVideo$1.run` is the only thing that fills
the plugin's `RewardBasedVideo` field: with it neutralised, the plugin's own
methods would dereference null, so the whole surface is stubbed as a set. That is
the same outcome as the comparison build's class gutting, done through the
declared-rule mechanism so `verify` can reproduce it.

### 4. Measured effect (emulator, same launch probe)

```
before: DynamiteModule selected, MobileAds.initialize, WebViewFactory,
        cr_BrowserStartup, :sandboxed_process0
after : none of the above; 0 mappings matching com.google.android.gms
        in /proc/<pid>/maps, no libmonochrome
game  : process up, no Java exception, UnityIAP reached, title screen renders
```

### 5. What this does and does not claim

**What it claims, and has measured:** the ads SDK is gone from the process. On
the emulator the original pulls GMS's "dynamite" module in and starts Chromium
~15 ms later; this recipe does neither, and `/proc/<pid>/maps` holds no
`com.google.android.gms` or `libmonochrome` mapping. That is a wanted property
of a client that talks to a local server, and it holds whether or not the crash
moves.

**What it does not claim:** that this is the fix for the Android 17 fault. That
remains a hypothesis, and the emulator cannot settle it because it never
reproduces the fault. It stays listed in `docs/unverified.md` with its removal
condition until a fault frame from the affected device confirms or refutes it.

The decision rule was written down before the measurement, so the result cannot
be narrated afterwards:

| Frame `#00` in | Conclusion | Action |
|---|---|---|
| `libunity.so` | Unity's native GMS bind / `bitter.jnibridge` proxy path | patch the `com.google.android.gms.ads.identifier.service.START` string in the library (external reports name this exact string, and one team needed it after the dex-side fix already applied) |
| `libil2cpp.so` | the Java side is irrelevant | discard the ads theory; continue from the frame |
| `libmonochrome.so` or GMS code | WebView/ads after all | this recipe should already fix it; find what still creates one |
| `linker64` / `libc.so` | mapping or page-size problem | revisit 16 KB beyond `p_align` |

A frame is obtainable without root: Unity installs its own signal handler and
prints registers, `pc` and a `backtrace:` block to logcat, which is where the
register values in this document came from. `adb logcat -d` after one crash is
the whole measurement.

## The title-screen panel: the A/B that isolated it

A device experiment (Galaxy S25, Android 17, 4 KB pages) replaced the earlier
picture with a much simpler one. Two builds were run identically: launch, wait
for the title screen, one injected tap, no other input.

| | comparison build (their dex) | this recipe 0.2.3 |
|---|---|---|
| launch | title screen | title screen |
| tap | "What's New" panel opens, black | `E Unity: Using memoryadresses from more that 16GB of memory` |
| then | close -> World Map, playable | `SIGSEGV` milliseconds later |
| message in the run | absent | present |

Both builds had the ads path removed and both reached the title screen, so the
ads path, GMS, and startup are all ruled out as the trigger. The one difference
left is the plugin: the comparison build stubs **every** `UniWebViewInterface`
method, while 0.2.3 stubbed only `init`, leaving 60 entry points able to run
their real bodies against a dialog that was never created.

That is the crash: the title screen opens the game's in-app browser, and a
half-initialised plugin faults inside the native WebView stack. Unity's
">16GB of memory" line is a symptom of what that path allocates, not the cause -
the string lives in `libunity.so` at file offset `0xad5978`, and no device that
does not open the panel ever prints it.

A caveat worth keeping: in the first pass the phone was minimised during the
tap, so the segfault could not be attributed cleanly. The table above is from a
rerun with the panel opened and closed deliberately.

### What changed

`patches/dex.json`'s `uniwebview` group went from 1 rule to 60, generated by
`tools/patchgen/gen_dex_uniwebview.py`, which picks the constant return from
each descriptor (`V`, 32-bit, wide, object). The constructor is skipped, because
the verifier requires it to call `super` - a stub there is a `VerifyError`, not a
neutralised method.

### Verified on the device (0.2.4)

The stub was built, installed and run on the affected phone with an injected tap
and no other input:

```
launch -> title screen -> tap -> "What's New" panel, black -> close -> World Map
process alive throughout; account and save intact
"Using memoryadresses" lines: 0
WebViewFactory / Chromium:   none
```

For contrast, the 0.2.3 run of the same sequence loaded WebView at `18:46:23`,
printed the message at `18:46:32.148` and died at `18:46:32.654`. So the panel
path is the crash, the class-level stub is what prevents it, and the failure
never was an `il2cpp` init problem.

The crash section is therefore closed. What remains in this document is the
record of the wrong turns, which is worth keeping: each one cost days and each
one is a predictable trap.

