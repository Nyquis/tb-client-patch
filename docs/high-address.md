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

Next step: diff the two dex files method by method, not byte by byte. The
decoded trees are already produced by `pixi run unpack`; a method-level
comparison will show exactly which class differs, and that difference is what
belongs in `patches/smali.json` or `patches/dex.json`.

## What has been ruled out

- the patch set (original APK fails identically)
- the signing identity (four different signers produce the same fault)
- client data (wiped, same fault)
- the server build (the crash precedes any network call)
- all four soak variants
- `libil2cpp`, `libunity`, `libmain`, `classes.dex`, `AndroidManifest.xml` as
  the carrier of the fix

## What is left

The remaining untested variable is **packaging**: the comparison APK ships both
`arm64-v8a` and `armeabi-v7a`, is 86 MB, and lays its zip entries out
differently. That affects `extractNativeLibs`, the mapped file offsets, and
therefore where the loader places things at runtime.

The next experiment is the inverse of the grafts above: install the comparison
APK with *our* `libmain`/`libunity`/`libil2cpp` swapped in. If that still
boots, packaging or the ABI split is the variable; if it crashes, the earlier
grafts were measuring the wrong thing and the corpus needs re-reading.

No fix is claimed. Until this is resolved, the client is known-good on the
emulator and the S23 Ultra and known-bad on that S25.
