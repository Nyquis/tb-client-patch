# Changes kept without a device reproduction

Everything in `patches/` is reproduced by `verify`, but reproduction is not
evidence that a change *works*. This file lists the parts of the recipe that
were added on a hypothesis rather than on a measurement from the device that
fails, and what would retire each one.

The rule this file exists to enforce:

> A crash fix needs a fault frame or a local reproduction. A product change does
> not, but it must not be described as a fix.

## Ledger

| Patch | Why it is there | Evidence it has | How it retires |
|---|---|---|---|
| `patches/dex.json` group `ads` (MobileAds + reward-video surface) | Product: this client talks to a local server, so ads contribute nothing. Incidentally the only startup path that loads GMS's "dynamite" module into the game process and starts Chromium. | **Measured** on the emulator: with these rules, no `DynamiteModule`, no `WebViewFactory`, no Chromium, and no `com.google.android.gms` mapping in the process; the game still reaches its title screen. | Not retired - the product reason stands. It stops being a *crash* candidate once a fault frame exists (see `docs/high-address.md`). |
| `patches/smali.json` group `jnibridge` | Android 16+ adds a default method to `ServiceConnection`; Unity's `java.lang.reflect.Proxy` routes it to the C# side, which has no implementation, and the native bridge throws on the main thread. | **Corroborated from outside**: another preservation project documents the identical `bitter.jnibridge` / `onServiceConnected` crash on Android 16 and ships a mitigation. Their remedy differs from ours (they rewrite the bind so it never completes). Never reproduced on our own devices. | Retire the rule if a fault frame shows the proxy path is not involved, or replace it with the bind-removal approach if it is but the guard is insufficient. |
| `patches/dex.json` group `uniwebview` (60 of 61 methods) | Stops the game's in-app browser ("What's New", opened from the title screen) forming anything at all. | **Measured A/B on the affected phone**: with only `init` neutralised, opening that panel emitted Unity's "Using memoryadresses from more that 16GB of memory" and the process died by `SIGSEGV`; the comparison build, which stubs the whole class, opens the same panel empty and continues to the World Map. | Retired when the class-level stub reproduces that behaviour on the device; the rule then stands on measurement rather than on the comparison build. |
| 16 KB repair (`tools/elf16k.py`) | Android 15+ / 16 KB-page hardware cannot map `p_align = 0x1000` libraries at all. | **Verified** structurally (`verify`) and required by the platform; documented by other projects as *the* cause of instant launch failure on 16 KB hardware. | Not retired. Note it did **not** fix the Android 17 device, which is 4 KB-page, so it is necessary but not sufficient. |

## Single-variable builds

To test one change at a time instead of shipping a monolith, both the build and
the verifier take the same flag:

```sh
pixi run build  --without dex-ads          # ads rules omitted
pixi run verify --without dex-ads          # must be given the same value
```

Known targets: `dex-ads`, `dex-uniwebview`, `smali-jnibridge`, `16kb`. A build
made this way is a diagnostic artefact, not a release: `verify` prints
`experiment: ... (not a full verification)` and `pixi run dist` never passes the
flag.

Rules for using it:

1. One target per build, unless you are deliberately isolating a combination.
2. Install, observe, write the result down before the next build.
3. Decide with the decision rule recorded in `docs/high-address.md`, not after
   looking at the result.
