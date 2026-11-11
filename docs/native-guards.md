# Native cave guardrails

Lessons from the 3-state battle-speed patch (2x/3x/4x). Every failure in that
work fell into one of six classes, and each class now has a mechanical check or
a written rule. Read this before authoring or changing a `patches/native_*.json`
cave.

Related: `docs/native-mods.md` (what the patches do), `AGENTS.md` (hard rules),
`docs/verification.md` (the APK-level checks).

## The six failure classes

| # | Class | What actually happened | Cost |
|---|---|---|---|
| A | **Declaration drift** | A hook still branched to the relocated/emptied cave `0x20C8A00` after the cave moved to `0x20D3500`. | toggle behaved as before |
| B | **Unproven runtime state** | The label cave read standalone literal slots (`" / "`, `[ffffff]`, `[808080]`) that are not initialised when `UpdateBtn` runs; `Concat` dropped them. | row showed `x3x4` |
| C | **Emitted semantics** | `Concat(suffix, label.text)` instead of `(label.text, suffix)`. | `x4FastForward` |
| D | **Unguarded index arithmetic** | A second `[rrggbb]` tag was requested from a one-tag string: `IndexOf` returned `-1`, `Substring(-1,8)` threw. | crash on the 2nd click |
| E | **Register liveness** | The save cave reused `x8`, which still held the PlayerPrefs key slot for the code it returned to; `SetInt` got a `GameManager` object as the key. | crash on the 1st click |
| F | **Value-domain coverage** | The saved speed went 0/1 -> 0/1/2, but `InitBtn` still did `value == 1` on the same key. | 4x reverted on restart |

Classes A, D (partly), E and F are now build failures. B, C and the note-taking
side of D remain review rules.

## Mechanical checks (`pixi run audit`)

`tools/audit_patches.py` reads only `patches/native_*.json`, the reference
`libil2cpp.so` and `work/dump/script.json`:

- every patch entry `"hook": true` must branch to a cave **in the same set**;
- caves must be zero-filled in the reference and must not overlap another patch;
- a cave must not write a register declared in the hook's `"live"` list;
- no `x18`/`w18` anywhere in a cave;
- an unconditional `b` may only leave the cave to an address in the hook's
  `"targets"` list (so a typo cannot silently jump into the middle of the game);
- conditional branches must stay inside the cave;
- every `bl` must target an IL2CPP method entry, another cave in the set, or the
  runtime support region below `0xD00000`;
- a cave may only dereference a **string literal slot** the replaced method also
  loads, unless the slot is acknowledged in `"literal_risk"`;
- `prefs_keys` declares every reference to a widened pref key; the audit
  re-derives them from the binary and fails if the set drifts or a site is not
  patched.

`pixi run audit-selftest` runs ten negative fixtures and proves the audit still
rejects each class. `pixi run dist` runs the audit before packaging.

### Hook declaration fields

```json
{
  "offset": "0xE95DB0",
  "original": "62264139",
  "patch": "e4f54814",
  "hook": true,
  "live": "x8,x19",
  "targets": ["0xe95db4"],
  "literal_risk": ["0x2bd3118"],
  "note": "speed save -> live-state cave; x8 holds the prefs key slot"
}
```

- `live` - registers the continuation reads before writing them (normalise
  `wN` to `xN`).
- `targets` - every address the cave is allowed to branch to outside itself.
- `literal_risk` - literal slots the replaced method never loads, acknowledged
  as initialised by the time the cave runs.

## Authoring rules

1. **Hook at a basic-block boundary.** Prefer a point where the registers you
   clobber are dead. If you must hook mid-block, list every register the
   continuation uses in `live`.
2. **Site sheet before code.** For each hook record: original instruction(s),
   live-in registers, flags, stack delta, resume address. The payload of a cave
   is only correct relative to that contract.
3. **Consume only proven data.** No new global literals, no assumptions that a
   metadata-usage slot is initialised, no guesses about string contents. Reuse
   the values the replaced code already loaded, or acknowledge the risk.
4. **Guard every index.** Anything from `IndexOf`, a length field, or a list
   count must be bounds-checked; `Substring`/array access/`Concat` chains need
   explicit empty fallbacks.
5. **Copy the ABI from a real call site**, not from the signature. Disassemble
   one existing call to the callee and match `x0..x3` and the `methodInfo`
   slot.
6. **Replay, do not reimplement.** For paths you do not intend to change, branch
   back to the original instructions instead of rewriting them.
7. **Verify control flow with a decoder, not by eye.** Jump tables and `b.ne`
   targets in 2 KB functions are easy to misread.
8. **Widening a stored value is a cross-cutting change.** Find the key's
   metadata-usage slot, enumerate every reader and writer, patch each
   conversion, and declare them in `prefs_keys`.
9. **Adding state to a live field means scanning its readers** (for
   `moreFasterFastForward` at `[GameManager+0xA0]+0x20` there is exactly one:
   `GameManager.Update`).
10. **Keep the boolean fallback.** Multi-state caves should replay the original
    boolean behaviour for every other button type, so unrelated rows cannot
    regress.

## Triage tree

| Symptom | First hypothesis | Check |
|---|---|---|
| Crash on click | live-register clobber | disassemble hook +/-3, list registers the continuation reads, compare with the cave |
| Crash in text/UI | null literal slot or negative index | does the replaced method load that slot? are `IndexOf` results guarded? |
| Value not persisted | another reader of the pref key | scan the key slot for `adrp`+`ldr` |
| Persisted but wrong behaviour | a reader of the live field | scan the field offset on the owning class |
| Toggle loop / wrong label | stale hook target | `pixi run audit` |

## Verification matrix

Any persisted or stateful feature gets tested against:

1. fresh install (no prefs) -> default state;
2. upgrade from the previous build (old 0/1 values) -> still valid;
3. each state: select -> force-stop -> reopen -> label and behaviour match;
4. each state inside a battle with the toggle on and off;
5. all other toggle rows unchanged;
6. click from every state to every state (no crash loop).

Static analysis cannot answer 3-6; those need the phone. Everything else should
be caught before the APK is built.

## Why the audit exists

`build_patch.py` proves the bytes still match and `verify.py` proves nothing else
moved. Neither can see whether the injected code is *coherent*: a stale target, a
clobbered register, or a half-patched value domain all build and verify green.
That gap is what produced five of the six classes above.
