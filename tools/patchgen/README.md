# patchgen — cave authoring tools

These scripts *emit* `patches/native_*.json`. The JSON is what `build_patch.py`
consumes; the scripts are the readable source of the cave code (ARM64 assembled
with small helpers and self-checked with capstone).

| Generator | Writes |
|---|---|
| `gen_audio_patch.py` | `native_audio.json` — attack-SE pool leak fix |
| `gen_drop_rate_patch.py` | `native_droprate.json`, and regenerates `native_kill_label.json` |
| `gen_killstart_patch.py` | `native_killstart.json` — Auto Play enemy-turn sweep |
| `gen_options_patch.py` | `native_options.json` — Auto Play Options row |
| `gen_probe_patch.py` | `native_probe.json` — disabled diagnostic probe |
| `gen_speed_label_patch.py` | `native_speed.json` — 3-state battle speed |
| `gen_time_patch.py` | `native_time.json` — time / HP / one-hit toggles and caves |

## Rule: the generator is the source, the JSON is the artefact

Change a cave by editing its generator, then regenerate and review the JSON
diff. **Never hand-edit the hex in `patches/native_*.json`** — that is how the
committed JSONs previously drifted from the generators (hooks carried
`hook`/`targets` that no generator emitted).

`hooks.annotate(spec)` is called by every generator before it writes: for a
4-byte patch that branches into a cave declared in the same file it adds
`"hook": true` and derives `targets` from that cave's branch exits. Authored
declarations are never overwritten.

`sites.guard(original_bytes)` produces the site pin: a digest
(`original_len` + `original_sha256`) for real code, plain zeros for cave
padding. The generators never store the original instruction bytes, so the
repository carries no game code.

## Prerequisites

- `work/il2cpp/libil2cpp.so` — the extracted original, used for the generators'
  self-checks and for the `hook`/`targets` derivation. Create it with
  `pixi run unpack`.
- `capstone` (already in `pixi.toml`).

## Run

```sh
pixi run unpack                                    # once per input APK
pixi run python tools/patchgen/gen_time_patch.py   # one family
```

All of them:

```sh
for g in tools/patchgen/gen_*.py; do pixi run python "$g"; done
```

## Acceptance

After regenerating, `git diff patches/` must be **empty**. Anything else is
either a deliberate change (commit it together with the generator edit) or
drift that has to be fixed in the generator, not in the JSON.
