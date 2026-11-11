# APK internals

Reference map of the shipped Terra Battle **5.5.7 (170)** artifacts and the
subsystems the patches touch. Names and offsets are from `work/dump/`
(Il2CppDumper) unless stated otherwise. Read this before changing a patch
family.

## Artifact identity

| Artifact | SHA-256 |
|---|---|
| `input/terra-battle-5.5.7-170-original.apk` | `f2c0ffa188255f4694f0f60e898a58b372c2cc3fff7dd312a01d593189bd7a15` |
| `lib/arm64-v8a/libil2cpp.so` | `ba6fecba562f7ff46305792cadeabcae1879a0c384f7195a5d77872af04c1753` |
| `assets/bin/Data/Managed/Metadata/global-metadata.dat` | `6544fdf0f23a244a00c0c8995897bc30883072306d17362446ae385952c5c07e` |

- Unity 2017.4 (data folder `data_u2017`), IL2CPP metadata **version 24**.
- `libil2cpp.so` is stripped (no `.symtab`); names come from Il2CppDumper.
- 9,717 managed string literals; `verify` compares their meaning, not filler
  bytes (`docs/verification.md`).

### ELF layout (matters for cave placement)

`libil2cpp.so` is 45,595,296 bytes. Its two `PT_LOAD` segments are:

| Segment | `p_offset` | `p_vaddr` | `p_filesz` | `p_memsz` |
|---|---|---|---|---|
| RX | `0x0` | `0x0` | `0x281389c` | `0x281389c` |
| RW | `0x28138a0` | `0x28238a0` | `0x367a08` | `0x454550` |

Code RVAs in the first segment equal file offsets. The second segment has a
`0x10000` offset delta, and VAs past `0x2B8B2A8` are **bss** (not file-backed),
which is where the string-literal usage slots live. Verify a padding run is
zero before placing a cave; `verify` rejects any undeclared byte.

## Workspace

| Path | What |
|---|---|
| `work/il2cpp/libil2cpp.so` | arm64 binary analysed by all generators |
| `work/il2cpp/global-metadata.dat` | metadata version 24 |
| `work/dump/dump.cs` | class/field/method dump (names + RVAs) |
| `work/dump/script.json` | `ScriptMethod` addresses, `ScriptString`, metadata |
| `work/dump/stringliteral.json` | `{value, address}` for the 9,717 literals |

Analysis tools used so far: Il2CppDumper (names/RVAs), capstone (disassembly
and ADRP/LDR resolution), UnityPy (Unity assets), and rizin/objdump. REA is
connected but its deep native provider (Ghidra) is **not installed** and
`inspect_il2cpp_metadata` rejects this header (`stringLiterals starts at 272,
not immediately after the 264-byte header`), so use the local dumps for now.

## Literal access (why some addresses work in caves)

At runtime an IL2CPP string literal is a usage slot holding an
`Il2CppString*`. A cave can load a known slot directly:

```asm
adrp x8, #0x2be0000
ldr  x8, [x8, #0x5c8]   ; usage slot -> Il2CppString*
```

`stringliteral.json` addresses are those slots (e.g. `icon_battle` ->
`0x2BE05C8`). An ADRP scan can miss indirect readers (for example loads through
a usage base), so treat "no direct reference found" as an open lead, not as
proof a literal is unused.

## Class map (verified from `work/dump/`)

| Class | TypeDefIndex | Why it matters |
|---|---|---|
| `GameManager` | 4121 | global state, `battleManager` +0x68, `isPaused`/`battlePaused`/`fastForward` statics |
| `BattleManager` | 4032 | battle result fields: `coinMulti` +0x130, `coinMultiByItem` +0x134, `expMulti` +0x138, `expMultiByItem` +0x13C, `expBonusCnt` +0x358 |
| `BattleManager.<_CheckForDrops>c__Iterator0` | 4052 | enemy EXP/coin/drop computation (`$this` at +0xF0) |
| `AudioController` | 2660 | Master Audio singleton: `_soundMuted` +0x59, `_isAdditionalAudioController` +0x5B, `_audioDisabled` +0x5C |
| `AudioObject` | 2669 | one-shot SE object: `_paused` +0x64, `_applicationPaused` +0x65, sources `+0xD0`/`+0xD8` |
| `ObjectPoolController` / `PoolableObject` | 2676 / 2675 | capped audio-object pool (`maxPoolSize` +0x18) |
| `MusicManager` | 4164 | custom BGM player with its own `AudioSource[]` |
| `AssetManager` | 3949 | loads `SE`/`BGM` bundles (`LoadSE`, `LoadBGM`, `GetSEAsset`, `GetBGMAsset`) |
| `UIBattleResultTeam` | 4568 | result screen; `AddExp` `0xF4DEF8` loops level-ups |
| `UIIconBtn` | - | Options / in-battle rows; type dispatch is `OnClickBtn` |

## Systems

### Audio

- **BGM**: custom `MusicManager` (TypeDefIndex 4164), driven by
  `AssetManager.LoadBGM` / `GetBGMAsset`; its own `AudioSource[]`, independent
  of Master Audio.
- **Battle SE**: `AudioController.Play` -> `_PlayEx` -> `PlayAudioItem` ->
  `PlayAudioSubItem` -> `AudioObject` -> `AudioSource`. SE clips are loaded
  from the `SE/*.bin` bundles and registered as Master Audio items.
- **UI SFX**: NGUI `NGUITools.PlaySound` -> `AudioSource.PlayOneShot`.

The minimise/resume fix and its evidence are in `docs/native-mods.md`.

### Rewards

`BattleManager.<_CheckForDrops>c__Iterator0.MoveNext` (`0xCE9D50`) computes:

- EXP at `0xCEA3AC`: `(int)(baseExp * (expMulti + expMultiByItem))`
- coins at `0xCEA3FC`: `(int)(baseCoin * (coinMulti + coinMultiByItem))`

The results-screen vs roster mismatch and the proposed fix are in
`docs/rewards.md`.

### Userdata / integrity

- Version verifier key `versionVerify_terra_battle_mistwalker` (literal slot
  `0x2BDC668`); `GameManager.Awake` compares the hashed version string.
- The anti-cheat audit (no binary/signature check; data-table and version
  checks only) is in `docs/investigation.md`.

## Known unknowns

- **x4 speed label.** Solved: `UIIconBtn.UpdateBtn` keyed on
  `Type.MoreFasterFastForward = 63` and treated `toggle` as a boolean, so state
  2 reused the x3 suffix. The label cave now builds all three values from the
  live 2x/3x suffix strings and the live `x4` literal; the standalone
  `" / "` / `[ffffff]` / `[808080]` slots are not initialized at that point.
  `x4` is at `0x2BD3118`.
- **Unity 2017.4 audio resume.** The exact reason the resume message does not
  reach pooled `AudioObject`s is not established; the patch removes the stale
  state instead of relying on it.
- **REA depth.** Ghidra is absent, so no pseudocode; `inspect_il2cpp_metadata`
  does not parse this metadata header. Do not treat REA provider errors as
  missing facts.
