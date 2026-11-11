# Investigation notes

Research history and audit results that informed the patches. Not required
reading to build or verify.

## Finding sites instead of reading them

Decompilation says what one site does; these say where the sites are. They replace
the throwaway `slot_refs` / `strb #0x88` / `+0x20` sweep scripts.

```sh
pixi run index                                # ensure the shared index exists (builds via the wrapper)
pixi run find-refs --slot 0x2A508E0           # ADRP+LDR/ADD sites touching a slot
pixi run find-refs --imm 0x88 --insn strb     # every strb #0x88 (stack slots skipped)
pixi run jumptable --at 0x1A2B3C --count 40   # decode a switch/jump table
```

The index (71k method RVAs, 16k field offsets) is produced by
`.tools/rea/bin/ghidra-method.ps1 -IndexOnly` and stored under
`.tools/ghidra/index/<so>_<sha8>[-fields].tsv`. This repo only reads it, so the
sweeps and the decompiler annotations always agree. `--index-dir` overrides the
location; `REA_TOOLS` relocates `.tools`.

- Output is bounded (`--limit`, `--offset`) and every hit is attributed to the
  enclosing method by nearest-preceding `dump.cs` RVA, so the method name is a
  strong hint, not a proof.
- `jumptable` reads `rel-table`/`rel-each` entries as **signed** by default,
  because ARM64 switch tables reached by `ldrsw` hold signed 32-bit offsets.
  `--unsigned` exists for the rare table that really is unsigned; when a computed
  target lands outside every segment the row prints `[unmapped]` with the opposite
  interpretation as a hint, rather than attributing it to a nearby method.
  `--signed/--unsigned` only change the reading, never the mode.
- A slot sweep is a linear ARM64 re-scan (~15 s here); there is no Ghidra project
  involved, so it never depends on analysis state.
- `--slot` reports the *referencing* instruction (add/ldr), not the ADRP.
- `jumptable` modes: `abs`, `rel-table`, `rel-each`; `--peek N` disassembles the
  first N instructions at each target, which is how you tell "sets isToggleBtn"
  from "shows a string" without another analysis pass.

## Il2CppDumper workflow

- The names `FastForward` / `timeScale1` / `timeScale2` / `MoreFasterFastForward`
  exist only as managed string literals; `data.unity3d` has zero hits.
- `libil2cpp.so` is stripped of `.symtab`; `SymbolMap-ARM64` is Unity's binary
  format. Il2CppDumper + capstone is the working path.
- Found with `Il2CppDumper` + capstone; `.tools/il2cppdumper` and `work/` are
  local and gitignored. No global tools were installed.

## Options screen UI

The options screen is in `data.unity3d` (`OptionMenuItem` -> `Btn` -> `Label` /
`SpriteIcon` / `SpriteBG`). Its serialized fields cannot be read without
generated typetrees for those MonoBehaviours, and the `gdresources` pack
contains no UI at all (only artwork/audio/scenario/profile bundles). Reading it
needs a typetree dump (AssetRipper/Il2CppDumper) before any x4 label work.

## Anti-cheat / integrity checks (audited)

There is **no binary or signature check**. Re-signing, repacking or patching code
does not affect any of these. The only hard stops are data-integrity and
version-string checks, which all `Debug.LogError` (`0x10BF144`) and then call
`Application.Quit` (`0x1D5F374`):

| String | Method (RVA) | Trigger |
|---|---|---|
| `version cheat detected..` | `GameManager.Awake` `0xD9B9C0` | `GetVersionVerifier(Application.version)` != stored value |
| `Detected plusCount cheating..` | `PlusTypeParams.CalcValueAtCount` `0xF004BC` | plusCount outside the parameter table |
| `Detected enemy data cheating..` | `EnemyData.GetData` `0x1078330` | enemy data fails its consistency check |
| `detected character data modification...` | `UserData.GetCharacterByID` `0x19D99F4` | character data does not match the expected value |

Log-and-repair only (no quit): `UserData.CorrectTeamMemeber` `0x19DBFD4`,
`CorrectTeamMemeber_VS` `0x19DC260`, `CorrectTeamBuddies_VS` `0x19DC4FC` - they
drop a team member/buddy that is no longer in the roster.

Dead strings (no metadata usage slot, never referenced):
`Detected job param data cheating..`, `Detected plusType param data cheating..`.

Version check details: `GameManager.GetVersionVerifier` `0xD9AE3C` builds a
string with the key `versionVerify_terra_battle_mistwalker` and hashes it
(`AppServerUtil.j5kyxGGxPJUndEDF` `0xDB3128`); `GameManager.Awake` compares that
against the stored verifier. It hashes the **version string**, not the binary, so
a patched client with the stock version passes. `app_version` /
`app_version_verify` are posted/read in `AppServerUtil.<Login>`, `<Signup>`,
`<GetServerStatus>` and `SendErrorInfo`.

`rankingCheat` is a `UserData` field at `+0x178`, parsed from the userdata JSON
in `AppServerUtil.LoadUserdataFromJson` `0xDB6010` (site `0xDB8048`). A scan of
every `ldr` of that offset found **no readers** - the flag is vestigial in this
build.

Consequence for mods: timer/muteki/PlayerPrefs/damage-clamp mods and a future
damage or one-hit toggle cannot trip any of these (they validate data tables and
the version string, not battle outcomes). Editing character/enemy/plus data, or
changing the version string, will quit the app.
