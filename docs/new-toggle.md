# Recipe for a new in-battle toggle

1. Pick a dead `UIIconBtn.Type` and its click case in `OnClickBtn` (the `t2`
   entry).
2. Pick an unused `DebugManager` static bool (scan the 29 class-pointer methods
   for the offset; +0x11, +0x12 and +0x25 are free).
3. If it is a Kamcord type: extend the Everyplay gate + availability caves, and
   nop its `SetDisableFlag` call in `StartBattle`.
4. Add a click cave (flip the flag, optional action, `SetColor` red/white) and a
   colour-sync hook at `0xE93A88`. For an Options row, keep `isToggleBtn = 0`
   and set the label/colour from the saved state at the end of `InitBtn`
   (`0xE9349C`); the built-in toggle prologue calls `UpdateBtn` before the type
   dispatch and is the path that failed for type 27.
5. Add a `patches/native_*.json` entry set. `pixi run build` applies every
   enabled file; `pixi run verify` re-applies the same set from the original and
   requires the result to match; `pixi run doctor` lists each family.
6. Keep caves in verified-zero padding; `verify` fails on any undeclared byte.
