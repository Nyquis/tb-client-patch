# Signing identity

The patched APK is signed with a local key in `keys/`, which is **gitignored**
and never published. The public half is pinned in `patches/signing.json`
(certificate SHA-256, distinguished name, alias), and both `pixi run build` and
`pixi run verify` refuse to continue if the APK was signed by anything else.

Why it matters: Android only installs an update over the same package if the
signer matches. Keeping the identity means `adb install -r` upgrades the client
and the player's local data (settings, cached bundle) survives. A new key means
a new app identity: the old client must be uninstalled first. The account itself
lives on the reTB server, so only local cache is lost.

## What is in the repository

| File | Contains | Secret? |
|---|---|---|
| `patches/signing.json` | certificate SHA-256, DN, alias, keystore path | no — public fingerprint |
| `tools/signing.py` | how the password is resolved | no |
| `tools/keycheck.py` | verifies the key matches the pin | no |
| `tools/make_key.py` | creates a new identity (only if `keys/` is lost) | no |

The password is read from `TB_KEY_PASS` or `keys/keystore.pass` (gitignored) and
is never stored in the repository.

## Create (only when `keys/` is lost)

```sh
pixi run newkey        # refuses to overwrite an existing key
```

It prints the new certificate fingerprint. Record it in `patches/signing.json`
and expect to uninstall any existing client before installing a build signed
with it.

## Back up

The keystore is ~2.6 KB. Two independent copies, at least one off-machine:

1. **Kopia** — `.kopiaignore` deliberately does *not* exclude `keys/`, so the
   keystore and `keys/keystore.pass` are backed up with the rest (Kopia's
   repository is encrypted).
2. **Password manager / encrypted archive** — e.g.
   `7z a -p keys/tb-client.keystore.7z keys/tb-client.keystore`, stored outside
   this folder.

`.gitignore` keeps `keys/` out of git in all cases.

## Restore and verify (new machine, fresh clone)

1. Copy `keys/tb-client.keystore` and `keys/keystore.pass` back into place
   (or set `TB_KEY_PASS`).
2. Run the check before building:

```sh
pixi run keycheck
# OK   keystore certificate 62af4013b450e4f2... == pinned identity
```

A mismatch means builds would carry a different identity; do not ship them.

## What the build does

`build_patch.py` signs with `keys/tb-client.keystore` (alias and password from
`signing.py`), then reads the certificate back out of the APK with
`apksigner verify --print-certs` and compares it to the pin. On a mismatch it
deletes the output and fails.
