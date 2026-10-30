# binary_encrypter

## Overview

Encrypts ONE file into the LNEC container for OTA distribution. Rust (Edition 2024). It is a single command with no
subcommands:

```bash
binary_encrypter --input FILE --key PUBLIC.pem --output OUT.enc
```

It writes the encrypted file and nothing else: **no `.sig`, no `.sha512`, no manifest.** The signature, the checksum
and the bundle around the encrypted file are made by the release workflow. For VTS that is
`vts/.github/workflows/release.yml`: `tar -czf … release_package.tar.gz`, `openssl dgst -sha512 -sign … -sigopt
rsa_pss_saltlen:-1` for `release_package.sig`, and a `release.json`, all tarred and then passed to this tool. For the
plain LiftCloud and liftNet_frontend artifacts it is `binary_updater pack`. The decrypting and verifying side is
`binary_updater` (`fetch`, `verify`, `inspect`, `decrypt`, the update daemon).

## Format (LNEC)

`"LNEC" 0x01 <key_len u32 BE> <RSA-OAEP-SHA512 wrapped AES-256 key> <12-byte nonce> <AES-256-GCM ciphertext + tag>`

`decrypt_from_reader` rejects a wrapped-key length outside `WRAPPED_KEY_LEN` (128..=1024) before it allocates
anything. `binary_updater` enforces the same bound (`crypto::WRAPPED_KEY_LEN`): change both or neither.

The encryption key is a PUBLIC key by design, so anyone can produce a validly encrypted file: an `.enc` proves nothing
about who made it. Authorship comes from the RSA-PSS signature over the inner package, which `binary_updater` verifies
against a trust anchor its caller supplies.

## Build & Quality

```bash
cargo fmt --all
cargo clippy --workspace -- -W clippy::all -W clippy::nursery -W clippy::pedantic
cargo test --workspace
```

## Key Files

- `src/main.rs` — the CLI; `src/lib.rs` — `encrypt_to_writer`, `decrypt_from_reader`, the format constants
- `tests/roundtrip.rs` — round trips, tamper and truncation cases, the wrapped-key length bound
- `build.rs` — `VERSION_STRING` from the newest `v*.*.*` git tag; copies `SIGNING_PUBLIC_KEY_PEM` (or
  `keys/signing_public.pem`, or a placeholder with a build warning) into `OUT_DIR`. The encrypter itself does not use
  that key.
- `bootstrap.sh` — initial key setup. `keys/` is git-ignored and is not part of the repository: never commit it, never
  print it.

## Known broken: there is no `bundle` subcommand

`scripts/bundle_release.sh` and `scripts/release_workflow_template.yml` (and `pxe_provision`'s `build-release.sh`) call
`binary_encrypter bundle --directory … --version … --binary-name … --signing-key …`. This tool has no such subcommand,
and none was ever committed here (`git log -S bundle -- src/` finds nothing), so those callers have always failed
against it; they also disagree with each other on flags. They are documented here and left in place: deleting them is
the owner's decision. The authoritative recipe for a real bundle is the VTS release workflow named above.
