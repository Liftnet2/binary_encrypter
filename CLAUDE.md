# binary_encrypter

## Overview

Security tool for encrypting binary files for secure OTA distribution. Rust (Edition 2024). Produces encrypted binaries with RSA signatures and SHA-512 checksums.

## Dependencies

- aes-gcm, rsa, sha2, clap, reqwest

## Build & Quality

```bash
cargo fmt
cargo clippy -- -W clippy::all -W clippy::nursery -W clippy::pedantic
cargo test
```

## Key Files

- `build.rs` — Build-time configuration
- `bootstrap.sh` — Initial key setup
- `keys/` — RSA key storage

## Cryptography

- RSA encryption for key exchange
- AES-256-GCM for symmetric encryption
- SHA-512 for integrity verification
- Outputs: `.sig` and `.sha512` files alongside encrypted binary
