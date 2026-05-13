#!/usr/bin/env bash
set -euo pipefail

# bundle_release.sh — Called by CI workflows to create an encrypted, signed,
# manifest-verified release bundle using binary_encrypter's `bundle` command.
#
# Required environment variables:
#   BINARY_NAME       — Name of the primary binary (e.g. "vts")
#   RELEASE_DIR       — Directory containing the binary and hook scripts
#   ENCRYPTION_PUB    — Path to the RSA public key for encryption
#   SIGNING_PRIV      — Path to the RSA private key for signing
#   VERSION           — Semantic version (e.g. "1.0.0", extracted from git tag)
#   OUTPUT_DIR        — Where to write .enc and .sha512 files
#
# Optional:
#   ENCRYPTER_BIN     — Path to binary_encrypter (default: binary_encrypter in PATH)

# Validate inputs first
for var in BINARY_NAME RELEASE_DIR ENCRYPTION_PUB SIGNING_PRIV VERSION OUTPUT_DIR; do
  if [[ -z "${!var:-}" ]]; then
    echo "ERROR: ${var} is not set" >&2
    exit 1
  fi
done

ENCRYPTER_BIN="${ENCRYPTER_BIN:-binary_encrypter}"
OUTPUT_FILE="${OUTPUT_DIR}/${BINARY_NAME}.enc"

echo "==> Bundling release: ${BINARY_NAME} v${VERSION}"
echo "    Source:     ${RELEASE_DIR}"
echo "    Output:     ${OUTPUT_FILE}"

if [[ ! -d "${RELEASE_DIR}" ]]; then
  echo "ERROR: RELEASE_DIR '${RELEASE_DIR}' does not exist" >&2
  exit 1
fi

if [[ ! -f "${RELEASE_DIR}/${BINARY_NAME}" ]]; then
  echo "ERROR: Binary '${BINARY_NAME}' not found in '${RELEASE_DIR}'" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# Run the bundle command — this creates:
#   1. Inner tar.gz with all files
#   2. Per-file SHA-512 manifest (release.json)
#   3. RSA-PSS/SHA-512 signature of inner archive
#   4. Outer tar.gz wrapping manifest + inner + signature
#   5. Hybrid-encrypted .enc output
#   6. Companion .sha512 checksum
"${ENCRYPTER_BIN}" bundle \
  --directory "${RELEASE_DIR}" \
  --version "${VERSION}" \
  --binary-name "${BINARY_NAME}" \
  --key "${ENCRYPTION_PUB}" \
  --signing-key "${SIGNING_PRIV}" \
  --output "${OUTPUT_FILE}"

echo "==> Bundle complete"
echo "    Encrypted:  ${OUTPUT_FILE}"
echo "    Checksum:   ${OUTPUT_FILE%.enc}.enc.sha512"
