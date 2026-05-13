#!/usr/bin/env bash
set -euo pipefail

# --- Configuration ---
ORG_VAR_NAME="BINARY_ENCRYPTER_PUB_KEY"

# --- UI Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}==> Starting Binary Encrypter Production Bootstrap...${NC}"

# --- 0. Environment Check ---
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$REPO_ROOT" ]; then
    echo -e "${RED}ERROR: Must be run inside a git repository${NC}"
    exit 1
fi
cd "$REPO_ROOT"

# Check for tools
for tool in openssl act git; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}ERROR: $tool is not installed.${NC}"
        exit 1
    fi
done

# --- 1. Version Pre-Validation (Host) ---
# This logic ensures Cargo.toml matches your git history before doing anything expensive.

CARGO_VERSION=$(grep "^version =" Cargo.toml | head -1 | cut -d '"' -f 2)

# Get the latest reachable tag. If none exists, default to what Cargo says (assuming first run).
LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v$CARGO_VERSION")

# Normalize: Strip the leading 'v'
TAG_NORMALIZED=${LATEST_TAG#v}

echo -e "${YELLOW}==> Verifying Versions...${NC}"
if [ "$CARGO_VERSION" != "$TAG_NORMALIZED" ]; then
    echo -e "${RED}------------------------------------------------${NC}"
    echo -e "${RED}ERROR: LOCAL VERSION MISMATCH${NC}"
    echo -e "Cargo.toml: $CARGO_VERSION"
    echo -e "Latest Tag: $LATEST_TAG"
    echo -e "${RED}------------------------------------------------${NC}"
    echo -e "Please update Cargo.toml or tag the commit:"
    echo -e "git tag -a v$CARGO_VERSION -m 'Release v$CARGO_VERSION'"
    exit 1
fi

APP_VERSION="$CARGO_VERSION"
echo -e "${GREEN}==> Version Check Passed: v$APP_VERSION${NC}"

# --- 2. Repo Detection ---
REMOTE_URL=$(git config --get remote.origin.url || echo "")
if [[ $REMOTE_URL =~ github.com[:/]([^/]+)/([^.]+)(\.git)? ]]; then
    ORG_NAME="${BASH_REMATCH[1]}"
    DETECTED_REPO="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
    echo -e "${GREEN}==> Detected Repository: $DETECTED_REPO${NC}"
else
    echo -e "${RED}ERROR: Could not detect GitHub remote.${NC}"
    exit 1
fi

# --- 3. Safe Key Generation ---
mkdir -p keys

generate_key_if_missing() {
    local name=$1
    local priv="keys/${name}_private.pem"
    local pub="keys/${name}_public.pem"

    if [[ -f "$priv" ]]; then
        echo -e "${YELLOW}Key pair '$name' already exists.${NC}"
        read -p "Overwrite and ROTATE keys? (This will invalidate old releases) [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${GREEN}Keeping existing keys.${NC}"
            return 0
        fi
        echo -e "${RED}Overwriting keys...${NC}"
    fi

    echo "Generating RSA-3072 pair: $name"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$priv"
    openssl rsa -in "$priv" -pubout -out "$pub"
    chmod 600 "$priv"
}

generate_key_if_missing "signing"
generate_key_if_missing "encryption"

# Gitignore check
[[ -f .gitignore ]] && ! grep -q "keys/" .gitignore && echo "keys/" >> .gitignore
[[ -f .gitignore ]] && ! grep -q "*.act.yml" .gitignore && echo "*.act.yml" >> .gitignore

# Prepare Variables
SIG_PRIV_B64=$(openssl base64 -A -in keys/signing_private.pem)
SIG_PUB_PEM=$(cat keys/signing_public.pem)
# Indent for YAML injection
SIG_PUB_PEM_INDENTED=$(echo "$SIG_PUB_PEM" | sed 's/^/        /')
ENC_PUB_B64=$(openssl base64 -A -in keys/encryption_public.pem)

# --- 4. Update Secrets & Org Vars ---
if command -v gh &> /dev/null && gh auth status &> /dev/null; then
    echo -e "${GREEN}==> Syncing secrets to GitHub ($DETECTED_REPO)...${NC}"
    
    # 1. Update Repo Secrets
    gh secret set SIGNING_PRIVATE_KEY_B64 --body "$SIG_PRIV_B64" --repo "$DETECTED_REPO"
    gh secret set SIGNING_PUBLIC_KEY_PEM --body "$SIG_PUB_PEM" --repo "$DETECTED_REPO"
    gh secret set ENCRYPTION_PUBLIC_KEY_B64 --body "$ENC_PUB_B64" --repo "$DETECTED_REPO"

    # 2. Update Org Variable
    echo -e "${YELLOW}==> Updating Organization Variable ($ORG_VAR_NAME)...${NC}"
    gh variable set $ORG_VAR_NAME --org "$ORG_NAME" --body "$SIG_PUB_PEM" --visibility "all"
else
    echo -e "${RED}!!! gh CLI not found or not logged in.${NC}"
fi

# --- 5. Common Verification Logic ---
# This ensures that inside the runner: Binary == Cargo.toml == Git Tag
VERIFY_STEP="      - name: Verify Ternary Version Consistency
        run: |
          BINARY_OUTPUT=\$(./target/release/binary_encrypter --version 2>&1 || echo 'EXEC_FAILED')
          # Extract version (e.g. 1.0.0) from output like 'binary_encrypter v1.0.0'
          BINARY_VER=\$(echo \"\$BINARY_OUTPUT\" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
          
          # Dynamic extraction of Cargo.toml version
          CARGO_VER=\$(grep \"^version =\" Cargo.toml | head -1 | cut -d '\"' -f 2)
          
          TAG_NAME=\"\${{ github.ref_name }}\"
          TAG_VER=\${TAG_NAME#v}

          echo \"Verifying: Binary (\$BINARY_VER) == Cargo (\$CARGO_VER) == Tag (\$TAG_VER)\"

          if [ -z \"\$BINARY_VER\" ] || [ \"\$BINARY_VER\" != \"\$CARGO_VER\" ] || [ \"\$BINARY_VER\" != \"\$TAG_VER\" ]; then
            echo \"ERROR: Version Mismatch\"; exit 1
          fi"

# --- 6. Generate Workflows ---
mkdir -p .github/workflows

# Production
cat > .github/workflows/release.yml <<EOF
name: Release
on:
  push:
    tags: [v*]
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Deps
        run: sudo apt-get update && sudo apt-get install -y cmake clang pkg-config libssl-dev openssl
      - name: Build
        env:
          SIGNING_PUBLIC_KEY_PEM: \${{ secrets.SIGNING_PUBLIC_KEY_PEM }}
        run: cargo build --release
$VERIFY_STEP
      - name: Sign and Hash Binary
        run: |
          cd target/release
          sha512sum binary_encrypter > binary_encrypter.sha512
          echo "\${{ secrets.SIGNING_PRIVATE_KEY_B64 }}" | openssl base64 -d -A > priv.pem
          openssl dgst -sha512 -sign priv.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -out binary_encrypter.sig binary_encrypter
          rm priv.pem
      - name: Create Release
        env:
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
        run: |
          gh release create \${{ github.ref_name }} \\
            target/release/binary_encrypter \\
            target/release/binary_encrypter.sig \\
            target/release/binary_encrypter.sha512 \\
            --generate-notes
EOF

# Local ACT
cat > .github/workflows/release.act.yml <<EOF
name: Release (act)
on: [push]
jobs:
  release:
    runs-on: ubuntu-latest
    env:
      SIGNING_PRIVATE_KEY_B64: $SIG_PRIV_B64
      SIGNING_PUBLIC_KEY_PEM: |
$SIG_PUB_PEM_INDENTED
    steps:
      - name: Deps
        run: apt-get update && apt-get install -y cmake clang pkg-config libssl-dev git nodejs openssl
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Build
        env:
          SIGNING_PUBLIC_KEY_PEM: \${{ env.SIGNING_PUBLIC_KEY_PEM }}
        run: cargo build --release
$VERIFY_STEP
      - name: Sign and Hash
        run: |
          cp target/release/binary_encrypter ./binary_encrypter-local
          sha512sum binary_encrypter-local > binary_encrypter.sha512
          echo "\$SIGNING_PRIVATE_KEY_B64" | openssl base64 -d -A > priv.pem
          openssl dgst -sha512 -sign priv.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -out binary_encrypter.sig binary_encrypter-local
          rm priv.pem
EOF

# --- 7. Execute Act Simulation ---
echo -e "${YELLOW}==> Running ACT Simulation...${NC}"

# Ensure a local tag exists so act can see it
git tag -f "v$APP_VERSION" 

if act push -W .github/workflows/release.act.yml \
    -e <(echo "{\"ref\": \"refs/tags/v$APP_VERSION\"}") \
    -P ubuntu-latest=rustlang/rust:nightly \
    --container-architecture linux/amd64 --bind; then
    
    echo -e "\n${GREEN}BOOTSTRAP & SIMULATION SUCCESSFUL${NC}"
    echo -e "Version: v$APP_VERSION"
    echo -e "Org Variable: $ORG_VAR_NAME (Updated)"
else
    echo -e "${RED}ERROR: Act simulation failed.${NC}"
    exit 1
fi