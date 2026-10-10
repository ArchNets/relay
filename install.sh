#!/bin/sh
# ArchNets/relay quick installer for Linux servers
# Compatible with x86_64 and aarch64
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ArchNets/relay/main/install.sh | sudo bash
#   or locally: sudo ./install.sh
set -eu

REPO="ArchNets/relay"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0" 2>/dev/null || pwd)" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    printf '\033[1;31mError: install.sh must be run as root (use sudo).\033[0m\n' >&2
    exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
    printf '\033[1;31mError: Only Linux is supported.\033[0m\n' >&2
    exit 1
fi

RAW_ARCH=$(uname -m)
case "$RAW_ARCH" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        printf '\033[1;31mError: Architecture %s is not supported (amd64 and arm64 only).\033[0m\n' "$RAW_ARCH" >&2
        exit 1
        ;;
esac

# Verify python3
if ! command -v python3 >/dev/null 2>&1; then
    printf '\033[1;33mPython3 not found. Attempting to install via package manager...\033[0m\n'
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qy && apt-get install -qy python3
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -qy python3
    elif command -v yum >/dev/null 2>&1; then
        yum install -qy python3
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm python
    else
        printf '\033[1;31mError: Python 3.10+ is required but not installed.\033[0m\n' >&2
        exit 1
    fi
fi

# Case 1: Local repository installation
if [ -f "$SCRIPT_DIR/scripts/netrix-manager.py" ]; then
    BINARY=""
    if [ -f "$SCRIPT_DIR/build/netrix" ]; then
        BINARY="$SCRIPT_DIR/build/netrix"
    elif [ -f "$SCRIPT_DIR/bin/netrix" ]; then
        BINARY="$SCRIPT_DIR/bin/netrix"
    elif command -v go >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/scripts/build.sh" ]; then
        printf '\033[1;34m[*] Building netrix from local source...\033[0m\n'
        (cd "$SCRIPT_DIR" && sh scripts/build.sh)
        BINARY="$SCRIPT_DIR/build/netrix"
    fi

    if [ -n "$BINARY" ] && [ -f "$BINARY" ]; then
        SHA=$(sha256sum "$BINARY" | cut -d' ' -f1)
        printf '\033[1;32m[*] Installing local binary (%s)...\033[0m\n' "$SHA"
        python3 "$SCRIPT_DIR/scripts/netrix-manager.py" install --binary "$BINARY" --sha256 "$SHA" "$@"
        printf '\033[1;32m[✓] Netrix installed successfully!\033[0m\n'
        printf 'Run \033[1;36msudo netrix-manager\033[0m to configure your tunnel.\n'
        exit 0
    fi
fi

# Case 2: Remote standalone download & install
printf '\033[1;34m[*] Fetching release package for linux-%s from GitHub (%s)...\033[0m\n' "$ARCH" "$REPO"
TMP_DIR=$(mktemp -d /tmp/netrix-install-XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

DOWNLOADER=""
if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget -qO-"
else
    printf '\033[1;31mError: curl or wget is required to download release files.\033[0m\n' >&2
    exit 1
fi

ASSET_URL="https://github.com/${REPO}/releases/latest/download/relay-linux-${ARCH}.tar.gz"
FALLBACK_URL="https://github.com/${REPO}/releases/download/v0.1.0/relay-linux-${ARCH}.tar.gz"

if ! curl -fsSL -o "$TMP_DIR/pkg.tar.gz" "$ASSET_URL" 2>/dev/null; then
    printf '\033[1;33m[*] Latest release not found; trying fallback release v0.1.0...\033[0m\n'
    if ! curl -fsSL -o "$TMP_DIR/pkg.tar.gz" "$FALLBACK_URL" 2>/dev/null; then
        printf '\033[1;31mError: Failed to download release asset from GitHub.\033[0m\n' >&2
        printf 'Check https://github.com/%s/releases\n' "$REPO" >&2
        exit 1
    fi
fi

tar -xzf "$TMP_DIR/pkg.tar.gz" -C "$TMP_DIR"

EXTRACTED_DIR=$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)
if [ -z "$EXTRACTED_DIR" ] || [ ! -f "$EXTRACTED_DIR/netrix" ]; then
    EXTRACTED_DIR="$TMP_DIR"
fi

BINARY="$EXTRACTED_DIR/netrix"
MANAGER="$EXTRACTED_DIR/scripts/netrix-manager.py"

if [ ! -f "$BINARY" ] || [ ! -f "$MANAGER" ]; then
    printf '\033[1;31mError: Corrupted archive; netrix binary or manager script missing.\033[0m\n' >&2
    exit 1
fi

SHA=$(sha256sum "$BINARY" | cut -d' ' -f1)
printf '\033[1;34m[*] Installing Netrix (%s)...\033[0m\n' "$SHA"
python3 "$MANAGER" install --binary "$BINARY" --sha256 "$SHA" "$@"

printf '\n\033[1;32m=====================================================\033[0m\n'
printf '\033[1;32m [✓] Netrix Relay successfully installed!           \033[0m\n'
printf '\033[1;32m=====================================================\033[0m\n\n'
printf 'To launch the interactive manager wizard, run:\n'
printf '    \033[1;36msudo netrix-manager\033[0m\n\n'
printf 'To inspect status:\n'
printf '    \033[1;36msudo netrix-manager status\033[0m\n\n'
