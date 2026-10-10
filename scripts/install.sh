#!/bin/sh
# Offline independent Netrix installer by ir_spoof — t.me/ir_spoof
# Behavioral reference: github.com/Karrari-Dev/Netrix-; no upstream script is embedded.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3.10 or newer is required. Install it with your Linux distribution package manager.' >&2
    exit 1
fi

# Pass explicit local core/checksum options through to the Python installer.
# Example: sudo sh scripts/install.sh --binary build/netrix --sha256 HASH
exec python3 "$script_dir/netrix-manager.py" install "$@"
