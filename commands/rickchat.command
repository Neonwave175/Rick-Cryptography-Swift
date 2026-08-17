#!/bin/bash
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)
cd "$SCRIPT_DIR"

echo "=================================================="
echo "         RickChat - Secure P2P Engine            "
echo "=================================================="

if [ ! -d ".build/release" ]; then
    echo "[i] Building release binaries..."
    swift build -c release
fi

swift run -c release rickchat "$@"
