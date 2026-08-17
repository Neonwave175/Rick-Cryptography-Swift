#!/bin/bash
set -e

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
cd "$SCRIPT_DIR"

echo "=================================================="
echo "      Setting up Rick Cryptography Swift          "
echo "=================================================="

if ! command -v swift >/dev/null 2>&1; then
    echo "[!] Error: Swift compiler is not installed or not in PATH."
    echo "    Please install Xcode Command Line Tools via: xcode-select --install"
    exit 1
fi

echo "[i] Building Swift package in release mode..."
swift build -c release

echo "[i] Setting executable permissions for command scripts..."
chmod +x setup.sh commands/*.command 2>/dev/null || true

echo "=================================================="
echo " Setup complete! All targets compiled cleanly.   "
echo "                                                  "
echo " Run applications via CLI:                        "
echo "   swift run -c release rick        (PoW Hash CPU) "
echo "   swift run -c release rick --gpu  (PoW Hash GPU) "
echo "   swift run -c release rickcrypt   (File Crypt)   "
echo "   swift run -c release rickchat    (P2P Chat)     "
echo "                                                  "
echo " Or launch double-clickable macOS scripts:        "
echo "   commands/rick.command                          "
echo "   commands/rickcrypt.command                     "
echo "   commands/rickchat.command                      "
echo "=================================================="
