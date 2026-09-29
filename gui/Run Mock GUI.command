#!/bin/zsh
# Stop on a failed command, so a failed build does not launch an older app.
set -e

# Start from the project folder, even when this file is double-clicked in Finder.
cd -- "$(dirname -- "$0")/.."

# Homebrew puts CMake here on Apple Silicon (or in /usr/local on Intel Macs).
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
# Configure the build folder, compile changed files, then ask macOS to open the app.
cmake -S gui -B out/gui-macos
cmake --build out/gui-macos --parallel 4
open out/gui-macos/IndagoRev.app
