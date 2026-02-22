#!/usr/bin/env bash
# dev-setup.sh — Set up a local dev environment for vox-py-sdk.
# Builds vox-media natively and installs vox-sdk in editable mode.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Creating/activating venv..."
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate

echo "==> Installing maturin..."
pip install --quiet maturin

echo "==> Building vox-media (maturin develop)..."
cd crates/vox-media
maturin develop --release
cd "$REPO_ROOT"

echo "==> Installing vox-sdk in editable mode with dev extras..."
pip install -e '.[dev,media]'

echo "==> Done! Activate with: source .venv/bin/activate"
