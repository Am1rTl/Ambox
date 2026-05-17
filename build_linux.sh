#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$ROOT_DIR/dist"
cd "$ROOT_DIR"

if [[ ! -x "$ROOT_DIR/.venv/bin/python" ]]; then
  echo "error: .venv not found. Create it first and install dependencies."
  exit 1
fi

. "$ROOT_DIR/.venv/bin/activate"
mkdir -p "$DIST_DIR"

pyinstaller --noconfirm --clean ambox-linux.spec
echo "Built: $DIST_DIR/ambox-linux"
