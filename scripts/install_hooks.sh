#!/usr/bin/env bash
# Install the git hooks for this repository. Run once per clone: `just install-hooks`.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$(git rev-parse --git-path hooks)"
mkdir -p "$HOOKS_DIR"

for name in pre-push; do
    src="$REPO_ROOT/scripts/hooks/$name"
    [ -f "$src" ] || { echo "ERROR: hook source not found: $src" >&2; exit 1; }
    cp "$src" "$HOOKS_DIR/$name"
    chmod +x "$HOOKS_DIR/$name"
    echo "Installed: $HOOKS_DIR/$name"
done
