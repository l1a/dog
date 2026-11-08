#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 l1a
"""Install repository git hooks from `scripts/hooks/` into `.git/hooks/`."""

from __future__ import annotations

import shutil
import stat
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_SRC = REPO_ROOT / "scripts" / "hooks"
HOOKS_DST = REPO_ROOT / ".git" / "hooks"


def main() -> int:
    if not HOOKS_DST.is_dir():
        print(f"error: {HOOKS_DST} not found (not a git checkout?)", file=sys.stderr)
        return 1

    installed = 0
    for src in sorted(HOOKS_SRC.iterdir()):
        if not src.is_file():
            continue
        dst = HOOKS_DST / src.name
        src_bytes = src.read_bytes().replace(b"\r\n", b"\n")
        if dst.exists() and dst.read_bytes().replace(b"\r\n", b"\n") != src_bytes:
            bak = dst.with_suffix(".bak")
            shutil.copy2(dst, bak)
            print(f"  backed up existing {src.name} -> {bak.name}")
        dst.write_bytes(src_bytes)
        mode = dst.stat().st_mode
        dst.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"  installed {src.name}")
        installed += 1

    print(f"{installed} hook(s) installed into {HOOKS_DST}")
    print("  skip once with: GIT_NO_CHECK=1 git push")
    return 0


if __name__ == "__main__":
    sys.exit(main())
