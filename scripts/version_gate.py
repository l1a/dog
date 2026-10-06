#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check that a change bumps the version, as every PR must.

    version_gate.py --base origin/master     # compare this tree against a git ref
    version_gate.py                          # lockfile and last-tag checks only
    version_gate.py --self-test

THE RULE: every merged PR bumps `Cargo.toml`'s version, with no carve-out for docs-only,
test-only or CI-only changes. Use a PATCH bump for fixes, tests, docs, CI and dependency
updates, and a MINOR bump for a new user-visible feature. A release needs no bump of its own:
after a tag, master stays at the released version and the next PR does the bumping, which is
also why the packaging templates record no version.

WHAT IS CHECKED, and why each one exists:

  1. Cargo.lock agrees with Cargo.toml. Every build and every packaging channel uses --locked,
     so a bump that leaves the lockfile behind fails there, and the v0.6.0 tag shipped exactly
     that way (its lockfile said 0.5.7), which made it unbuildable by any --locked channel.
  2. The version is strictly past the BASE ref's (master's). Comparing only with the last tag,
     as the sibling projects do, lets two PRs both bump to 0.7.1 and neither notice that the
     second one added nothing.
  3. The version is strictly past the last tag. Without a base ref this is all there is to
     compare with.

Versions compare numerically per component, so 0.10.0 is past 0.9.0. A string comparison gets
that backwards.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render_packaging as rp  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "dogdns"


def parse(version: str) -> tuple[int, ...]:
    """A version as a tuple of integers, so comparison is numeric, not alphabetical."""
    return tuple(int(part) for part in rp.validate_version(version).split("."))


def lock_version(lock_text: str, package: str = PACKAGE) -> str:
    """The version Cargo.lock records for `package`."""
    for block in lock_text.split("[[package]]"):
        m = re.search(r'^name = "([^"]+)"\s*\nversion = "([^"]+)"', block, re.MULTILINE)
        if m and m.group(1) == package:
            return m.group(2)
    raise rp.RenderError(f"{package} not found in Cargo.lock")


def suggestions(version: str) -> str:
    major, minor, patch = (parse(version) + (0, 0, 0))[:3]
    return f"{major}.{minor}.{patch + 1} (patch) or {major}.{minor + 1}.0 (minor)"


def problems(current: str, lock: str, base: str | None, tag: str | None) -> list[str]:
    """Everything wrong with `current`. Empty means the version is acceptable."""
    found = []
    if lock != current:
        found.append(
            f"Cargo.lock records {lock} but Cargo.toml says {current}. "
            "Run `cargo build` and commit Cargo.lock."
        )
    if base is not None and parse(current) <= parse(base):
        found.append(
            f"version {current} is not past master's {base}. Bump it: {suggestions(base)}."
        )
    if tag is not None and parse(current) <= parse(tag):
        found.append(
            f"version {current} is not past the last tag v{tag}. Bump it: {suggestions(tag)}."
        )
    return found


def bump_kind(old: str, new: str) -> str:
    a, b = (parse(old) + (0, 0, 0))[:3], (parse(new) + (0, 0, 0))[:3]
    if b[0] != a[0]:
        return "major"
    if b[1] != a[1]:
        return "minor"
    return "patch"


def git(*args: str) -> str:
    out = subprocess.run(["git", *args], cwd=REPO_ROOT, text=True, capture_output=True)
    if out.returncode != 0:
        raise rp.RenderError(f"git {' '.join(args)} failed: {out.stderr.strip()}")
    return out.stdout


def last_tag_version() -> str | None:
    out = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*"],
        cwd=REPO_ROOT, text=True, capture_output=True,
    )
    return out.stdout.strip().removeprefix("v") if out.returncode == 0 and out.stdout.strip() else None


def self_test() -> None:
    """Prove the gate can FAIL, not just that a good version passes."""
    # Numeric, not alphabetical: 0.10.0 is past 0.9.0, and 0.9.0 is not past 0.10.0.
    assert parse("0.10.0") > parse("0.9.0") and not parse("0.9.0") > parse("0.10.0")
    assert parse("1.0.0") > parse("0.99.99")

    assert problems("0.7.1", "0.7.1", "0.7.0", "0.6.0") == []
    assert problems("0.7.0", "0.7.0", "0.6.0", "0.6.0") == []

    # Not bumped past master: equal, and lower.
    assert any("not past master" in p for p in problems("0.7.0", "0.7.0", "0.7.0", "0.6.0"))
    assert any("not past master" in p for p in problems("0.6.9", "0.6.9", "0.7.0", "0.6.0"))
    # The case a tag-only gate misses: master has moved on from the tag, and this PR did not bump.
    assert problems("0.7.0", "0.7.0", "0.7.0", "0.6.0") != [], "a tag-only gate would pass this"
    # Not bumped past the last tag.
    assert any("last tag" in p for p in problems("0.6.0", "0.6.0", None, "0.6.0"))
    # A stale lockfile, which is what made the v0.6.0 tag unbuildable.
    assert any("Cargo.lock" in p for p in problems("0.7.0", "0.6.0", "0.6.0", "0.6.0"))
    # With no base and no tag there is nothing to compare against, and only the lockfile can fail.
    assert problems("0.1.0", "0.1.0", None, None) == []
    assert problems("0.1.0", "0.0.9", None, None) != []

    assert lock_version('[[package]]\nname = "x"\nversion = "1.0.0"\n\n'
                        '[[package]]\nname = "dogdns"\nversion = "0.7.0"\n') == "0.7.0"
    try:
        lock_version('[[package]]\nname = "x"\nversion = "1.0.0"\n')
    except rp.RenderError:
        pass
    else:
        raise AssertionError("lock_version accepted a lockfile without the package")

    assert bump_kind("0.6.0", "0.6.1") == "patch"
    assert bump_kind("0.6.1", "0.7.0") == "minor"
    assert bump_kind("0.7.0", "1.0.0") == "major"
    assert suggestions("0.7.0") == "0.7.1 (patch) or 0.8.0 (minor)"
    for bad in ("v1.2.3", "1.2.3-rc.1", "", "x.y", "1."):
        try:
            parse(bad)
        except rp.RenderError:
            pass
        else:
            raise AssertionError(f"parse accepted {bad!r}")
    print("self-test passed")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", help="a git ref to compare against, such as origin/master")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    try:
        if args.self_test:
            self_test()
            return 0

        current = rp.cargo_version((REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        lock = lock_version((REPO_ROOT / "Cargo.lock").read_text(encoding="utf-8"))
        base = rp.cargo_version(git("show", f"{args.base}:Cargo.toml")) if args.base else None
        tag = last_tag_version()

        print(f"Cargo.toml: {current}   Cargo.lock: {lock}   "
              f"{args.base or 'base'}: {base or '-'}   last tag: {('v' + tag) if tag else '-'}")
        found = problems(current, lock, base, tag)
        for p in found:
            print(f"error: {p}", file=sys.stderr)
            print(f"::error::{p}")  # a GitHub Actions annotation; harmless elsewhere
        if found:
            return 1
        ref = base or tag
        kind = f"a {bump_kind(ref, current)} bump from {ref}" if ref else "no earlier version to compare"
        print(f"version OK: {current} ({kind})")
        return 0
    except rp.RenderError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
