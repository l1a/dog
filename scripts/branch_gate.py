#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the branch name before a PR is opened, as `just pr` does.

    branch_gate.py [--base origin/master]     # checks the current branch
    branch_gate.py --self-test

THE RULES
  * The name is `feature/<name>`, `fix/<name>`, `chore/<name>` or `docs/<name>`.
  * A `docs/` branch must change documentation only (root Markdown, `man/`, `LICENSE`,
    `dog-screenshot.png`, `.github/ISSUE_TEMPLATE/`, `.github/pull_request_template.md`, plus the
    required version bump in `Cargo.toml` and `Cargo.lock`). A change that touches code, scripts,
    packaging, or workflows is not `docs/`: it gets `feature/`, `fix/` or `chore/`.

A docs-only change on a `feature/`, `fix/` or `chore/` branch is allowed.
"""

from __future__ import annotations

import re
import subprocess
import sys

PREFIXES = ("feature", "fix", "chore", "docs")
NAME = re.compile(r"(feature|fix|chore|docs)/[A-Za-z0-9][A-Za-z0-9._-]*")

DOC_EXACT = {"LICENSE", "dog-screenshot.png", ".github/pull_request_template.md"}
DOC_PREFIXES = ("man/", ".github/ISSUE_TEMPLATE/")

_VERSION_LINE = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')
_LOCK_HEADER = re.compile(r'^\[\[package\]\]\nname = "dogdns"\nversion = "([^"]+)"\n', re.MULTILINE)


def version_only_change(old_cargo: str, new_cargo: str, old_lock: str, new_lock: str) -> bool:
    """True when `Cargo.toml` and `Cargo.lock` change ONLY the dogdns version line."""
    old_lines, new_lines = old_cargo.splitlines(), new_cargo.splitlines()
    if len(old_lines) != len(new_lines):
        return False
    cargo_diffs = [(a, b) for a, b in zip(old_lines, new_lines) if a != b]
    if len(cargo_diffs) != 1:
        return False
    old_m, new_m = _VERSION_LINE.match(cargo_diffs[0][0]), _VERSION_LINE.match(cargo_diffs[0][1])
    if not old_m or not new_m or old_m.group(1) == new_m.group(1):
        return False
    old_ver, new_ver = old_m.group(1), new_m.group(1)

    if old_lock == new_lock:
        return True
    lock_m = _LOCK_HEADER.search(old_lock)
    if not lock_m or lock_m.group(1) != old_ver:
        return False
    expected = (
        old_lock[: lock_m.start()]
        + f'[[package]]\nname = "dogdns"\nversion = "{new_ver}"\n'
        + old_lock[lock_m.end() :]
    )
    return new_lock == expected


def is_doc_path(path: str) -> bool:
    if path in DOC_EXACT:
        return True
    if any(path.startswith(p) for p in DOC_PREFIXES):
        return True
    return "/" not in path and path.endswith(".md")


def non_doc_files(paths: list[str], *, version_bump: bool = True) -> list[str]:
    allowed_bump = {"Cargo.toml", "Cargo.lock"} if version_bump else set()
    return [p for p in paths if p not in allowed_bump and not is_doc_path(p)]


def check(branch: str, changed_paths: list[str] | None, *, version_bump: bool = True) -> list[str]:
    """What is wrong with the branch. `changed_paths` is only consulted for a docs/ branch."""
    if not NAME.fullmatch(branch):
        return [f"branch '{branch}' must be named {{{','.join(PREFIXES)}}}/<name> (letters, digits, '.', '_', '-')"]
    if branch.startswith("docs/"):
        if changed_paths is None:
            return ["could not list the changed files, so cannot confirm this is a docs-only change"]
        bad = non_doc_files(changed_paths, version_bump=version_bump)
        if bad:
            return [
                f"'{branch}' is for documentation only, but this change touches {bad[0]} "
                f"({len(bad)} non-docs file(s)). Use feature/, fix/ or chore/"
            ]
    return []


def git(*args: str) -> str:
    out = subprocess.run(["git", *args], text=True, capture_output=True)
    if out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {out.stderr.strip()}")
    return out.stdout


def changed_since(base: str) -> tuple[list[str], bool]:
    merge_base = git("merge-base", base, "HEAD").strip()
    paths: list[str] = []
    for line in git("diff", "--name-only", merge_base, "HEAD").splitlines():
        if line.strip():
            paths.append(line.strip())
    bump_only = False
    if "Cargo.toml" in paths or "Cargo.lock" in paths:
        try:
            old_cargo = git("show", f"{merge_base}:Cargo.toml")
            new_cargo = git("show", "HEAD:Cargo.toml")
            old_lock = git("show", f"{merge_base}:Cargo.lock")
            new_lock = git("show", "HEAD:Cargo.lock")
            bump_only = version_only_change(old_cargo, new_cargo, old_lock, new_lock)
        except RuntimeError:
            bump_only = False
    return paths, bump_only


def self_test() -> None:
    docs = ["README.md", "man/dog.1.md", "man/dog.1", "Cargo.toml", "Cargo.lock"]
    code = ["src/main.rs", "Cargo.toml", "Cargo.lock"]
    wf = [".github/workflows/ci.yml"]
    for ok in ["feature/x", "fix/broken-pipe", "chore/remove-datetime", "docs/project-descriptions", "fix/a.b_c-1"]:
        assert check(ok, code) == [] or ok.startswith("docs/"), ok
    assert check("docs/readme", docs, version_bump=True) == []
    # A docs/ branch that modifies Cargo.toml beyond the version line must be rejected.
    dep_change = check("docs/readme", docs, version_bump=False)
    assert dep_change and "Cargo.toml" in dep_change[0], dep_change

    c_old = '[package]\nname = "dogdns"\nversion = "0.8.4"\n[dependencies]\nlibc = "0.2"\n'
    c_new = '[package]\nname = "dogdns"\nversion = "0.8.5"\n[dependencies]\nlibc = "0.2"\n'
    c_dep = '[package]\nname = "dogdns"\nversion = "0.8.5"\n[dependencies]\nlibc = "0.3"\n'
    l_old = '[[package]]\nname = "dogdns"\nversion = "0.8.4"\n'
    l_new = '[[package]]\nname = "dogdns"\nversion = "0.8.5"\n'
    l_dep = '[[package]]\nname = "dogdns"\nversion = "0.8.5"\n[[package]]\nname = "x"\nversion = "1"\n'
    assert version_only_change(c_old, c_new, l_old, l_new)
    assert not version_only_change(c_old, c_dep, l_old, l_new)
    assert not version_only_change(c_old, c_new, l_old, l_dep)
    assert not version_only_change(c_old, c_old, l_old, l_old)

    for bad in ["master", "main", "wip", "feat/x", "feature", "feature/", "fix", "docs", "dependabot/cargo/x",
                "Fix/x", "fix/-x", "fix/a b", "fix//x", "fix/a/b", "docs/", " fix/x", "fix/x\n", "release/1.0"]:
        assert check(bad, docs), f"{bad!r} must be rejected"
    for c, why in [(code, "src/main.rs"), (wf, ".github/workflows/ci.yml")]:
        problems = check("docs/readme", c)
        assert problems and why in problems[0], problems
    assert check("docs/readme", None)
    assert check("fix/readme-typo", docs) == [] and check("chore/x", None) == []
    print("branch_gate.py self-test passed")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0
    base = sys.argv[sys.argv.index("--base") + 1] if "--base" in sys.argv else "origin/master"
    try:
        branch = git("rev-parse", "--abbrev-ref", "HEAD").strip()
        paths, bump_only = changed_since(base) if branch.startswith("docs/") else (None, True)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    problems = check(branch, paths, version_bump=bump_only)
    for p in problems:
        print(p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
