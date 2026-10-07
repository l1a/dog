#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the branch name before a PR is opened, as `just pr` does.

    branch_gate.py [--base origin/master]     # checks the current branch
    branch_gate.py --self-test

THE RULES
  * The name is `feature/<name>`, `fix/<name>`, `chore/<name>` or `docs/<name>`.
  * A `docs/` branch must change documentation only, as scripts/ci_changes.py classifies it (the
    same classification CI uses to take the docs-only fast path, including a bare version bump
    being ignored). A change that touches code is not `docs/`: it gets feature/, fix/ or chore/.

A docs-only change on a feature/, fix/ or chore/ branch is allowed: the prefix says what the
author meant, and CI classifies the files itself either way.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_changes as cc  # noqa: E402

PREFIXES = ("feature", "fix", "chore", "docs")
NAME = re.compile(r"(feature|fix|chore|docs)/[A-Za-z0-9][A-Za-z0-9._-]*")


def check(branch: str, classification: cc.Classification | None) -> list[str]:
    """What is wrong with the branch. `classification` is only consulted for a docs/ branch."""
    if not NAME.fullmatch(branch):
        return [f"branch '{branch}' must be named {{{','.join(PREFIXES)}}}/<name> (letters, digits, '.', '_', '-')"]
    if branch.startswith("docs/"):
        if classification is None:
            return ["could not classify the changed files, so cannot confirm this is a docs-only change"]
        if not classification.docs_only:
            return [f"'{branch}' is for documentation only, but this change is not docs-only "
                    f"({classification.reason}). Use feature/, fix/ or chore/"]
    return []


def git(*args: str) -> str:
    out = subprocess.run(["git", *args], text=True, capture_output=True)
    if out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {out.stderr.strip()}")
    return out.stdout


def local_classification(base: str) -> cc.Classification:
    """Classify what HEAD changes relative to the merge base with `base`, as CI would."""
    merge_base = git("merge-base", base, "HEAD").strip()
    files: dict[str, dict] = {}
    for line in git("diff", "--name-status", "-M", merge_base, "HEAD").splitlines():
        status, *names = line.split("\t")
        entry = {"status": {"M": "modified", "A": "added", "D": "removed"}.get(status[0], "renamed")}
        if status[0] == "R":
            entry["previous_filename"] = names[0]
        for name in names:
            files[name] = {**entry, "filename": names[-1]}

    def fetch(path: str, which: str) -> str:
        return git("show", f"{merge_base if which == 'base' else 'HEAD'}:{path}")

    return cc.classify_pr(files, fetch)


def self_test() -> None:
    docs = cc.Classification(False, False, "only documentation changed")
    code = cc.Classification(True, True, "1 non-docs file(s), e.g. src/main.rs")
    man = cc.Classification(False, True, "only docs and man/ changed")
    for ok in ["feature/x", "fix/broken-pipe", "chore/remove-datetime", "docs/project-descriptions", "fix/a.b_c-1"]:
        assert check(ok, code) == [] or ok.startswith("docs/"), ok
    assert check("docs/readme", docs) == []
    for bad in ["master", "main", "wip", "feat/x", "feature", "feature/", "fix", "docs", "dependabot/cargo/x",
                "Fix/x", "fix/-x", "fix/a b", "fix//x", "fix/a/b", "docs/", " fix/x", "fix/x\n", "release/1.0"]:
        assert check(bad, docs), f"{bad!r} must be rejected"
    # docs/ must be docs-only: code and man changes and an unknown classification are refused.
    for c, why in [(code, "src/main.rs"), (man, "man/")]:
        problems = check("docs/readme", c)
        assert problems and why in problems[0], problems
    assert check("docs/readme", None)
    # Other prefixes may carry docs-only changes.
    assert check("fix/readme-typo", docs) == [] and check("chore/x", None) == []
    print("self-test passed")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0
    base = sys.argv[sys.argv.index("--base") + 1] if "--base" in sys.argv else "origin/master"
    try:
        branch = git("rev-parse", "--abbrev-ref", "HEAD").strip()
        classification = local_classification(base) if branch.startswith("docs/") else None
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    problems = check(branch, classification)
    for p in problems:
        print(p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
