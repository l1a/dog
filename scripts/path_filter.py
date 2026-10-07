#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Decide whether a workflow has anything to check in a pull request, like `on.pull_request.paths`
but without being fooled by the version bump every PR must make.

    path_filter.py <workflow file>     # in CI: reads the environment, writes `run=true|false`
    path_filter.py --self-test

WHY NOT `paths:`. packaging.yml, metadata.yml and security.yml list Cargo.toml and Cargo.lock,
because a real change to either can break them. But every PR bumps the version, which edits both,
so a docs-only PR still started the COPR, AUR and Homebrew builds, the metadata check and cargo
audit. A path filter cannot tell a bare bump from a real change. This can: it uses the proof in
scripts/ci_changes.py (both files fetched at the merge base and the head; one line each, the
package's own version, the same old -> new), and ignores the two files only when it holds.

THE PATTERNS ARE NOT WRITTEN TWICE. They are read from the workflow's own `on.push.paths`, which
stays as a real `paths:` filter (a push to master has no PR to classify). The workflow's
`pull_request` trigger has no `paths:`, so the workflow always starts, a `changes` job runs this,
and the jobs are skipped with `if:`. None of these workflows is a required check, so a skipped
job blocks nothing (ci.yml, which IS required, has its own gate: scripts/ci_gate.py).

IT FAILS CLOSED. Anything that is not a pull request, a workflow it cannot read the patterns of,
an API error, a truncated file list, and a change to the version files alone all mean `run=true`.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_changes as cc  # noqa: E402


def glob_regex(pattern: str) -> re.Pattern:
    """A workflow-syntax glob as a regex: `**` crosses directories, `*` and `?` do not."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out)


def push_paths(workflow_text: str) -> list[str]:
    """The list under `on: push: paths:`. Empty if there is none (the caller fails closed)."""
    lines = workflow_text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if re.fullmatch(r"  push:\s*", line))
    except StopIteration:
        return []
    patterns, in_paths = [], False
    for line in lines[start + 1:]:
        if line.strip() and not line.startswith("    "):
            break                                   # dedented out of `push:`
        if re.fullmatch(r"    paths:\s*", line):
            in_paths = True
        elif in_paths:
            m = re.fullmatch(r"      - (?:'([^']*)'|\"([^\"]*)\"|(\S+))\s*(?:#.*)?", line)
            if m:
                patterns.append(next(g for g in m.groups() if g is not None))
            elif line.strip() and not line.strip().startswith("#"):
                break                               # the next key under `push:`
    return patterns


def relevant(files: dict[str, dict], patterns: list[str], fetch: Callable[[str, str], str]) -> tuple[bool, str]:
    """(run, why) for a PR that changes `files`."""
    if not patterns:
        return True, "no patterns to match"
    rx = [glob_regex(p) for p in patterns]
    paths = list(files)
    bump = cc.version_bump(files, fetch)
    note = ""
    if bump:
        rest = [p for p in paths if p not in cc.VERSION_FILES]
        if not rest:
            return True, f"only the version changed ({bump[0]} -> {bump[1]}); running to be safe"
        paths, note = rest, f"; the version bump {bump[0]} -> {bump[1]} is ignored"
    hits = [p for p in paths if any(r.fullmatch(p) for r in rx)]
    if hits:
        return True, f"{len(hits)} matching file(s), e.g. {hits[0]}{note}"
    return False, f"none of {len(paths)} changed file(s) matches{note}"


def decide(event: str, repo: str, number: str, workflow: Path) -> tuple[bool, str]:
    if event != "pull_request":
        return True, f"event is {event or 'unknown'}, not a pull request"
    if not number:
        return True, "no pull request number"
    try:
        patterns = push_paths(workflow.read_text(encoding="utf-8"))
        files = cc.pr_files(repo, number)
        if len(files) >= cc.API_FILE_LIMIT:
            return True, f"{len(files)} files: the list may be truncated"
        return relevant(files, patterns, cc.pr_fetcher(repo, number))
    except (RuntimeError, OSError, ValueError) as e:
        return True, str(e)


WORKFLOW = """name: X
on:
  push:
    branches: [ master ]
    paths:
      - 'packaging/**'
      - "man/**"
      - Cargo.toml
      - '**/Cargo.lock'   # a comment
  pull_request:
    branches: [ master ]
  workflow_dispatch:
"""


def self_test() -> None:
    # Globs.
    g = lambda pat, path: bool(glob_regex(pat).fullmatch(path))  # noqa: E731
    assert g("packaging/**", "packaging/a/b.txt") and g("packaging/**", "packaging/a")
    assert not g("packaging/**", "packaging") and not g("packaging/**", "xpackaging/a")
    assert g("Cargo.toml", "Cargo.toml") and not g("Cargo.toml", "x/Cargo.toml") and not g("Cargo.toml", "Cargo.tomlx")
    assert g("**/Cargo.toml", "Cargo.toml") and g("**/Cargo.toml", "a/b/Cargo.toml") and not g("**/Cargo.toml", "Cargo.toml.bak")
    assert g("*.md", "README.md") and not g("*.md", "a/README.md")
    assert g("scripts/render_packaging.py", "scripts/render_packaging.py") and not g("scripts/render_packaging.py", "scripts/renderXpackaging.py")

    # Reading the patterns from a workflow: all three quoting styles, a comment, and stopping at the next key.
    assert push_paths(WORKFLOW) == ["packaging/**", "man/**", "Cargo.toml", "**/Cargo.lock"], push_paths(WORKFLOW)
    assert push_paths("on:\n  pull_request:\n    paths:\n      - 'a'\n") == [], "only on.push counts"
    assert push_paths("") == []
    # The real workflows must yield patterns, or the filter would fail closed forever.
    for name in ("packaging", "metadata", "security"):
        text = (Path(__file__).resolve().parent.parent / ".github" / "workflows" / f"{name}.yml").read_text(encoding="utf-8")
        assert push_paths(text), f"{name}.yml has no on.push.paths"
        assert "  pull_request:\n" in text, f"{name}.yml: pull_request is missing"
        pr_block = text.split("  pull_request:\n", 1)[1].split("\n  push:", 1)[0].split("\n  workflow_dispatch", 1)[0]
        assert "paths:" not in pr_block, f"{name}.yml: pull_request must not carry paths:, or the filter never runs for a bump"

    # Relevance, with the same fixtures ci_changes uses for its bump proof.
    entry = {"status": "modified"}
    good_toml, good_lock = cc.bumped(cc.TOML, "0.7.1", "0.7.2"), cc.bumped(cc.LOCK, "0.7.1", "0.7.2")
    texts = {("Cargo.toml", "base"): cc.TOML, ("Cargo.toml", "head"): good_toml,
             ("Cargo.lock", "base"): cc.LOCK, ("Cargo.lock", "head"): good_lock}
    fetch = lambda path, which: texts[(path, which)]  # noqa: E731
    pats = ["packaging/**", "man/**", "Cargo.toml", "Cargo.lock"]

    def run(files: list[str], fetcher=fetch) -> tuple[bool, str]:
        return relevant({f: dict(entry) for f in files}, pats, fetcher)

    assert run(["README.md", "Cargo.toml", "Cargo.lock"])[0] is False, "docs + a bare bump: nothing to check"
    assert "ignored" in run(["README.md", "Cargo.toml", "Cargo.lock"])[1]
    assert run(["README.md"])[0] is False
    assert run(["README.md", "packaging/x.spec", "Cargo.toml", "Cargo.lock"])[0] is True, "a matching file beside a bump runs"
    assert run(["man/dog.1.md"])[0] is True
    assert run(["packaging/aur/PKGBUILD.in"])[0] is True

    # Negative controls: the bump is NOT ignored unless proved, so the files match their patterns.
    texts[("Cargo.toml", "head")] = good_toml.replace("A DNS client", "A better client")
    assert run(["README.md", "Cargo.toml", "Cargo.lock"])[0] is True, "a description edit in Cargo.toml must run"
    texts[("Cargo.toml", "head")] = good_toml
    assert run(["README.md", "Cargo.toml"])[0] is True, "Cargo.toml bumped alone, no lock: not a proved bump"

    def boom(path, which):
        raise RuntimeError("api down")
    assert run(["README.md", "Cargo.toml", "Cargo.lock"], boom)[0] is True, "a fetch failure must run it"
    only = run(["Cargo.toml", "Cargo.lock"])
    assert only[0] is True and "only the version changed" in only[1], only
    assert relevant({"README.md": entry}, [], fetch)[0] is True, "no patterns: fail closed"

    # Not a pull request, or any doubt: run.
    wf = Path("/nonexistent")
    assert decide("push", "o/r", "", wf)[0] and decide("schedule", "o/r", "", wf)[0] and decide("workflow_dispatch", "o/r", "", wf)[0]
    assert decide("pull_request", "o/r", "", wf)[0]
    assert decide("pull_request", "o/r", "1", wf)[0], "an unreadable workflow must run"
    print("self-test passed")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if len(args) != 1:
        print("usage: path_filter.py <workflow file> | --self-test", file=sys.stderr)
        return 2
    run, why = decide(os.environ.get("EVENT_NAME", ""), os.environ.get("GH_REPO", ""),
                      os.environ.get("PR_NUMBER", ""), Path(args[0]))
    print(f"run={str(run).lower()}: {why}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"run={str(run).lower()}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
