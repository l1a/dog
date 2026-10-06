#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Classify the files a pull request changes, so a docs-only PR can skip the full CI suite.

    ci_changes.py             # in CI: reads the environment, writes outputs for later jobs
    ci_changes.py --self-test

WHY THIS IS NOT A `paths:` FILTER. Branch protection requires the single `CI OK` job, and a
workflow filtered out by `paths:` never reports a status, so a docs-only PR would wait on a
required check forever. Instead ci.yml always runs, a `changes` job calls this script, and the
heavy jobs are skipped with `if:`. `CI OK` runs every time, recomputes this classification
itself (scripts/ci_gate.py) and checks that the jobs this change needs actually ran, so a
misclassification here cannot silently skip CI.

THE CLASSES
  docs-only   every changed file is documentation. Nothing is built or tested.
  man         a file under man/ changed. Only the `Man page` job runs: the page is rendered by
              pandoc, which is the one thing a man/ change can break.
  code        anything else, including Cargo.toml, Cargo.lock, src/, build.rs, scripts/,
              packaging/, and every workflow file. The full suite runs.

WHAT COUNTS AS DOCUMENTATION is deliberately narrow: Markdown at the repository root, LICENSE,
the screenshot, and the issue and PR templates. Markdown in a subdirectory is NOT docs: it can
be a build input (man/dog.1.md becomes the man page, packaging/**/*.md becomes the COPR project
page), so it takes the conservative path. Workflow files are never docs: a change to
.github/workflows/ci.yml must be tested by the CI it changes.

IT FAILS CLOSED. Anything that is not a pull request (a push to master, a release, a manual
run), an empty file list, a truncated file list, or any error fetching it, means `code`: the
full suite runs. The only way to skip CI is to prove, from the API's own file list, that every
file is documentation.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass

# Matched against the whole path (re.fullmatch), so `README.md` is docs and `src/README.md` is not.
DOC_PATTERNS = [
    re.compile(r"[^/]+\.md"),                         # Markdown at the repository root
    re.compile(r"LICENSE"),
    re.compile(r"dog-screenshot\.png"),
    re.compile(r"\.github/ISSUE_TEMPLATE/[^/]+"),
    re.compile(r"\.github/pull_request_template\.md"),
]
MAN_PATTERN = re.compile(r"man/.+")

# The API returns at most 3000 files for a pull request. A list that long may be truncated, and a
# truncated list cannot prove the change is docs-only.
API_FILE_LIMIT = 3000


@dataclass(frozen=True)
class Classification:
    code: bool        # the full suite (format, clippy, tests, man page) must run
    man: bool         # the man page job must run (true whenever `code` is)
    reason: str

    @property
    def docs_only(self) -> bool:
        return not self.code and not self.man


EVERYTHING = "the full suite runs"


def is_doc(path: str) -> bool:
    return any(p.fullmatch(path) for p in DOC_PATTERNS)


def classify(paths: list[str]) -> Classification:
    """The class of a change, from the paths it touches. An empty list fails closed."""
    if not paths:
        return Classification(True, True, "no changed files could be listed; " + EVERYTHING)
    non_doc = [p for p in paths if not is_doc(p)]
    code = [p for p in non_doc if not MAN_PATTERN.fullmatch(p)]
    if code:
        return Classification(True, True, f"{len(code)} non-docs file(s), e.g. {code[0]}")
    if non_doc:
        return Classification(False, True, f"only docs and man/ changed ({len(non_doc)} man/ file(s))")
    return Classification(False, False, f"only documentation changed ({len(paths)} file(s))")


def fail_closed(reason: str) -> Classification:
    return Classification(True, True, f"{reason}; {EVERYTHING}")


def gh_lines(*args: str) -> list[str]:
    out = subprocess.run(["gh", *args], text=True, capture_output=True)
    if out.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {out.stderr.strip() or out.returncode}")
    return [line for line in out.stdout.splitlines() if line]


def pr_paths(repo: str, number: str) -> list[str]:
    """Every path a PR touches. A rename contributes BOTH names: moving a code file to a docs
    path must not read as a docs-only change."""
    return gh_lines(
        "api", "--paginate", f"repos/{repo}/pulls/{number}/files?per_page=100",
        "--jq", ".[] | .filename, (.previous_filename // empty)",
    )


def decide(event: str, repo: str, number: str) -> Classification:
    """The classification for a CI run. Fails closed on every doubt."""
    if event != "pull_request":
        return fail_closed(f"event is {event or 'unknown'}, not a pull request")
    if not number:
        return fail_closed("no pull request number")
    try:
        paths = pr_paths(repo, number)
    except (RuntimeError, OSError) as e:
        return fail_closed(str(e))
    if len(paths) >= API_FILE_LIMIT:
        return fail_closed(f"{len(paths)} files: the list may be truncated")
    return classify(paths)


def self_test() -> None:
    """Prove the classifier can say `code`, not just `docs`."""
    docs = ["README.md", "CONTRIBUTING.md", "AGENTS.md", "CLAUDE.md", "LICENSE", "dog-screenshot.png",
            ".github/pull_request_template.md", ".github/ISSUE_TEMPLATE/bug_report.md"]
    for p in docs:
        assert is_doc(p), f"{p} should be documentation"
    # Narrow on purpose: none of these are docs.
    for p in ["src/main.rs", "Cargo.toml", "Cargo.lock", "build.rs", "Justfile", "man/dog.1.md",
              "packaging/copr/project-description.md", "scripts/ci_changes.py", "docs/guide.md",
              "src/README.md", ".github/workflows/ci.yml", ".github/dependabot.yml",
              "README.md.bak", "README.markdown", ".md", "xREADME.md/evil", ".github/ISSUE_TEMPLATE/x/y"]:
        assert not is_doc(p), f"{p} must NOT be documentation"

    assert classify(docs) == Classification(False, False, "only documentation changed (8 file(s))")
    assert classify(docs).docs_only
    assert classify(["README.md"]).docs_only

    # Any single non-docs file makes it `code`, however many docs sit beside it.
    assert classify(docs + ["src/main.rs"]).code
    assert classify(["README.md", "Cargo.lock"]).code
    assert classify([".github/workflows/ci.yml"]).code, "a change to CI must be tested by CI"
    assert classify(["scripts/ci_gate.py"]).code
    assert classify(["packaging/copr/project-description.md"]).code, "a build input, not docs"

    # man/ only needs the man page job.
    m = classify(["man/dog.1.md", "README.md"])
    assert (m.code, m.man) == (False, True), m
    assert classify(["man/dog.1.md", "src/main.rs"]).code

    # Fails closed.
    assert classify([]).code and classify([]).man
    assert fail_closed("boom").code
    assert decide("push", "o/r", "").code and decide("workflow_call", "o/r", "").code
    assert decide("pull_request", "o/r", "").code
    # An unreachable API must run everything, never skip it.
    saved = os.environ.get("PATH", "")
    try:
        os.environ["PATH"] = "/nonexistent"
        assert decide("pull_request", "o/r", "1").code, "an API failure must fail closed"
    finally:
        os.environ["PATH"] = saved
    print("self-test passed")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0

    result = decide(os.environ.get("EVENT_NAME", ""), os.environ.get("GH_REPO", ""), os.environ.get("PR_NUMBER", ""))
    print(f"code={str(result.code).lower()} man={str(result.man).lower()}: {result.reason}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"code={str(result.code).lower()}\nman={str(result.man).lower()}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
