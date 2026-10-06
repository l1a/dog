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

THE VERSION BUMP DOES NOT COUNT. Every pull request must bump the version (version_gate.py), which
edits Cargo.toml and Cargo.lock, and both are `code`, so without this a docs-only PR would run the
full suite and the fast path could never be taken by a PR that follows the rules. A bump is
ignored ONLY when it is proved to be nothing but a bump: Cargo.toml and Cargo.lock are both
fetched at the merge base and at the head, and each must differ in exactly one line, that line
must be `version = "..."`, and parsing the TOML must show that the line is dogdns's own version,
the same old -> new in both files. Any other edit to either file (a dependency, a description, a
comment, a rename), one file bumped without the other, or any fetch or parse problem leaves them
counted as `code`. A PR that changes only the version files is still `code`: nothing remains to
prove it docs-only.

IT FAILS CLOSED. Anything that is not a pull request (a push to master, a release, a manual
run), an empty file list, a truncated file list, or any error fetching it, means `code`: the
full suite runs. The only way to skip CI is to prove, from the API's own file list, that every
file is documentation.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from typing import Callable

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


def gh_text(*args: str) -> str:
    out = subprocess.run(["gh", *args], text=True, capture_output=True)
    if out.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {out.stderr.strip() or out.returncode}")
    return out.stdout


# ---- the version bump -------------------------------------------------------------------------

VERSION_FILES = ("Cargo.toml", "Cargo.lock")
VERSION_LINE = re.compile(r'version = "([^"]+)"')


def own_version(kind: str, text: str) -> str | None:
    """dogdns's own version as TOML says it, or None."""
    data = tomllib.loads(text)
    if kind == "Cargo.toml":
        return data.get("package", {}).get("version")
    own = [p for p in data.get("package", []) if p.get("name") == "dogdns"]
    return own[0].get("version") if len(own) == 1 else None


def version_only_change(kind: str, old: str, new: str) -> tuple[str, str] | None:
    """(old version, new version) if `new` is `old` with exactly one line changed and that line is
    dogdns's own `version = "..."`; otherwise None."""
    old_lines, new_lines = old.splitlines(), new.splitlines()
    changed = [op for op in difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False).get_opcodes()
               if op[0] != "equal"]
    if len(changed) != 1:
        return None
    tag, i1, i2, j1, j2 = changed[0]
    if tag != "replace" or i2 - i1 != 1 or j2 - j1 != 1:
        return None
    before, after = VERSION_LINE.fullmatch(old_lines[i1]), VERSION_LINE.fullmatch(new_lines[j1])
    if not before or not after or before.group(1) == after.group(1):
        return None
    # The changed line is *a* version line; TOML must say it is *the package's* version.
    if own_version(kind, old) != before.group(1) or own_version(kind, new) != after.group(1):
        return None
    return before.group(1), after.group(1)


def version_bump(files: dict[str, dict], fetch: Callable[[str, str], str]) -> tuple[str, str] | None:
    """(old, new) when the PR's edits to Cargo.toml and Cargo.lock are a bare version bump, the same
    in both. `files` maps a changed path to its API entry; `fetch(path, "base" | "head")` returns the
    file's text at the merge base or at the head. None means do not ignore them."""
    if not all(name in files for name in VERSION_FILES):
        return None
    if any(files[name].get("status") != "modified" or files[name].get("previous_filename") for name in VERSION_FILES):
        return None
    try:
        found = {name: version_only_change(name, fetch(name, "base"), fetch(name, "head")) for name in VERSION_FILES}
    except (RuntimeError, OSError, ValueError, tomllib.TOMLDecodeError):
        return None
    toml, lock = found["Cargo.toml"], found["Cargo.lock"]
    return toml if toml is not None and toml == lock else None


def pr_files(repo: str, number: str) -> dict[str, dict]:
    """The API's entry for every file a PR touches, by path. A rename is keyed by BOTH names."""
    lines = gh_lines(
        "api", "--paginate", f"repos/{repo}/pulls/{number}/files?per_page=100",
        "--jq", r".[] | {filename, previous_filename, status} | @json",
    )
    files: dict[str, dict] = {}
    for line in lines:
        entry = json.loads(line)
        files[entry["filename"]] = entry
        if entry.get("previous_filename"):
            files[entry["previous_filename"]] = entry
    return files


def pr_fetcher(repo: str, number: str) -> Callable[[str, str], str]:
    """`fetch(path, "base" | "head")` for a PR: the merge base, not the base branch's tip, because the
    files API diffs against the merge base."""
    shas: dict[str, str] = {}

    def fetch(path: str, which: str) -> str:
        if not shas:
            head = gh_text("api", f"repos/{repo}/pulls/{number}", "--jq", ".head.sha").strip()
            base = gh_text("api", f"repos/{repo}/pulls/{number}", "--jq", ".base.sha").strip()
            merge_base = gh_text("api", f"repos/{repo}/compare/{base}...{head}", "--jq", ".merge_base_commit.sha").strip()
            if not (head and merge_base):
                raise RuntimeError("could not find the merge base")
            shas.update(head=head, base=merge_base)
        return gh_text("api", "-H", "Accept: application/vnd.github.raw", f"repos/{repo}/contents/{path}?ref={shas[which]}")

    return fetch


def decide(event: str, repo: str, number: str) -> Classification:
    """The classification for a CI run. Fails closed on every doubt."""
    if event != "pull_request":
        return fail_closed(f"event is {event or 'unknown'}, not a pull request")
    if not number:
        return fail_closed("no pull request number")
    try:
        files = pr_files(repo, number)
        if len(files) >= API_FILE_LIMIT:
            return fail_closed(f"{len(files)} files: the list may be truncated")
        return classify_pr(files, pr_fetcher(repo, number))
    except (RuntimeError, OSError, ValueError) as e:
        return fail_closed(str(e))


def classify_pr(files: dict[str, dict], fetch: Callable[[str, str], str]) -> Classification:
    """`classify`, with a proved bare version bump left out of the file list."""
    paths = list(files)
    bump = version_bump(files, fetch)
    if bump is None:
        return classify(paths)
    rest = [p for p in paths if p not in VERSION_FILES]
    if not rest:
        return Classification(True, True, f"only the version changed ({bump[0]} -> {bump[1]}); {EVERYTHING}")
    result = classify(rest)
    return Classification(result.code, result.man, f"{result.reason}; the version bump {bump[0]} -> {bump[1]} is ignored")


TOML = """[package]
name = "dogdns"
description = "A DNS client"
version = "0.7.1"

[dependencies]
clap = { version = "4", features = ["derive"] }

[dependencies.other]
version = "1.0"
"""
LOCK = """version = 4

[[package]]
name = "clap"
version = "4.0.0"

[[package]]
name = "other"
version = "1.0"

[[package]]
name = "dogdns"
version = "0.7.1"
dependencies = [
 "clap",
]
"""


def bumped(text: str, old: str, new: str, nth: int = 0) -> str:
    """`text` with the nth occurrence of `version = "old"` changed to `new`."""
    needle = f'version = "{old}"'
    at = -1
    for _ in range(nth + 1):
        at = text.index(needle, at + 1)
    return text[:at] + f'version = "{new}"' + text[at + len(needle):]


def version_self_test() -> None:
    """The version bump is ignored only when it is provably nothing but a bump."""
    def run(toml_head: str, lock_head: str, files=None) -> Classification:
        texts = {("Cargo.toml", "base"): TOML, ("Cargo.toml", "head"): toml_head,
                 ("Cargo.lock", "base"): LOCK, ("Cargo.lock", "head"): lock_head}
        entry = {"status": "modified"}
        listed = files if files is not None else {n: dict(entry) for n in VERSION_FILES}
        listed = {**listed, "README.md": dict(entry)}
        return classify_pr(listed, lambda path, which: texts[(path, which)])

    good_toml, good_lock = bumped(TOML, "0.7.1", "0.7.2"), bumped(LOCK, "0.7.1", "0.7.2")
    r = run(good_toml, good_lock)
    assert r.docs_only and "0.7.1 -> 0.7.2" in r.reason, r

    # A bump of a MINOR or the like is still a bump.
    assert run(bumped(TOML, "0.7.1", "0.8.0"), bumped(LOCK, "0.7.1", "0.8.0")).docs_only

    def code(r: Classification, needle: str) -> None:
        assert r.code and needle in r.reason, r

    # Negative controls: each of these must stay `code`, and say why it did.
    code(run(good_toml, LOCK), "Cargo.toml")                                       # lock not bumped
    code(run(TOML, good_lock), "Cargo.toml")                                       # toml not bumped
    code(run(good_toml, bumped(LOCK, "0.7.1", "0.7.3")), "Cargo.toml")             # different versions
    code(run(good_toml.replace("A DNS client", "A better client"), good_lock), "Cargo.toml")  # + a description
    code(run(good_toml + "# a comment\n", good_lock), "Cargo.toml")                 # + a comment
    code(run(bumped(TOML, "1.0", "2.0"), LOCK), "Cargo.toml")                      # a DEPENDENCY's version line
    # A DEPENDENCY's version line changed identically in both files: one changed line each, both
    # `version = "..."`, the same old -> new, yet not the package's own version.
    code(run(bumped(TOML, "1.0", "1.1"), bumped(LOCK, "1.0", "1.1")), "Cargo.toml")
    code(run(bumped(TOML, "0.7.1", "0.7.2").replace('clap = { version = "4"', 'clap = { version = "5"'), good_lock), "Cargo.toml")
    code(run(good_toml, bumped(LOCK, "4.0.0", "4.0.1")), "Cargo.toml")             # lock: another package
    code(run(good_toml, good_lock.replace('"clap",', '"clap",\n "serde",')), "Cargo.toml")  # lock: dependency list
    code(run(TOML, LOCK), "Cargo.toml")                                            # no change at all
    code(run(good_toml, good_lock, {"Cargo.toml": {"status": "modified"}}), "Cargo.toml")   # lock not in the PR
    code(run(good_toml, good_lock, {"Cargo.toml": {"status": "modified"},
                                     "Cargo.lock": {"status": "renamed", "previous_filename": "old.lock"}}), "Cargo.toml")
    code(run(good_toml, good_lock, {"Cargo.toml": {"status": "added"}, "Cargo.lock": {"status": "modified"}}), "Cargo.toml")
    code(run(good_toml, "not [ toml"), "Cargo.toml")                               # unparsable
    # A fetch failure leaves the files counted as code, never as ignored.
    def boom(path, which):
        raise RuntimeError("api down")
    entry = {"status": "modified"}
    code(classify_pr({"Cargo.toml": entry, "Cargo.lock": entry, "README.md": entry}, boom), "Cargo.toml")
    # A real code file beside a proved bump is still code.
    mixed = classify_pr({"Cargo.toml": entry, "Cargo.lock": entry, "src/main.rs": entry},
                        lambda path, which: {("Cargo.toml", "base"): TOML, ("Cargo.toml", "head"): good_toml,
                                             ("Cargo.lock", "base"): LOCK, ("Cargo.lock", "head"): good_lock}[(path, which)])
    code(mixed, "src/main.rs")
    # man/ beside a bump needs only the man page job.
    man = classify_pr({"Cargo.toml": entry, "Cargo.lock": entry, "man/dog.1.md": entry},
                      lambda path, which: {("Cargo.toml", "base"): TOML, ("Cargo.toml", "head"): good_toml,
                                           ("Cargo.lock", "base"): LOCK, ("Cargo.lock", "head"): good_lock}[(path, which)])
    assert (man.code, man.man) == (False, True), man
    # A bump and nothing else is not docs-only: there is nothing to prove it is.
    alone = classify_pr({"Cargo.toml": entry, "Cargo.lock": entry},
                        lambda path, which: {("Cargo.toml", "base"): TOML, ("Cargo.toml", "head"): good_toml,
                                             ("Cargo.lock", "base"): LOCK, ("Cargo.lock", "head"): good_lock}[(path, which)])
    assert alone.code and "only the version changed" in alone.reason, alone


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

    version_self_test()

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
