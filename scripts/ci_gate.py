#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""The `CI OK` gate: verify that the jobs this change NEEDS ran, and that every job succeeded.

    ci_gate.py             # in CI: reads the environment
    ci_gate.py --self-test

Branch protection requires only `CI OK`, so this is the one place a red or missing check is
caught. It asks the API what every job in the run ACTUALLY concluded and does not trust
`needs.*.result` alone, because a job cancelled in the runner queue reports `abandoned`, which
the original gate did not recognise, so it passed a run whose jobs had all been cancelled
(GitHub Actions outage, 2026-10-05).

WHAT IS EXPECTED depends on the change (scripts/ci_changes.py classifies it, and this script
recomputes that itself rather than trusting the `changes` job):

    class        Format and Clippy   Test (...)   Man page
    code         must succeed        must succeed must succeed
    man          may be skipped      may be skipped  must succeed
    docs-only    may be skipped      may be skipped  may be skipped

"May be skipped" means `skipped` or `success`; anything else (failure, cancelled, abandoned, not
run at all) fails. "Must succeed" means exactly `success`: a job that a code change needs and
that was SKIPPED fails, because that is how a misclassification would hide.

It fails CLOSED. An API error, a job group that is missing from the run, a `changes` job that did
not succeed, and any result it does not recognise all fail the gate.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_changes as cc  # noqa: E402

# When another workflow calls this one, GitHub prefixes the job names ("CI / Test (...)").
GROUPS = {
    "lints": re.compile(r"(^| / )Format and Clippy$"),
    "tests": re.compile(r"(^| / )Test \(.*\)$"),
    "man": re.compile(r"(^| / )Man page$"),
}
# The job ids in ci.yml, which is what `needs.<id>.result` is keyed by.
NEEDS_ID = {"lints": "lints", "tests": "test", "man": "man"}


@dataclass(frozen=True)
class Expect:
    lints: bool
    tests: bool
    man: bool


def expectation(c: cc.Classification) -> Expect:
    return Expect(lints=c.code, tests=c.code, man=c.man)


def _allowed(expected: bool) -> set[str]:
    return {"success"} if expected else {"success", "skipped"}


def _why(result: str, expected: bool) -> str:
    return " (skipped, but this change needs it)" if expected and result == "skipped" else ""


def problems(jobs: list[tuple[str, str]], needs: dict[str, str], expect: Expect) -> list[str]:
    """Everything wrong with this run. Empty means CI is genuinely green for this change."""
    found = []

    # `needs` is a second signal, kept strict: anything unrecognised fails.
    if needs.get("changes") != "success":
        found.append(f"the change-detection job ended as '{needs.get('changes', 'missing')}', not 'success'")
    for group in GROUPS:
        key = NEEDS_ID[group]
        expected = getattr(expect, group)
        result = needs.get(key)
        if result is None:
            found.append(f"needs.{key} is missing")
        elif result not in _allowed(expected):
            found.append(f"{key} ended as '{result}'{_why(result, expected)}")

    # The API is the authority on what each job concluded.
    for group, rx in GROUPS.items():
        expected = getattr(expect, group)
        members = [(name, conclusion) for name, conclusion in jobs if rx.search(name)]
        if not members:
            found.append(f"no {group} job found in this run")
        for name, conclusion in members:
            if conclusion not in _allowed(expected):
                found.append(f"{name} concluded {conclusion}{_why(conclusion, expected)}")
    return found


def fetch_jobs(repo: str, run_id: str) -> list[tuple[str, str]]:
    lines = cc.gh_lines(
        "api", "--paginate", f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100",
        "--jq", r".jobs[] | [.name, (.conclusion // .status)] | @tsv",
    )
    jobs = []
    for line in lines:
        name, _, conclusion = line.rpartition("\t")
        jobs.append((name, conclusion))
    return jobs


def needs_results(raw: str) -> dict[str, str]:
    """{job id: result} from `toJSON(needs)`."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        raise RuntimeError("NEEDS_JSON is not valid JSON")
    return {key: value.get("result", "") for key, value in data.items() if isinstance(value, dict)}


def claimed(raw: str) -> tuple[str, str]:
    """What the `changes` job said, for the log: (code, man)."""
    try:
        outputs = json.loads(raw).get("changes", {}).get("outputs", {})
    except (json.JSONDecodeError, TypeError, AttributeError):
        return "?", "?"
    return outputs.get("code", "?"), outputs.get("man", "?")


def self_test() -> None:
    """Prove the gate can FAIL. The first cases are the real incident."""
    ok = {"changes": "success", "lints": "success", "test": "success", "man": "success"}
    code = Expect(True, True, True)
    man_only = Expect(False, False, True)
    docs = Expect(False, False, False)

    def jobs(lints="success", tests="success", man="success", prefix=""):
        return [
            (f"{prefix}Format and Clippy", lints), (f"{prefix}Man page", man),
            (f"{prefix}Test (linux-x86_64)", tests), (f"{prefix}Test (macos-aarch64)", tests),
            (f"{prefix}Test (windows-x86_64)", tests), (f"{prefix}Test (fedora-x86_64)", tests),
            (f"{prefix}Test (linux-aarch64)", tests), (f"{prefix}Test (windows-aarch64)", tests),
            (f"{prefix}CI OK", "success"), (f"{prefix}Detect changed files", "success"),
        ]

    # A code change with everything green passes, with or without the caller's "CI / " prefix.
    assert problems(jobs(), ok, code) == []
    assert problems(jobs(prefix="CI / "), ok, code) == []

    # THE 2026-10-05 INCIDENT: three jobs cancelled in the queue; `needs` said `abandoned`, and the old gate
    # only knew `cancelled`. Both signals must catch it, separately.
    incident_needs = {"changes": "success", "lints": "abandoned", "test": "success", "man": "abandoned"}
    p = problems(jobs(lints="cancelled", man="cancelled"), incident_needs, code)
    assert any("Format and Clippy concluded cancelled" in x for x in p) and any("abandoned" in x for x in p), p
    assert problems(jobs(lints="cancelled", man="cancelled"), ok, code), "the API check alone must catch it"
    assert problems(jobs(), incident_needs, code), "the needs check alone must catch it"

    # A code change must run everything: a SKIPPED job is how a misclassification would hide.
    skipped_needs = {"changes": "success", "lints": "skipped", "test": "skipped", "man": "skipped"}
    p = problems(jobs("skipped", "skipped", "skipped"), skipped_needs, code)
    assert any("skipped, but this change needs it" in x for x in p), p

    # Docs-only: skipped is correct, and a job that ran anyway is fine.
    assert problems(jobs("skipped", "skipped", "skipped"), skipped_needs, docs) == []
    assert problems(jobs(), ok, docs) == []
    # ...but a docs-only change must still not have FAILED jobs.
    assert problems(jobs(tests="failure"), ok, docs) != []

    # man/ only: the man page must succeed, the rest may be skipped.
    man_needs = {"changes": "success", "lints": "skipped", "test": "skipped", "man": "success"}
    assert problems(jobs("skipped", "skipped", "success"), man_needs, man_only) == []
    assert problems(jobs("skipped", "skipped", "skipped"), skipped_needs, man_only) != []
    assert problems(jobs("skipped", "skipped", "failure"), man_needs, man_only) != []

    # Fails closed: change detection did not succeed, a group is missing, or a result is unknown.
    assert problems(jobs(), {**ok, "changes": "failure"}, code) != []
    assert problems(jobs(), {k: v for k, v in ok.items() if k != "changes"}, code) != []
    assert problems([j for j in jobs() if not j[0].startswith("Man")], ok, code) != []
    assert problems([j for j in jobs() if not j[0].startswith("Test")], ok, docs) != [], "a missing group fails even when docs-only"
    assert problems(jobs(), {**ok, "lints": "weird"}, code) != []
    assert problems([], ok, code) != []

    # The classification maps onto the expectation as documented.
    assert expectation(cc.classify(["src/main.rs"])) == code
    assert expectation(cc.classify(["man/dog.1.md"])) == man_only
    assert expectation(cc.classify(["README.md"])) == docs
    assert expectation(cc.fail_closed("x")) == code

    assert needs_results('{"changes":{"result":"success","outputs":{"code":"true"}},"lints":{"result":"skipped"}}') == {"changes": "success", "lints": "skipped"}
    assert claimed('{"changes":{"outputs":{"code":"false","man":"false"}}}') == ("false", "false")
    try:
        needs_results("not json")
    except RuntimeError:
        pass
    else:
        raise AssertionError("needs_results accepted garbage")
    print("self-test passed")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0

    repo = os.environ.get("GH_REPO", "")
    run_id = os.environ.get("RUN_ID", "")
    raw_needs = os.environ.get("NEEDS_JSON", "")
    try:
        needs = needs_results(raw_needs)
        classification = cc.decide(os.environ.get("EVENT_NAME", ""), repo, os.environ.get("PR_NUMBER", ""))
        jobs = fetch_jobs(repo, run_id)
    except RuntimeError as e:
        print(f"::error::cannot verify this run: {e}")
        return 1

    expect = expectation(classification)
    said_code, said_man = claimed(raw_needs)
    print(f"change class: code={classification.code} man={classification.man} ({classification.reason})")
    print(f"the changes job said: code={said_code} man={said_man}")
    print(f"needs results: {needs}")
    print("jobs in this run:")
    for name, conclusion in jobs:
        print(f"  {name}: {conclusion}")

    found = problems(jobs, needs, expect)
    if classification.code and said_code == "false":
        found.append("the changes job classified this as not needing the full suite, but it does")
    for p in found:
        print(f"::error::{p}")
    if found:
        return 1
    ran = [g for g in ("lints", "tests", "man") if getattr(expect, g)]
    print(f"CI is green: {', '.join(ran) or 'no jobs were needed (docs only)'} verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
