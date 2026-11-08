#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""The `CI OK` gate: verify that every CI job group ran and succeeded.

    ci_gate.py             # in CI: reads the environment
    ci_gate.py --self-test

Branch protection requires only `CI OK`, so this is the one place a red, skipped, or missing check
is caught. It asks the API what every job in the run ACTUALLY concluded and does not trust
`needs.*.result` alone, because a job cancelled in the runner queue reports `abandoned`, which
the original gate did not recognise, so it passed a run whose jobs had all been cancelled
(GitHub Actions outage, 2026-10-05).

Every group (`Format and Clippy`, `Test (...)`, `Man page`) must conclude `success`. It fails
CLOSED: an API error, a job group missing from the run, or any non-`success` result fails the gate.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

# When another workflow calls this one, GitHub prefixes the job names ("CI / Test (...)").
GROUPS = {
    "lints": re.compile(r"(^| / )Format and Clippy$"),
    "tests": re.compile(r"(^| / )Test \(.*\)$"),
    "man": re.compile(r"(^| / )Man page$"),
}
# The job ids in ci.yml, which is what `needs.<id>.result` is keyed by.
NEEDS_ID = {"lints": "lints", "tests": "test", "man": "man"}


def gh_lines(*args: str) -> list[str]:
    out = subprocess.run(["gh", *args], text=True, capture_output=True)
    if out.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:2])} failed: {out.stderr.strip()}")
    return [line for line in out.stdout.splitlines() if line]


def problems(jobs: list[tuple[str, str]], needs: dict[str, str]) -> list[str]:
    """Everything wrong with this run. Empty means CI is genuinely green."""
    found = []

    # `needs` is a second signal, kept strict: anything other than `success` fails.
    for group in GROUPS:
        key = NEEDS_ID[group]
        result = needs.get(key)
        if result is None:
            found.append(f"needs.{key} is missing")
        elif result != "success":
            found.append(f"{key} ended as '{result}'")

    # The API is the authority on what each job concluded.
    for group, rx in GROUPS.items():
        members = [(name, conclusion) for name, conclusion in jobs if rx.search(name)]
        if not members:
            found.append(f"no {group} job found in this run")
        for name, conclusion in members:
            if conclusion != "success":
                found.append(f"{name} concluded {conclusion}")
    return found


def fetch_jobs(repo: str, run_id: str) -> list[tuple[str, str]]:
    lines = gh_lines(
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
    except (json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError("NEEDS_JSON is not valid JSON") from exc
    if not isinstance(data, dict):
        raise RuntimeError("NEEDS_JSON must be a JSON object")
    return {key: value.get("result", "") for key, value in data.items() if isinstance(value, dict)}


def self_test() -> None:
    """Prove the gate can FAIL. The first cases are the real incident."""
    ok = {"lints": "success", "test": "success", "man": "success"}

    def jobs(lints="success", tests="success", man="success", prefix=""):
        return [
            (f"{prefix}Format and Clippy", lints), (f"{prefix}Man page", man),
            (f"{prefix}Test (linux-x86_64)", tests), (f"{prefix}Test (macos-aarch64)", tests),
            (f"{prefix}Test (windows-x86_64)", tests), (f"{prefix}Test (fedora-x86_64)", tests),
            (f"{prefix}Test (linux-aarch64)", tests), (f"{prefix}Test (windows-aarch64)", tests),
            (f"{prefix}CI OK", "success"),
        ]

    # Everything green passes, with or without the caller's "CI / " prefix.
    assert problems(jobs(), ok) == []
    assert problems(jobs(prefix="CI / "), ok) == []

    # THE 2026-10-05 INCIDENT: jobs cancelled in the queue; `needs` said `abandoned`, and the old
    # gate only knew `cancelled`. Both signals must catch it, separately.
    incident_needs = {"lints": "abandoned", "test": "success", "man": "abandoned"}
    p = problems(jobs(lints="cancelled", man="cancelled"), incident_needs)
    assert any("Format and Clippy concluded cancelled" in x for x in p) and any("abandoned" in x for x in p), p
    assert problems(jobs(lints="cancelled", man="cancelled"), ok), "the API check alone must catch it"
    assert problems(jobs(), incident_needs), "the needs check alone must catch it"

    # A skipped job must fail.
    skipped_needs = {"lints": "skipped", "test": "skipped", "man": "skipped"}
    assert problems(jobs("skipped", "skipped", "skipped"), skipped_needs) != []

    # Fails closed: a group is missing, or a result is unknown/failed.
    assert problems(jobs(), {k: v for k, v in ok.items() if k != "man"}) != []
    assert problems([j for j in jobs() if not j[0].startswith("Man")], ok) != []
    assert problems([j for j in jobs() if not j[0].startswith("Test")], ok) != []
    assert problems(jobs(), {**ok, "lints": "weird"}) != []
    assert problems(jobs(tests="failure"), ok) != []
    assert problems([], ok) != []

    assert needs_results('{"lints":{"result":"success"},"test":{"result":"skipped"}}') == {
        "lints": "success",
        "test": "skipped",
    }
    for bad in ("not json", "[]"):
        try:
            needs_results(bad)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"needs_results accepted {bad!r}")
    print("ci_gate.py self-test passed")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0

    repo = os.environ.get("GH_REPO", "")
    run_id = os.environ.get("RUN_ID", "")
    raw_needs = os.environ.get("NEEDS_JSON", "")
    try:
        needs = needs_results(raw_needs)
        jobs = fetch_jobs(repo, run_id)
    except RuntimeError as e:
        print(f"::error::cannot verify this run: {e}")
        return 1

    print(f"needs results: {needs}")
    print("jobs in this run:")
    for name, conclusion in jobs:
        print(f"  {name}: {conclusion}")

    found = problems(jobs, needs)
    for p in found:
        print(f"::error::{p}")
    if found:
        return 1
    print("CI is green: lints, tests, and man verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
