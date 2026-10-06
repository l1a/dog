#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Set the GitHub About box and topics from packaging/metadata.toml.

    github_metadata.py            # print what would change; change nothing
    github_metadata.py --apply    # print it, ask, then change it
    github_metadata.py --self-test

The About box and the topics live on GitHub, not in any file a release carries, so nothing else
keeps them in step with the description written in packaging/metadata.toml. This does, and it
sets the topics as an EXACT list: one removed from metadata.toml is removed from the repository.
It is public and immediate, so it shows the change first and asks.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = "l1a/dog"
META = Path(__file__).resolve().parent.parent / "packaging" / "metadata.toml"


def plan(current: dict, wanted: dict) -> dict:
    """What has to change to turn `current` into `wanted`. Empty values mean nothing to do."""
    have, want = set(current["topics"]), set(wanted["topics"])
    return {
        "description": wanted["description"] if current["description"] != wanted["description"] else None,
        "add": sorted(want - have),
        "remove": sorted(have - want),
    }


def is_empty(p: dict) -> bool:
    return p["description"] is None and not p["add"] and not p["remove"]


def topic_names(raw) -> list[str]:
    """Topic names from `gh repo view --json repositoryTopics`, which is `null` for none and, depending on
    the gh version, a list of {"name": ...} or of {"topic": {"name": ...}}. Accept both."""
    names = []
    for item in raw or []:
        name = item.get("name") or (item.get("topic") or {}).get("name")
        if name:
            names.append(name)
    return names


def current_state() -> dict:
    out = subprocess.run(
        ["gh", "repo", "view", REPO, "--json", "description,repositoryTopics"],
        text=True, capture_output=True,
    )
    if out.returncode != 0:
        raise RuntimeError(f"could not read {REPO}: {out.stderr.strip()}")
    data = json.loads(out.stdout)
    return {
        "description": data.get("description") or "",
        "topics": topic_names(data.get("repositoryTopics")),
    }


def apply(p: dict) -> None:
    args = ["gh", "repo", "edit", REPO]
    if p["description"] is not None:
        args += ["--description", p["description"]]
    if p["add"]:
        args += ["--add-topic", ",".join(p["add"])]
    if p["remove"]:
        args += ["--remove-topic", ",".join(p["remove"])]
    out = subprocess.run(args, text=True, capture_output=True)
    if out.returncode != 0:
        raise RuntimeError(f"gh repo edit failed: {out.stderr.strip()}")


def show(current: dict, p: dict) -> None:
    if p["description"] is not None:
        print(f"description:\n  now : {current['description']!r}\n  to  : {p['description']!r}")
    if p["add"]:
        print(f"topics to add   : {', '.join(p['add'])}")
    if p["remove"]:
        print(f"topics to remove: {', '.join(p['remove'])}")


def self_test() -> None:
    cur = {"description": "old", "topics": ["a", "b"]}
    assert plan(cur, {"description": "old", "topics": ["a", "b"]}) == {"description": None, "add": [], "remove": []}
    assert is_empty(plan(cur, {"description": "old", "topics": ["b", "a"]})), "topic order is irrelevant"
    p = plan(cur, {"description": "new", "topics": ["b", "c", "d"]})
    assert p == {"description": "new", "add": ["c", "d"], "remove": ["a"]}, p
    assert not is_empty(p)
    # An exact list: a topic that is no longer wanted is removed, not left behind.
    assert plan({"description": "x", "topics": ["gone"]}, {"description": "x", "topics": []})["remove"] == ["gone"]
    # An empty current state (a repository with no description and no topics, as this one was).
    assert plan({"description": "", "topics": []}, {"description": "d", "topics": ["t"]}) == {"description": "d", "add": ["t"], "remove": []}
    # Both shapes gh has used, and none.
    assert topic_names(None) == [] and topic_names([]) == []
    assert topic_names([{"name": "a"}, {"name": "b"}]) == ["a", "b"]
    assert topic_names([{"topic": {"name": "a"}}, {"topic": {"name": "b"}}]) == ["a", "b"]
    assert topic_names([{"unexpected": 1}, {"name": "c"}]) == ["c"], "an entry with no name is skipped, not a crash"
    print("self-test passed")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0
    wanted = tomllib.loads(META.read_text(encoding="utf-8"))["github"]
    try:
        current = current_state()
        p = plan(current, wanted)
        if is_empty(p):
            print(f"{REPO} already matches packaging/metadata.toml. Nothing to change.")
            return 0
        show(current, p)
        if "--apply" not in sys.argv:
            print("\nDry run: nothing changed. Re-run with --apply to change it.")
            return 0
        if input(f"\nThis is PUBLIC and IMMEDIATE on {REPO}. Apply? [y/N] ").strip().lower() != "y":
            print("aborted; nothing changed")
            return 1
        apply(p)
        print("done")
        return 0
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
