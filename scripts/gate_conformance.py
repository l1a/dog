#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 l1a
"""Assert the pr / open-pr / merge-pr triad still carries its required guards.

TEMPLATE v4 — vendored verbatim in rusticprofile, retch and etr. Change it here, bump
TEMPLATE_VERSION, and propagate in each repo's own PR. Run by `just standard-check`.

WHAT THIS IS, AND HONESTLY WHAT IT IS NOT
-----------------------------------------
This is a **structural** check. It reads the justfile and asserts each guard is present.
It does NOT prove the guards work — a recipe could satisfy every assertion here and still
be wrong.

That limitation is deliberate rather than lazy, and the reason is worth stating: the install
helpers could be checked behaviourally because their logic is pure functions over a path and
an environment, so `--self-test` can call them. The gate recipes are not: `pr` runs the whole
test suite, regenerates the man page and touches git; `open-pr` pushes and opens a PR;
`merge-pr` merges. Executing them from a `check` dependency would be slow, side-effecting and
occasionally destructive. So this checks that the guards are *there*, and the guards
themselves are exercised for real on every PR — which is the strongest thing available
without making `just check` open pull requests.

It would have caught every one of the drift items found by hand in August 2026:
PR_CONFIRM missing in two repos, open-pr not pushing in one, and merge-pr having no CI gate
at all in two.

WHY THESE RECIPES ARE NOT SHARED VERBATIM LIKE THE INSTALL FAMILY
-----------------------------------------------------------------
They legitimately differ: `cargo clippy` is bare in rusticprofile, `--workspace` in retch and
`--all-targets` in etr; the NOTES header is `## Current State (vX)` in two and
`## Current state: vX` in the third; retch's checklist has wiki and tldr items, etr's has
PROTOCOL.md, rusticprofile's has neither. Forcing one body would mean changing what each gate
*does*, which is a behaviour change per repo rather than a copy. So what is standardised is
their **behaviour**, and this file is what stops that behaviour drifting apart again.
"""

import re
import sys
from pathlib import Path

TEMPLATE_VERSION = 4


def recipe_body(text, name):
    """The lines of one recipe, from its header to the next top-level construct.

    Deliberately not a YAML/justfile parser: a recipe body is every line after the header
    that is indented or blank, which is the one structural rule just guarantees.
    """
    lines = text.splitlines()
    start = None
    for i, l in enumerate(lines):
        if re.match(rf"^{re.escape(name)}(\s+[*+]?\w+.*)?:", l):
            start = i
            break
    if start is None:
        return None
    body = []
    for l in lines[start + 1:]:
        if l.strip() and not l.startswith((" ", "\t")):
            break
        body.append(l)
    return "\n".join(body)


def code_of(body):
    """Recipe body with comment-only lines removed.

    Load-bearing: every assertion below must run against CODE, never against prose. A comment
    explaining a guard would otherwise satisfy the check for a recipe that lost it — which is
    exactly how `if: false` inside a comment once read as an active guard during this work.
    """
    out = []
    for l in body.splitlines():
        s = l.strip()
        if s.startswith("#") or s.startswith("@#"):
            continue
        out.append(l)
    return "\n".join(out)


# (recipe, key, human description, predicate over the recipe's CODE)
RULES = [
    ("pr", "confirm-env",
     "`pr` READS PR_CONFIRM, so a script or agent can satisfy the gate. Naming it in help "
     "text is not honouring it -- the rule requires a parameter expansion.",
     lambda c: re.search(r"\$\{?PR_CONFIRM", c) is not None),
    ("pr", "confirm-refuses",
     "`pr` REFUSES rather than defaulting to yes when there is no terminal and no stdin",
     lambda c: re.search(r"PR_CONFIRM", c) and re.search(r"exit 1|fail ", c)),
    ("pr", "confirm-explicit-y",
     "`pr` still requires an explicit y — widening who can answer, not what counts",
     lambda c: re.search(r'CONFIRM"?\s*=\s*"?y', c, re.I) is not None),
    ("open-pr", "gate-first",
     "`open-pr` runs the gate before creating the PR",
     lambda c: re.search(r"just\s+pr\b", c) is not None),
    ("open-pr", "creates-pr",
     "`open-pr` is the call site that actually creates the PR",
     lambda c: "gh pr create" in c),
    ("open-pr", "push-if-no-upstream",
     "`open-pr` pushes when the branch has no upstream, and only then",
     lambda c: "@{upstream}" in c and re.search(r"git push", c) is not None),
    ("merge-pr", "refuse-red",
     "`merge-pr` refuses to merge over a failing check",
     lambda c: re.search(r"FAILURE|TIMED_OUT|CANCELLED", c) is not None),
    ("merge-pr", "refuse-empty",
     "`merge-pr` refuses an EMPTY status rollup — 'nothing ran' is not 'everything passed'",
     lambda c: re.search(r"statusCheckRollup", c) is not None
               and re.search(r"\[\]|empty|no checks", c, re.I) is not None),
    ("merge-pr", "refuse-pending",
     "`merge-pr` refuses while checks are still running rather than racing them",
     lambda c: re.search(r"still running|in progress|pending", c, re.I) is not None),
]


HEADER_RE = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_-]*)(\s+[^:]*)?:(?!=)")

# `<<WORD`, `<<'WORD'`, `<<"WORD"` and the `<<-` indent-stripping form.
HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def at_prefixed_lines_in_shebang_recipes(text):
    """Find `@`-prefixed lines inside `#!`-shebang recipe bodies. Returns [(name, lineno, line)].

    WHY THIS EXISTS -- it is the one rule here that was added after being paid for twice.

    In a PLAIN recipe a leading `@` tells just not to echo the line, and just strips it. In a
    SHEBANG recipe just strips nothing: the body is handed to the interpreter verbatim, so the
    `@` reaches the shell, which looks for a command literally named `@/usr/bin/python3` and
    exits 127.

    rusticprofile 0.2.2 fixed exactly this after a global regex put `@` in front of lines in
    `merge-pr`, `pr` and `aur-publish`. retch v0.17.13 fixed it again in `merge-pr`, in a
    session where that write-up had already been read. **A documented trap is not a guard**,
    which is this file's whole argument, so it is now a check.

    It is also the one rule that cannot be per-recipe: the mistake is about a recipe's SHAPE,
    not about the triad's behaviour, and it can land in any recipe at all.

    HEREDOCS ARE SKIPPED, and that is not a nicety. A `cat <<'MSG'` block inside a shebang
    recipe is DATA; a line of it beginning with `@` is a literal `@`, not a command. Without
    this the check fires on correct code, and a guard that fires on correct code is deleted
    within a week -- which would cost the real rule. Verified both ways in the self-test.
    """
    lines = text.splitlines()
    hits = []
    i = 0
    while i < len(lines):
        m = HEADER_RE.match(lines[i])
        if not m or ":=" in lines[i].split("#")[0]:
            i += 1
            continue
        name = m.group(1)
        body, j = [], i + 1
        while j < len(lines) and (not lines[j].strip() or lines[j].startswith((" ", "\t"))):
            body.append((j + 1, lines[j]))
            j += 1
        first = next((l for _, l in body if l.strip()), "")
        if first.strip().startswith("#!"):
            pending = None  # heredoc terminator currently open
            for lineno, l in body:
                if pending is not None:
                    if l.strip() == pending:
                        pending = None
                    continue
                hd = HEREDOC_RE.search(l)
                if hd:
                    pending = hd.group(2)
                    continue
                if l.strip().startswith("@"):
                    hits.append((name, lineno, l.strip()))
        i = j
    return hits


def check(justfile: Path):
    text = justfile.read_text(encoding="utf-8")
    failures = []
    for recipe, key, desc, pred in RULES:
        body = recipe_body(text, recipe)
        if body is None:
            failures.append((f"{recipe}:{key}", f"recipe `{recipe}` does not exist"))
            continue
        if not pred(code_of(body)):
            failures.append((f"{recipe}:{key}", desc))

    # Whole-file, not per-recipe: an `@` inside a shebang body can land in ANY recipe.
    for name, lineno, line in at_prefixed_lines_in_shebang_recipes(text):
        failures.append((
            f"{name}:{lineno}:at-in-shebang",
            f"`@` prefix inside a shebang recipe -- just does not strip it there, so the "
            f"shell gets a command literally named `@...` and exits 127. Drop the `@`. "
            f"Line: {line[:60]}"))
    return failures


CONFORMANT = """
pr:
    #!/usr/bin/env bash
    if [ -n "${PR_CONFIRM:-}" ]; then CONFIRM="$PR_CONFIRM"
    elif [ -t 0 ]; then read -r CONFIRM
    else read -r -t 10 CONFIRM || CONFIRM=""
         [ -n "$CONFIRM" ] || { echo "set PR_CONFIRM=y"; exit 1; }
    fi
    [ "$CONFIRM" = "y" ] || exit 1

open-pr *ARGS:
    #!/usr/bin/env bash
    just pr
    if ! git rev-parse '@{upstream}' >/dev/null 2>&1; then git push -u origin "$B"; fi
    gh pr create

merge-pr:
    #!/usr/bin/env bash
    STATES=$(gh pr view --json statusCheckRollup --jq '...')
    if [ "$STATES" = "[]" ]; then echo "no checks have reported"; exit 1; fi
    if echo "$STATES" | grep -q '""'; then echo "still running"; exit 1; fi
    if echo "$STATES" | grep -qE 'FAILURE|TIMED_OUT'; then exit 1; fi
    gh pr merge --squash
"""


def self_test():
    """Prove the checker passes a conformant justfile and FAILS each guard's removal.

    A conformance checker nobody has watched fail is exactly the thing it exists to catch, so
    every rule is verified to fire when its guard is deleted — not merely to be satisfied.
    """
    import tempfile
    problems = []

    with tempfile.TemporaryDirectory() as d:
        good = Path(d) / "Justfile"
        good.write_text(CONFORMANT, encoding="utf-8")
        got = check(good)
        if got:
            problems.append(f"  conformant fixture should pass, but failed: {[k for k, _ in got]}")

        # Removing any single guard must be caught by that guard's own rule.
        breaks = {
            "pr:confirm-env": ("PR_CONFIRM", "NOPE"),
            "open-pr:gate-first": ("just pr", "echo skipped"),
            "open-pr:creates-pr": ("gh pr create", "echo nope"),
            "open-pr:push-if-no-upstream": ("@{upstream}", "@{nothing}"),
            "merge-pr:refuse-red": ("FAILURE|TIMED_OUT", "NOTHING"),
            "merge-pr:refuse-empty": ("statusCheckRollup", "somethingElse"),
            "merge-pr:refuse-pending": ("still running", "quiet"),
        }
        for key, (needle, repl) in breaks.items():
            broken = Path(d) / "Broken"
            broken.write_text(CONFORMANT.replace(needle, repl), encoding="utf-8")
            keys = [k for k, _ in check(broken)]
            if key not in keys:
                problems.append(f"  removing {needle!r} should trip {key}, but tripped {keys}")

        # A comment must NOT satisfy a rule. This is the `if: false`-in-a-comment trap.
        commented = Path(d) / "Commented"
        commented.write_text(
            CONFORMANT.replace('if [ -n "${PR_CONFIRM:-}" ]; then CONFIRM="$PR_CONFIRM"',
                               '# PR_CONFIRM is handled elsewhere\n    if false; then CONFIRM=x'),
            encoding="utf-8")
        if "pr:confirm-env" not in [k for k, _ in check(commented)]:
            problems.append("  a COMMENT mentioning PR_CONFIRM satisfied pr:confirm-env")

        # A missing recipe must be a failure, not a pass by absence.
        missing = Path(d) / "Missing"
        missing.write_text(CONFORMANT.replace("open-pr *ARGS:", "unrelated:"), encoding="utf-8")
        if not any(k.startswith("open-pr") for k, _ in check(missing)):
            problems.append("  a MISSING open-pr recipe did not fail the check")

        # --- template v4: `@` inside a shebang recipe -------------------------------------
        # Four cases, because three of them are the ways this check could be WRONG rather
        # than the way it is right.

        # 1. It fires on the real defect. This is retch v0.17.12's actual line.
        at_bad = Path(d) / "AtBad"
        at_bad.write_text(CONFORMANT + '''
broken-recipe:
    #!/usr/bin/env bash
    set -euo pipefail
    @"{{PY}}" scripts/update_wip.py
''', encoding="utf-8")
        if not any(k.endswith("at-in-shebang") for k, _ in check(at_bad)):
            problems.append("  an `@` inside a shebang recipe was NOT caught")

        # 2. It does NOT fire on a PLAIN recipe, where `@` is correct and required.
        at_plain = Path(d) / "AtPlain"
        at_plain.write_text(CONFORMANT + '''
plain-recipe:
    @"{{PY}}" scripts/thing.py --self-test
''', encoding="utf-8")
        if any(k.endswith("at-in-shebang") for k, _ in check(at_plain)):
            problems.append("  `@` in a PLAIN recipe was wrongly flagged -- that form is correct")

        # 3. It does NOT fire on heredoc DATA. Without this the check fires on correct code,
        #    and a guard that fires on correct code gets deleted, taking the real rule with it.
        at_heredoc = Path(d) / "AtHeredoc"
        at_heredoc.write_text(CONFORMANT + '''
heredoc-recipe:
    #!/usr/bin/env bash
    cat > out.txt <<\'MSG\'
    @this is data, not a command
    MSG
    echo done
''', encoding="utf-8")
        if any(k.endswith("at-in-shebang") for k, _ in check(at_heredoc)):
            problems.append("  an `@` inside a HEREDOC was wrongly flagged as a command")

        # 4. ...but a real defect AFTER a heredoc is still caught. Skipping the heredoc must
        #    not swallow the rest of the recipe.
        at_after = Path(d) / "AtAfter"
        at_after.write_text(CONFORMANT + '''
after-heredoc:
    #!/usr/bin/env bash
    cat <<\'MSG\'
    @data
    MSG
    @"{{PY}}" thing.py
''', encoding="utf-8")
        if not any(k.endswith("at-in-shebang") for k, _ in check(at_after)):
            problems.append("  an `@` defect AFTER a heredoc was missed -- the skip over-ran")

    if problems:
        print(f"gate_conformance self-test FAILED (template v{TEMPLATE_VERSION}):", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"gate_conformance.py self-test passed (template v{TEMPLATE_VERSION})")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()

    args = [a for a in argv if not a.startswith("-")]
    here = Path(__file__).resolve().parent.parent
    candidates = [Path(args[0])] if args else [here / "Justfile", here / "justfile"]
    justfile = next((c for c in candidates if c.is_file()), None)
    if justfile is None:
        print(f"error: no justfile found (tried {[str(c) for c in candidates]})", file=sys.stderr)
        return 1

    failures = check(justfile)
    if failures:
        print(f"gate conformance FAILED for {justfile.name} "
              f"(template v{TEMPLATE_VERSION}):", file=sys.stderr)
        for key, desc in failures:
            print(f"  [{key}] {desc}", file=sys.stderr)
        print("", file=sys.stderr)
        print("  These guards are shared behaviour across rusticprofile, retch and etr. Each one", file=sys.stderr)
        print("  exists because it was missing once and something bad followed: a PR merged over", file=sys.stderr)
        print("  a red leg, a merge over a rollup nothing had reported into, a gate no script", file=sys.stderr)
        print("  could answer, an open-pr that printed 'Gate passed' and then failed.", file=sys.stderr)
        return 1
    print(f"gate conformance ok: pr / open-pr / merge-pr (template v{TEMPLATE_VERSION})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
