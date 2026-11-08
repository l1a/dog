# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 l1a
#
# ============================================================================
# CANONICAL COMMON JUSTFILE BLOCK — template v6
# ============================================================================
#
# The text below `---- BEGIN CANONICAL ----` is the reference for the block
# delimited by `# >>> COMMON (template v6)` and `# <<< COMMON` in a project's
# Justfile. Vendored in: rusticprofile, retch, etr.
#
# It is a THIN layer. The real work lives in two vendored Python helpers,
# `scripts/install_completions.py` and `scripts/install_man.py`, which carry
# their own rationale and their own `--self-test`.
#
#
# WHY `install-man` DOES NOT BUILD THE PAGE  (v6)
# ----------------------------------------------------------------------------
# Through v5 `install-man` depended on `man`, so `just install` rebuilt every page
# before installing it. That made mandown -- a tool for WRITING the page -- a
# prerequisite for INSTALLING the program: in a fresh retch clone without it,
# `just install` failed with `'mandown' executable not found` before `cargo install`
# ever ran. And where mandown was present it rewrote a tracked file in the user's
# checkout (the page's date footer moves every month).
#
# The dependency was only ever needed while a page was not committed. etr built its
# pages into a gitignored `man/build/` until its #72 (2026-09-13); since then all
# three repos commit their pages, and each one's gate refuses a stale page, so the
# committed page IS the current page. Found by retch v0.17.17, which had to document
# mandown as a prerequisite of `just install` before this removed it.
#
# `install_man.py` still skips a page that is not tracked at a TAG, because
# `install-tag` can install an etr release from before #72.
#
#
# WHY `@` IS REFUSED INSIDE A SHEBANG RECIPE  (v5 added the guard)
# ----------------------------------------------------------------------------
# In a PLAIN recipe a leading `@` tells just not to echo the line, and just strips
# it. In a SHEBANG recipe just strips NOTHING — the body goes to the interpreter
# verbatim — so the `@` reaches the shell, which looks for a command literally
# named `@/usr/bin/python3` and exits 127.
#
# `scripts/gate_conformance.py` now refuses that shape in ANY recipe, not just the
# triad, because it is a fact about a recipe's SHAPE rather than about the gate's
# behaviour and can land anywhere.
#
# IT IS HERE BECAUSE IT WAS PAID FOR TWICE. rusticprofile `0.2.2` fixed it after a
# global regex put `@` in front of lines in `pr`, `merge-pr` and `aur-publish`.
# retch `v0.17.13` fixed it again in `merge-pr`, in a session where that write-up
# had already been read — and it broke the very merge that shipped it. **A
# documented trap is not a guard**, which is this whole file's argument.
#
# Run against the two historical defects it exists for, the guard names all four
# sites: rusticprofile's `pr`, `merge-pr` and `aur-publish`, and retch's `merge-pr`.
#
# HEREDOCS ARE SKIPPED, and that is load-bearing rather than polite. A `cat <<'MSG'`
# block inside a shebang recipe is DATA, so a line of it starting with `@` is a
# literal `@` and not a command. Without the skip the check fires on correct code —
# and a guard that fires on correct code is deleted within a week, taking the real
# rule with it. The self-test pins all four cases: it fires on the defect, stays
# silent on a plain recipe, stays silent inside a heredoc, and still fires on a
# defect AFTER a heredoc.
#
# TWO VERSION NUMBERS, DELIBERATELY NOT THE SAME ONE. This block's marker is v6; the
# helpers carry their own `TEMPLATE_VERSION` (`gate_conformance.py` is now 4,
# `install_completions.py` 3, `install_man.py` 3). They move independently because a
# helper can change without the block changing, and vice versa — which is what
# happened here.
#
#
# WHY `standard-check` HAS NO SHEBANG  (v4 settled this; v1's mistake nearly recurred)
# ----------------------------------------------------------------------------
# Three repos all declared `template v3` while `standard-check`'s BODY differed:
# retch ran four plain `@"{{PY}}"` lines; etr and rusticprofile ran a
# `#!/usr/bin/env bash` recipe with `set -euo pipefail` and an explicit
# `[ "{{PY}}" != "PYTHON-NOT-FOUND" ]` guard. Each repo was internally consistent
# — template file and Justfile agreed — so nothing looked wrong anywhere.
#
# THE MAJORITY WAS WRONG, and reconciling toward it would have been v1 repeating.
# The decisive measurement is which recipes each repo's `check` actually depends
# on, counted rather than argued:
#
#     retch          7 of 7 check dependencies shell-free
#     etr            4 of 6 are bash shebangs
#     rusticprofile  2 of 4 are bash shebangs
#
# So retch is the only repo where `just check` still runs on a default Windows
# PATH — no `cygpath`, no Git `usr\bin` — which is the ENTIRE property v0.6.16
# bought and the reason these helpers are Python at all. Adopting the shebang
# body would have spent it, in the one repo that still had it, to match two repos
# that had already lost it for unrelated reasons.
#
# The guard is also worth less than it looks. The sentinel is the literal string
# `PYTHON-NOT-FOUND`, so the UNGUARDED failure is `PYTHON-NOT-FOUND: command not
# found` — which already names the problem. The guard buys a tidier message; the
# shebang costs a platform.
#
# CANONICAL: `standard-check` is four plain lines and has no shebang. A repo whose
# `check` needs bash for OTHER reasons is free to have bash-shebang recipes of its
# own — OUTSIDE these markers. That is a gap in those repos, stated rather than
# hidden, and it is not fixed by making this block worse.
#
# Stated precisely, because the loose version of this claim is false: the rule is
# about the GATE, not about the whole block. `install-tag` below IS a bash shebang
# recipe and stays one — it is an explicit install action nobody runs from `check`,
# it needs real control flow, and a Windows user running it has already chosen to
# install a toolchain. What must stay shell-free is every recipe `check` depends on.
#
# The transferable half, which is v1's lesson arriving in new clothes: "two of
# three repos agree" is a fact about how the drift SPREAD, not about which side is
# right. Count the property at stake instead of counting the repos.
#
#
# WHY PYTHON HELPERS RATHER THAN JUST RECIPES  (v2 reversed v1 here)
# -----------------------------------------------------------------
# This is retch's finding, adopted as the standard. retch converted these exact
# recipes to Python in its v0.6.16 to eliminate bash-shebang escaping bugs and
# run natively on Windows PowerShell, CMD and Unix shells WITHOUT requiring
# Git's `usr\bin` on PATH.
#
# v1 of this template got that backwards: it took rusticprofile's plain-`sh`
# recipes as canonical because rusticprofile had the CORRECTNESS fixes, and
# would have regressed retch's deliberate portability work in the name of
# consistency. The two repos had each solved half the problem. v2 keeps retch's
# mechanism and rusticprofile's measured correctness:
#
#   * a `bash` shebang recipe cannot run on Windows without `cygpath` at all
#   * a plain `sh` recipe still needs an `sh` on PATH
#   * a Python helper needs only an interpreter, and its logic is unit-testable
#     off-platform — which matters because the branch that keeps being wrong is
#     the Windows one, on machines that never take it
#
# The lesson worth keeping: "the repo with the fixes" and "the repo with the
# right mechanism" were not the same repo, and picking a reference without
# reading each one's release log would have shipped a regression as a standard.
#
#
# WHY A VENDORED COPY RATHER THAN `just import`
# ---------------------------------------------
# Three separate git repositories. An `import` still needs the imported file to
# exist in each one, so it moves the duplication rather than removing it, and a
# submodule for one file costs more than it saves. What makes a copy safe is not
# that it is a copy — it is that something CHECKS it.
#
# Not hypothetical. rusticprofile measured and fixed three completion defects and
# both siblings then carried them for months, because nothing compared them:
#
#   1. nushell completions written to the XDG path, which Windows nushell never
#      reads — live in retch AND etr
#   2. output claiming zsh completions are "auto-loaded from the default $fpath",
#      false on every distribution — live in etr
#   3. `install-completions` as a bash shebang recipe, unrunnable on Windows — etr
#
# And retch has a fourth of its own: its helper logs a generation failure to
# stderr, carries on, and then prints "Installed completions for retch:" with
# the full path list regardless — success reported over work not done.
#
#
# WHY `standard-check` RUNS SELF-TESTS RATHER THAN DIFFING TEXT
# ------------------------------------------------------------
# With the logic in a script, a within-repo text diff checks nothing useful, and
# across repos it is impossible — git cannot diff a file it does not have. So
# each helper asserts its own invariants and `standard-check` runs them. That is
# the stronger property anyway: it is what was actually violated above, and a
# text diff would pass happily on a repo that never adopted the standard at all.
#
#
# WHY EVERY RECIPE IS WRITTEN AGAINST VARIABLES
# ---------------------------------------------
# `etr` ships two binaries (`etr`, `etrs`); the others ship one. A block with a
# hardcoded binary name cannot be copied, and a standard that cannot be copied is
# decoration. Project facts live ABOVE the block, in a PROJECT header each repo
# owns:
#
#     BINS      := "etr etrs"                          # space separated
#     MAN_PAGES := "man/etr.1 man/etrs.1"              # space separated
#
# Project-specific recipes are normal — put them OUTSIDE the markers, under
# `# ===== PROJECT-SPECIFIC =====`. Editing INSIDE the markers means changing the
# standard: edit this file and both helpers, bump TEMPLATE_VERSION and the marker,
# and propagate to the siblings in their own PRs.
#
#
# SCOPE, STATED SO THE GAPS ARE NOT READ AS OVERSIGHTS
# ----------------------------------------------------
# Covers the install/man/completions family, and — since v3 — the BEHAVIOUR of the
# `pr`/`open-pr`/`merge-pr` triad, via `scripts/gate_conformance.py`.
#
# The triad's *bodies* are still not shared, and that is deliberate: `cargo clippy` is
# bare in rusticprofile, `--workspace` in retch and `--all-targets` in etr; the NOTES
# header differs; each checklist asks for different things. Forcing one body would
# change what each gate DOES. So what is standardised is the set of guards each recipe
# must carry, and `gate_conformance.py` asserts they are present.
#
# That check is STRUCTURAL, not behavioural, and its own docstring says so: it proves a
# guard exists, not that it works. The install helpers can be checked behaviourally
# because they are pure functions; the gate recipes run test suites, push branches and
# merge PRs, so executing them from `check` would be slow and destructive.
#
# Still not covered: `check`/`lint`/`test` bodies, and `man` — each repo builds its
# page(s) its own way (one builds two). All three COMMIT the result, which is what
# lets `install-man` install without building (v6).
#
# Known divergences left alone, for whoever extends this:
#   * `Justfile` (rusticprofile, retch) vs `justfile` (etr)
#   * `lint` (rusticprofile, retch) vs `clippy` (etr)
#   * `## Current State (vX)` vs `## Current state: vX` in NOTES.md
#   * etr's `check` chain still needs bash (man-check, packaging-check, text-check are
#     shebang recipes); retch's is 7 of 7 shell-free. See the v4 note above.
#
# (A bullet claiming etr has no `install-hooks` and no `open-pr` stood here until v5. Both
# exist there now — justfile:306 and justfile:268 — so it was removed rather than corrected.
# It had been false for long enough that nobody re-read it, which is `0.2.4`'s finding about
# duplicated state, inside the file that exists to stop duplication drifting.)
#
# ---- BEGIN CANONICAL ----
# The interpreter is resolved ONCE per line, and a missing one is a hard error. The
# `python3 … 2>/dev/null || python …` idiom is deliberately NOT used: it retries on ANY
# failure, so a real error inside the script gets re-run and reported as if the
# interpreter were the problem.
PY := `command -v python3 || command -v python || echo PYTHON-NOT-FOUND`

# Install from this checkout: binary, man page(s) and completions.
#
# The dependencies are the point. `cargo install` alone replaces the binary and leaves the
# man page and completions at whatever version last ran their recipe — measured on a host
# whose page was ELEVEN releases stale with nothing reporting it.
install: install-man install-completions
    cargo install --path .

# Install a RELEASED tag: binary, man page(s) and completions, all three FROM THAT TAG.
#
# **It deliberately does NOT depend on `install-man`/`install-completions`**, because those
# work from the checkout. Reusing them would pair a tag's binary with the worktree's man
# page and completions — on a checkout one release ahead, a v0.2.22 binary with a v0.2.23
# page. Mismatched artefacts that each look fine is the failure class this standard exists
# to remove, so the three sources are made to agree: binary from the tag, completions from
# THE INSTALLED BINARY (`--from-path`), man page from the tag (`--from-tag`).
#
# Never `--path`: on a Syncthing-shared checkout that builds from a directory other
# machines write into. Takes a bare version and normalises a leading `v`.
install-tag VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    V="{{VERSION}}"; V="${V#v}"
    [ -n "$V" ] || { echo "error: install-tag needs a version, e.g. just install-tag 0.2.22" >&2; exit 1; }
    git rev-parse -q --verify "refs/tags/v${V}" >/dev/null || {
        echo "error: tag v${V} is not in this clone. Run: git fetch --tags" >&2; exit 1; }
    REPO=$(git config --get remote.origin.url)
    echo "Installing from tag v${V} of ${REPO}"
    cargo install --git "$REPO" --tag "v${V}" --locked --force
    # POST-CONDITION: cargo prints a replacement line, but only a version query proves which
    # binary is on PATH now.
    for b in {{BINS}}; do
        command -v "$b" >/dev/null 2>&1 || { echo "error: $b is not on PATH after install" >&2; exit 1; }
        echo "  $b -> $("$b" --version)"
    done
    "{{PY}}" scripts/install_man.py {{MAN_PAGES}} --from-tag "v${V}"
    "{{PY}}" scripts/install_completions.py {{BINS}} --from-path

# Install the man page(s) to the XDG man directory.
#
# Installs the COMMITTED page(s) and deliberately does NOT depend on `man` (v6). Every repo
# using this block commits its pages and its gate refuses a stale one, so rebuilding here
# only made `just install` require mandown -- a documentation build tool -- to install a
# finished page, and rewrote a tracked file in the user's checkout. Edited the page source?
# Run `just man` first; the gate would refuse the stale page at PR time anyway.
install-man:
    @"{{PY}}" scripts/install_man.py {{MAN_PAGES}}

# Generate and install shell completions for every binary.
#
# Python rather than a just recipe, which is retch's finding and the more portable
# mechanism: no `sh`, no `cygpath`, no coreutils, nothing from Git's `usr\bin` on Windows.
# A `bash` shebang recipe cannot run on Windows without `cygpath` at all, and even a plain
# `sh` recipe still needs an `sh` on PATH.
install-completions: build
    @"{{PY}}" scripts/install_completions.py {{BINS}}

# Prove the vendored helpers still behave the way the standard requires.
#
# **This runs the helpers' own self-tests rather than diffing text**, and that is the whole
# point: three separate repositories cannot diff each other's files, but each can prove its
# copy still behaves correctly — which is the property that was actually violated when two
# repos quietly shipped the pre-fix nushell path for months. A text diff would also have
# passed happily on a repo that had never adopted the standard at all.
standard-check:
    @"{{PY}}" scripts/install_completions.py --self-test
    @"{{PY}}" scripts/install_man.py --self-test
    @"{{PY}}" scripts/gate_conformance.py --self-test
    @"{{PY}}" scripts/gate_conformance.py "{{justfile()}}"
