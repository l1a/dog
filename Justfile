# ============================================================================
# PROJECT CONFIGURATION
# ============================================================================

BINS      := "dog"
MAN_PAGES := "man/dog.1"
base      := "origin/master"

export DOG_DEBUG := ""

# Default: build and run unit tests
default: build test

all: build test
all-release: build-release test-release
all-quick: build-quick test-quick

# >>> COMMON (template v6)
# Canonical reference & rationale: templates/justfile-common.just
# Do not edit between the >>> and <<< markers alone — change the template and
# the helpers in scripts/, bump TEMPLATE_VERSION, and propagate to sibling repos.

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
    [ -n "$V" ] || { echo "error: install-tag needs a version, e.g. just install-tag 0.8.3" >&2; exit 1; }
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

# <<< COMMON

# ============================================================================
# PROJECT-SPECIFIC
# ============================================================================

#----------#
# building #
#----------#

# compile the dog binary
@build:
    cargo build

# compile the dog binary (in release mode)
@build-release:
    cargo build --release --verbose
    strip "${CARGO_TARGET_DIR:-target}/release/dog"

# install the dog binary locally (release version)
@install-release:
    cargo install --path .

# produce an HTML chart of compilation timings
@build-time:
    cargo +nightly clean
    cargo +nightly build -Z timings

# compile the dog binary (without some features)
@build-quick:
    cargo build --no-default-features

# remove build output
@clean:
    cargo clean


#---------------#
# running tests #
#---------------#

# run unit tests
@test: fmt-check clippy
    cargo test --workspace -- --quiet

# run unit tests (in release mode)
@test-release: fmt-check clippy
    cargo test --workspace --release --verbose

# run unit tests (without some features)
@test-quick: fmt-check clippy
    cargo test --workspace --no-default-features -- --quiet


#-----------------------#
# code quality and misc #
#-----------------------#

# format code with rustfmt
fmt:
    cargo fmt

# check code formatting without modifying files
fmt-check:
    cargo fmt -- --check

# lint the code with clippy
clippy:
    cargo clippy --all-targets -- -D warnings

# alias for clippy
lint: clippy

# run all offline repository quality gates (fmt-check, clippy, standard-check, man-check, packaging-check, scripts-check, text-check, wip-check)
check: fmt-check clippy standard-check man-check packaging-check scripts-check text-check wip-check
    @echo "All checks passed."

# check the packaging templates, COPR invariants, and metadata agreement
packaging-check: render-check copr-check metadata-check

# run the packaging renderer's self-test
render-check:
    @"{{PY}}" scripts/render_packaging.py --self-test

# verify packaging/copr/dog.spec, .copr/Makefile, and .github/workflows/copr.yml invariants
copr-check:
    @"{{PY}}" scripts/copr_check.py --self-test
    @"{{PY}}" scripts/copr_check.py

# run the self-tests of every project script, and check the project description agrees everywhere
scripts-check:
    @"{{PY}}" scripts/render_packaging.py --self-test
    @"{{PY}}" scripts/copr_check.py --self-test
    @"{{PY}}" scripts/version_gate.py --self-test
    @"{{PY}}" scripts/ci_gate.py --self-test
    @"{{PY}}" scripts/branch_gate.py --self-test
    @"{{PY}}" scripts/metadata_check.py --self-test
    @"{{PY}}" scripts/github_metadata.py --self-test
    @"{{PY}}" scripts/metadata_check.py

# check that every copy of the project description agrees with packaging/metadata.toml
metadata-check:
    @"{{PY}}" scripts/metadata_check.py

# refuse control characters and CRLF line endings in tracked text files
text-check:
    @"{{PY}}" scripts/text_check.py --self-test
    @"{{PY}}" scripts/text_check.py

# refuse CRLF in WIP.md and verify scripts/reset_wip.py
wip-check:
    @"{{PY}}" scripts/reset_wip.py --self-test
    @"{{PY}}" scripts/reset_wip.py --check-endings

# set the GitHub About box and topics from packaging/metadata.toml (public: shows the change and asks first)
github-metadata:
    "{{PY}}" scripts/github_metadata.py --apply

# publish a released version to the AUR (public and immediate: you must type the version to confirm)
aur-publish version:
    @"{{PY}}" scripts/publish_packaging.py aur "{{version}}"

# alias for aur-publish
publish-aur version: (aur-publish version)

# publish a released version to the Homebrew tap (public and immediate: you must type the version to confirm)
brew-publish version:
    @"{{PY}}" scripts/publish_packaging.py brew "{{version}}"

# alias for brew-publish
publish-brew version: (brew-publish version)

# run a real DNS query against 8.8.8.8 with a freshly built dog (needs the network); what CI's smoke test runs
@smoke-dns:
    scripts/smoke_dns.sh

# generate a code coverage report using tarpaulin via docker
@coverage-docker:
    docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin cargo tarpaulin --all --out Html

# update dependency versions, and check for outdated ones
@update-deps:
    cargo update
    command -v cargo-outdated >/dev/null || (echo "cargo-outdated not installed" && exit 1)
    cargo outdated

# list unused dependencies
@unused-deps:
    command -v cargo-udeps >/dev/null || (echo "cargo-udeps not installed" && exit 1)
    cargo +nightly udeps

# print versions of the necessary build tools
@versions:
    rustc --version
    cargo --version


#-----------------------#
# the pull-request flow #
#-----------------------#

# check the version was bumped past master and the last tag (what the `Version bump` CI job runs)
version-check:
    @"{{PY}}" scripts/version_gate.py --base {{base}}

# install the git hooks (pre-push runs `just check`); run once per clone
install-hooks:
    @"{{PY}}" scripts/install_hooks.py

# Run before opening a PR and before each later push. Never call `gh pr create` directly;
# use `just open-pr`.
# pre-PR gate: version bump, build, fmt, clippy, tests, audit, then a manual checklist
pr:
    #!/usr/bin/env bash
    set -euo pipefail
    BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
    pass() { echo -e "${GREEN}[ok]${NC} $1"; }
    fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
    info() { echo -e "${YELLOW}[..]${NC} $1"; }

    echo -e "\n${BOLD}=== Pre-PR gate ===${NC}\n"

    # 1. A feature branch, never master.
    BRANCH=$(git rev-parse --abbrev-ref HEAD)
    [ "$BRANCH" = "master" ] && fail "On master: create a feature branch first (feature/, fix/, chore/ or docs/<name>)"
    git fetch -q origin master
    "{{PY}}" scripts/branch_gate.py --base {{base}} || fail "Branch name: see above (CONTRIBUTING.md, Workflow)"
    pass "Branch: $BRANCH"

    # 2. Everything committed, so what this gate checks is what gets pushed.
    if ! git diff --quiet || ! git diff --cached --quiet; then
        git status --short
        fail "Uncommitted changes: commit them first, so the gate checks what will be pushed"
    fi
    pass "Working tree is clean"

    # 3. The version is bumped past master and the last tag, and Cargo.lock agrees.
    info "Checking the version bump..."
    if ! VG_OUT=$("{{PY}}" scripts/version_gate.py --base {{base}} 2>&1); then
        printf '%s\n' "$VG_OUT"
        fail "Version not bumped past master and the last tag (Z for fixes/tests/docs/CI/deps, Y for new features; see CONTRIBUTING.md, Version numbers)"
    fi
    printf '%s\n' "$VG_OUT" | grep -E '^(Cargo|version)' | sed 's/^/    /'
    pass "Version bumped"

    # 4. Offline quality gate (fmt-check, clippy, standard-check, man-check, packaging-check, scripts-check, text-check, wip-check).
    info "just check..."
    just check > /dev/null
    pass "Offline quality gate (just check)"

    # 5. The lockfile builds as committed (CI and every packaging channel use --locked).
    info "cargo build --locked..."
    cargo build --locked -q
    pass "Cargo.lock is current and committed"

    # 6. Unit and integration tests.
    info "just test..."
    just test > /dev/null
    pass "fmt-check, clippy and tests passed"

    # 7. Security audit. Advisory only: advisories can appear against unchanged dependencies,
    #    and should not hard-block otherwise ready work. CI runs the same audit separately.
    if command -v cargo-audit >/dev/null 2>&1; then
        info "cargo audit..."
        if cargo audit -q; then pass "cargo audit: no advisories"; else info "cargo audit reported advisories (above): advisory only, not blocking"; fi
    else
        info "cargo-audit is not installed: skipping the advisory audit (cargo install cargo-audit)"
    fi

    echo -e "\n${BOLD}Automated checks passed.${NC}\n"
    echo -e "${BOLD}Manual checklist: confirm each before opening the PR:${NC}"
    echo "  [ ] The bump is the right part of X.Y.Z: Z for fixes/tests/docs/CI/dependency updates, Y for a new user-visible feature,"
    echo "      and a breaking change is Y before 1.0.0 and X after (CONTRIBUTING.md, Version numbers)"
    echo "  [ ] README.md and man/dog.1.md reviewed (new flags, behaviour, install channels), and man/dog.1 regenerated via just man"
    echo "  [ ] AGENTS.md / CONTRIBUTING.md updated if the workflow, CI or packaging changed (in THIS PR, not later)"
    echo "  [ ] Packaging templates changed? then they were built for real (see AGENTS.md, Packaging)"
    echo "  [ ] PR description says what and why, has a test plan, and ends with Assisted-By: <model name>"
    echo ""
    if [ -n "${PR_CONFIRM:-}" ]; then
        CONFIRM="$PR_CONFIRM"
        echo "All manual items confirmed? [y/N] $CONFIRM   (answered by PR_CONFIRM)"
    elif [ -t 0 ]; then
        echo -n "All manual items confirmed? [y/N] "
        read -r CONFIRM
    else
        echo -n "All manual items confirmed? [y/N] "
        read -r -t 10 CONFIRM || CONFIRM=""
        echo "$CONFIRM"
        [ -n "$CONFIRM" ] || fail "No terminal to confirm the checklist on. Re-run with PR_CONFIRM=y once each item above is actually checked."
    fi
    [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ] || fail "Complete the checklist first."
    if [ -n "${OPEN_PR:-}" ]; then
        echo -e "\n${GREEN}Gate passed.${NC}\n"
    else
        echo -e "\n${GREEN}Gate passed. Open the PR with: just open-pr --title \"...\" --body-file <file>${NC}\n"
    fi

# gh has no hook of its own to gate `gh pr create`, so this is the one call site that can.
# --repo is explicit because this repository is a fork of ogham/dog, and a bare `gh pr create`
# can target upstream.
# run the pre-PR gate, push if the branch has no upstream, then `gh pr create` against l1a/dog master
[positional-arguments]
open-pr *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    OPEN_PR=1 just pr
    if ! git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' >/dev/null 2>&1; then
        BRANCH=$(git rev-parse --abbrev-ref HEAD)
        echo "Pushing $BRANCH to origin..."
        git push -u origin "$BRANCH"
    fi
    gh pr create --repo l1a/dog --base master "$@"

# delete local branches whose remote branch is gone, if they are merged
prune-branches:
    #!/usr/bin/env bash
    set -euo pipefail
    git fetch --prune -q origin
    current=$(git rev-parse --abbrev-ref HEAD)
    gone=$(git for-each-ref --format='%(refname:short) %(upstream:track)' refs/heads | awk '$2=="[gone]"{print $1}')
    if [ -z "$gone" ]; then echo "No local branches with a deleted remote branch."; exit 0; fi
    [ "$current" = "master" ] || echo "Note: you are on $current, not master; a branch is kept unless it is merged into this one."
    for b in $gone; do
        if [ "$b" = "$current" ]; then echo "kept     $b (checked out)"; continue; fi
        if git branch -d "$b" > /dev/null 2>&1; then echo "deleted  $b"; else echo "KEPT     $b (not merged: git branch -D $b to force)"; fi
    done

# merge the current branch's PR, but only if every check is green
merge-pr:
    #!/usr/bin/env bash
    set -euo pipefail
    BRANCH=$(git rev-parse --abbrev-ref HEAD)
    [ "$BRANCH" = "master" ] && { echo "Error: already on master."; exit 1; }
    PR=$(gh pr view "$BRANCH" --repo l1a/dog --json number --jq .number) \
        || { echo "Error: no pull request found for branch $BRANCH in l1a/dog."; exit 1; }
    [ "$(gh pr view "$PR" --repo l1a/dog --json headRefOid --jq .headRefOid)" = "$(git rev-parse HEAD)" ] \
        || { echo "Error: the PR head is not your local HEAD. Push first, then wait for CI on that commit."; exit 1; }

    STATES=$(gh pr view "$PR" --repo l1a/dog --json statusCheckRollup \
        --jq '[.statusCheckRollup[] | select((.conclusion // .state // "") != "SKIPPED") | (.conclusion // .state // "")]')
    if [ "$STATES" = "[]" ]; then
        echo "Error: no checks have reported for this commit. That is not the same as passing." >&2
        exit 1
    fi
    if echo "$STATES" | grep -qE 'FAILURE|TIMED_OUT|CANCELLED|ACTION_REQUIRED'; then
        echo "Error: CI has failing checks on this branch:" >&2
        gh pr checks "$PR" --repo l1a/dog >&2 || true
        exit 1
    fi
    if echo "$STATES" | grep -qE 'PENDING|QUEUED|IN_PROGRESS|WAITING|REQUESTED|""'; then
        echo "Error: CI checks are still running on this branch. Wait for them to finish." >&2
        gh pr checks "$PR" --repo l1a/dog >&2 || true
        exit 1
    fi
    [ "$(gh pr view "$PR" --repo l1a/dog --json mergeable --jq .mergeable)" = "MERGEABLE" ] \
        || { echo "Error: the PR is not mergeable (conflicts, or GitHub is still working it out)."; exit 1; }
    echo "CI is green on every check."
    gh pr merge "$PR" --repo l1a/dog --merge
    git checkout master
    git pull -q origin master
    git branch -D "$BRANCH" 2>/dev/null || true
    VER=$("{{PY}}" scripts/render_packaging.py --print-version)
    "{{PY}}" scripts/reset_wip.py --branch master --pr "$PR" --version "$VER"


#---------------#
# documentation #
#---------------#

# render the documentation
@doc:
    cargo doc --no-deps --workspace

# build man/dog.1 from man/dog.1.md using mandown and stamp the version from Cargo.toml
man:
    @"{{PY}}" scripts/man_pages.py --build

# check that man/dog.1 is current in both worktree and HEAD
man-check:
    @"{{PY}}" scripts/man_pages.py --self-test
    @"{{PY}}" scripts/man_pages.py --check

# preview the committed man page
@man-preview:
    man man/dog.1

# install the man page to ~/.local/share/man/man1
man-local: install-man
