all: build test
all-release: build-release test-release
all-quick: build-quick test-quick

export DOG_DEBUG := ""

version := `grep '^version =' Cargo.toml | head -1 | cut -d '"' -f 2`


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

# check that the dog binary can compile
@check:
    cargo check


#---------------#
# running tests #
#---------------#

# run unit tests
@test: fmt clippy
    cargo test --workspace -- --quiet

# run unit tests (in release mode)
@test-release: fmt clippy
    cargo test --workspace --release --verbose

# run unit tests (without some features)
@test-quick: fmt clippy
    cargo test --workspace --no-default-features -- --quiet







#-----------------------#
# code quality and misc #
#-----------------------#

# check code formatting
@fmt:
    cargo fmt --check

# check the packaging templates (the renderer's guards, and that every template still renders)
@packaging-check:
    python3 scripts/render_packaging.py --self-test

# run the self-tests of every project script, and check the project description agrees everywhere
@scripts-check:
    python3 scripts/render_packaging.py --self-test
    python3 scripts/version_gate.py --self-test
    python3 scripts/ci_changes.py --self-test
    python3 scripts/ci_gate.py --self-test
    python3 scripts/metadata_check.py --self-test
    python3 scripts/github_metadata.py --self-test
    python3 scripts/metadata_check.py

# check that every copy of the project description agrees with packaging/metadata.toml
@metadata-check:
    python3 scripts/metadata_check.py

# set the GitHub About box and topics from packaging/metadata.toml (public: shows the change and asks first)
github-metadata:
    python3 scripts/github_metadata.py --apply

# publish a released version to the AUR (public and immediate: you must type the version to confirm)
@publish-aur version:
    python3 scripts/publish_packaging.py aur "{{version}}"

# publish a released version to the Homebrew tap (public and immediate: you must type the version to confirm)
@publish-brew version:
    python3 scripts/publish_packaging.py brew "{{version}}"

# lint the code
@clippy:
    cargo clippy --all-targets -- -D warnings

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

# The branch every PR targets, as a git ref.
base := "origin/master"

# check the version was bumped past master and the last tag (what the `Version bump` CI job runs)
@version-check:
    python3 scripts/version_gate.py --base {{base}}

# install the git hooks (a pre-push that runs fmt and clippy); run once per clone
@install-hooks:
    bash scripts/install_hooks.sh

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
    [ "$BRANCH" = "master" ] && fail "On master: create a feature branch first (feature/, fix/ or chore/<name>)"
    pass "Branch: $BRANCH"

    # 2. Everything committed, so what this gate checks is what gets pushed.
    if ! git diff --quiet || ! git diff --cached --quiet; then
        git status --short
        fail "Uncommitted changes: commit them first, so the gate checks what will be pushed"
    fi
    pass "Working tree is clean"

    # 3. The version is bumped past master and the last tag, and Cargo.lock agrees.
    info "Checking the version bump..."
    git fetch -q origin master
    python3 scripts/version_gate.py --base {{base}} > /tmp/version-gate.$$ 2>&1 || { cat /tmp/version-gate.$$; rm -f /tmp/version-gate.$$; fail "Version not bumped past master and the last tag (Z for fixes/tests/docs/CI/deps, Y for new features; see CONTRIBUTING.md, Version numbers)"; }
    grep -E '^(Cargo|version)' /tmp/version-gate.$$ | sed 's/^/    /'; rm -f /tmp/version-gate.$$
    pass "Version bumped"

    # 4. The scripts' self-tests, which include the packaging templates still rendering and
    #    still recording nothing.
    just scripts-check > /dev/null
    pass "Script self-tests and packaging templates"

    # 5. The lockfile builds as committed (CI and every packaging channel use --locked).
    info "cargo build --locked..."
    cargo build --locked -q
    pass "Cargo.lock is current and committed"

    # 6. fmt, clippy --all-targets -D warnings, and the tests: exactly what CI runs.
    info "just (build, fmt, clippy, tests)..."
    just > /dev/null
    pass "fmt, clippy and tests passed"

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
    echo "  [ ] README.md and man/dog.1.md reviewed (new flags, behaviour, install channels)"
    echo "  [ ] AGENTS.md / CONTRIBUTING.md updated if the workflow, CI or packaging changed (in THIS PR, not later)"
    echo "  [ ] Packaging templates changed? then they were built for real (see AGENTS.md, Packaging)"
    echo "  [ ] PR description says what and why, has a test plan, and ends with Assisted-By: <model name>"
    echo ""
    # A bare `read` cannot be answered by a script, CI job or agent, and the failure then reads as
    # the gate refusing the change. PR_CONFIRM is the explicit answer for a non-interactive caller.
    # It is not a bypass: setting it is the same act as typing y, recorded where a script can
    # supply it, and it must be answered AFTER checking each item above.
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
    # `just open-pr` sets OPEN_PR and opens the PR itself, so telling it to run open-pr would be noise.
    if [ -n "${OPEN_PR:-}" ]; then
        echo -e "\n${GREEN}Gate passed.${NC}\n"
    else
        echo -e "\n${GREEN}Gate passed. Open the PR with: just open-pr --title \"...\" --body-file <file>${NC}\n"
    fi

# gh has no hook of its own to gate `gh pr create`, so this is the one call site that can.
# --repo is explicit because this repository is a fork of ogham/dog, and a bare `gh pr create`
# can target upstream.
# run the pre-PR gate, then `gh pr create` against l1a/dog master
[positional-arguments]
open-pr *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    OPEN_PR=1 just pr
    # "$@", not {{ARGS}}: just joins a variadic argument with spaces and no quoting, so a title with
    # spaces would reach gh as several words. positional-arguments passes each argument through intact.
    gh pr create --repo l1a/dog --base master "$@"

# GitHub deletes a PR's remote branch when it merges (the repository setting is on), but never your
# local one, so merged branches pile up here, each marked [gone]. `just merge-pr` removes the branch it
# merges; this clears the rest. A branch is kept, with a message, if it is not merged into HEAD.
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

# Run this ONLY when merging has been authorised. `gh pr merge` merges a red PR happily, and
# "the checks have settled" is not "the checks passed". No checks at all is not green either,
# and an empty list must not read as success.
# merge the current branch's PR, but only if every check is green
merge-pr:
    #!/usr/bin/env bash
    set -euo pipefail
    BRANCH=$(git rev-parse --abbrev-ref HEAD)
    [ "$BRANCH" = "master" ] && { echo "Error: already on master."; exit 1; }
    [ "$(gh pr view --repo l1a/dog --json headRefOid --jq .headRefOid)" = "$(git rev-parse HEAD)" ] \
        || { echo "Error: the PR head is not your local HEAD. Push first, then wait for CI on that commit."; exit 1; }

    # Count in jq rather than looping over a list of states in the shell: a check that is still
    # running reports an EMPTY state, and word-splitting drops an empty word, so a loop over the
    # states would never see it and the recipe would merge with a check pending. A check that
    # reports neither a conclusion nor a state counts as not green.
    CHECKS='.statusCheckRollup[]? | select((.conclusion // .state // "") != "SKIPPED")'
    TOTAL=$(gh pr view --repo l1a/dog --json statusCheckRollup --jq "[$CHECKS] | length")
    if [ "$TOTAL" = "0" ]; then
        echo "Error: no checks have reported for this commit. That is not the same as passing."
        exit 1
    fi
    NOT_GREEN=$(gh pr view --repo l1a/dog --json statusCheckRollup --jq "[$CHECKS | select((.conclusion // .state // \"\") != \"SUCCESS\")] | length")
    if [ "$NOT_GREEN" != "0" ]; then
        echo "Error: CI is not green on this branch ($NOT_GREEN of $TOTAL checks):"
        gh pr view --repo l1a/dog --json statusCheckRollup \
            --jq ".statusCheckRollup[]? | select((.conclusion // .state // \"\") != \"SKIPPED\" and (.conclusion // .state // \"\") != \"SUCCESS\") | \"  \(if (.conclusion // .state // \"\") == \"\" then (.status // \"PENDING\") else (.conclusion // .state) end)  \(.name // .context)\""
        exit 1
    fi
    [ "$(gh pr view --repo l1a/dog --json mergeable --jq .mergeable)" = "MERGEABLE" ] \
        || { echo "Error: the PR is not mergeable (conflicts, or GitHub is still working it out)."; exit 1; }
    echo "CI is green on every check."
    gh pr merge --repo l1a/dog --merge
    git checkout master
    git pull -q origin master
    git branch -D "$BRANCH" 2>/dev/null || true


#---------------#
# documentation #
#---------------#

# render the documentation
@doc:
    cargo doc --no-deps --workspace

# build the man pages
@man:
    mkdir -p "${CARGO_TARGET_DIR:-target}/man"
    sed "s/{{ '{{' }}VERSION{{ '}}' }}/{{version}}/g" man/dog.1.md | pandoc --standalone -f markdown -t man > "${CARGO_TARGET_DIR:-target}/man/dog.1"

# build and preview the man page
@man-preview: man
    man "${CARGO_TARGET_DIR:-target}/man/dog.1"
@man-local: man
    mkdir -p ~/.local/share/man/man1
    cp "${CARGO_TARGET_DIR:-target}/man/dog.1" ~/.local/share/man/man1/


#-----------#
# packaging #
#-----------#

# create a distributable package
zip desc exe="dog":
    #!/usr/bin/env perl
    use Archive::Zip;
    -e 'target/release/{{ exe }}' || die 'Binary not built!';
    -e 'target/man/dog.1' || die 'Man page not built!';
    my $zip = Archive::Zip->new();
    $zip->addFile('completions/dog.bash');
    $zip->addFile('completions/dog.zsh');
    $zip->addFile('completions/dog.fish');
    $zip->addFile('target/man/dog.1', 'man/dog.1');
    $zip->addFile('target/release/{{ exe }}', 'bin/{{ exe }}');
    $zip->writeToFileNamed('dog-{{ desc }}.zip') == AZ_OK || die 'Zip write error!';
    system 'unzip -l "dog-{{ desc }}".zip'
