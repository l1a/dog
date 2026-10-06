# Dog - DNS client

A command-line DNS client (like dig, but more user-friendly).

## Build

The default build may require `libssl-dev` depending on the platform due to the use of TLS for DNS-over-TLS/HTTPS. Use the vendored feature to statically link if needed (if configured in `Cargo.toml`).

```sh
cargo build --release
```

## Project structure

The `l1a/dog` fork relies heavily on the [`hickory-resolver`](https://github.com/hickory-dns/hickory-dns) crate for all DNS parsing and networking. 

- `src/` - CLI binary source code
  - `main.rs` - Application entry point and `hickory-resolver` orchestration
  - `options.rs` - Command-line argument parsing
  - `output.rs` - Formatting DNS responses (JSON and Text)
  - `table.rs` - Pretty-printing tables for terminal output

## Testing

```sh
cargo test
```

The test suite covers:
- CLI argument parsing (`src/options.rs`)

*Note: The original `dog` integration test suite (`xtests/`) and `dns/` wire format parsing tests are no longer applicable as parsing is entirely delegated to `hickory-resolver`.*

## Versioning

### Version numbers: X.Y.Z (MAJOR.MINOR.PATCH)

`Cargo.toml`'s version is `X.Y.Z`, [semantic versioning](https://semver.org). **Bump exactly one part per PR, the highest that
applies**, and reset every part to its right to 0.

| Part | Name | Bump it when | Resets |
|---|---|---|---|
| **Z** | PATCH | the PR changes nothing a user can newly do and no correct invocation could notice: a bug fix, tests, docs, CI, packaging, a refactor, a dependency update | nothing |
| **Y** | MINOR | the PR adds something a user can see and nothing breaks: a new flag or option, record type, output mode, transport, platform archive or install channel. **While X is 0, also any breaking change** | Z to 0 |
| **X** | MAJOR | the PR breaks the public interface, **from 1.0.0 on**. While X is 0 it is reserved: the move to `1.0.0` is a deliberate decision by the maintainer to declare the interface stable, never a side effect of a PR | Y and Z to 0 |

Examples: `0.7.3` + a fix is `0.7.4`. `0.7.3` + a new flag is `0.8.0`. `0.7.3` + a renamed flag is `0.8.0` (breaking, pre-1.0).
`1.4.2` + a renamed flag is `2.0.0`. `1.4.2` + a new flag is `1.5.0`. `1.4.2` + a fix is `1.4.3`.

**What "the interface" is.** `dog` is a command-line tool, so the interface is what a user or a script can depend on:
- the flags, options and arguments, and their meaning and defaults;
- the output: the text format and, above all, the **`--json` shape** (key names and nesting);
- the exit codes;
- what is installed: the `dog` binary, its man page and the shell completions.

It is **not** the Rust code (the crate is a binary, not a library), the dependencies, CI, the docs, or how a package is built.

**How to decide, in order, stopping at the first yes:**
1. *Could an invocation or script that worked on the previous release now break or behave differently on purpose?* Removing or
   renaming a flag, changing a JSON key or its structure, changing an exit code, changing a default that scripts rely on.
   That is **breaking**: Y while X is 0, X from 1.0.0. Say `BREAKING:` in the PR title and description.
2. *Can a user now do something they could not, or see something new?* A new flag, record type, output mode, transport, or a
   new platform or install channel. That is **Y**.
3. *Otherwise* (a fix, tests, docs, CI, packaging, a refactor, a dependency update): **Z**.

A bug fix is a **patch even when it changes output**, if the old output was wrong: the interface did not change, the program now
does what it already claimed to. A dependency update is a patch even when the dependency's own version jumped, unless it changes
something a user sees, in which case it follows the questions above.

**Pre-release tags.** `vX.Y.Z-rc.N` is published as a pre-release. The suffix lives only on the tag; `Cargo.toml` keeps `X.Y.Z`.

### The rule

- **Every merged PR bumps `Cargo.toml`'s version.** No carve-out for docs-only, test-only or CI-only changes: those are patch
  bumps. Which part to bump is decided as above. This is the `etr`/`retch` rule (`rusticprofile` uses patch for everything until
  1.0, which does not apply here). Commit `Cargo.lock` with the bump.
- **A release needs no bump.** After a tag, `master` stays at the released version and the next PR bumps it. That is why the
  packaging templates record no version: nothing has to be updated after a release, and nothing can fall behind one.
- **The bump is checked against `master`, not only the last tag** (`scripts/version_gate.py --base origin/master`). The
  siblings compare only with the tag, which lets two PRs bump to the same number and neither notice that the second added
  nothing. The check is numeric per component (`0.10.0` is past `0.9.0`), and requires `Cargo.lock` to agree, because every build and
  every packaging channel uses `--locked` and the `v0.6.0` tag shipped with a stale lockfile (`0.5.7`).
- **Dependabot PRs are not merged.** They close by themselves once `master` carries the update. We open our own PR to resolve
  what Dependabot found, and that PR follows this process, bump included. The same goes for any other auto-generated PR.
- **How it is enforced** (a Justfile recipe and a hook, not agent configuration, so it binds a human, Claude and Gemini alike):
  - `just pr` is the pre-PR gate: feature branch, clean tree, version bump, the scripts' self-tests (`just scripts-check`, which
    include the packaging templates), `cargo build --locked`, `just` (fmt, clippy `--all-targets`, tests), an advisory
    `cargo audit`, then a manual checklist answered by typing `y` or by `PR_CONFIRM=y` for a non-interactive caller (only after
    actually checking each item).
  - **`just open-pr` instead of `gh pr create`**: it runs the gate, then `gh pr create --repo l1a/dog --base master "$@"`. Pass a
    multi-line body with `--body-file`. The arguments reach `gh` intact because the recipe uses `[positional-arguments]` and `"$@"`:
    `{{ARGS}}` joins them with spaces and no quoting, so a title with spaces became several words and a backtick in the body
    **ran as a command**.
  - `just merge-pr` refuses to merge unless every check is `SUCCESS` on the PR's current head (no checks at all is not green).
    Run it only when merging has been authorised.
  - `just install-hooks` installs a `pre-push` hook that runs fmt and clippy; skip once with `GIT_NO_CHECK=1`.
  - **`version.yml` is an advisory CI job** (`Version bumped`). It is not a required check, so it informs without blocking, and it
    is skipped for `dependabot[bot]`. It has no `paths:` filter, because the rule has no carve-out.
- **Baseline.** `0.7.0` is the first bump under this rule. It covers everything merged since `v0.6.0` without one (the `dogdns`
  crate, the COPR/AUR/Homebrew packaging, ARM release archives, the hickory update), as one minor bump.

## Source control and CI

- **Trunk on `master`.** Short-lived `{feature,fix,chore}/<name>` branches are PR'd into `master`. The old `dev` and
  `dependabot` branches are retired; Dependabot targets `master`.
- **`just` is the local mirror of CI.** `just` = build + `cargo fmt --check` + `cargo clippy --all-targets -- -D warnings` + tests.
  Run it before pushing. A new Rust release can add lints, so `master` can go red with no code change.
- **`.github/workflows/ci.yml`** runs on every PR and push to `master`: format and clippy, tests on Linux (x86_64, aarch64,
  Fedora), macOS and Windows (x86_64, aarch64), and a man-page build.
- **A docs-only PR skips the full suite, but not with `paths:` filters.** Branch protection requires the single `CI OK` job, and a
  workflow filtered out by `paths:` never reports a status, so the PR would wait on a required check forever. Instead a `changes`
  job (`scripts/ci_changes.py`) classifies the PR's files and `lints`, `test` and `man` are skipped with `if:`; `CI OK` always runs.
  - **docs-only**: every changed file is Markdown at the repository root, `LICENSE`, the screenshot, or an issue or PR template.
    Nothing is built or tested.
  - **man**: `man/` changed. Only `Man page` runs (pandoc is the one thing a `man/` change can break).
  - **code**: anything else, including `Cargo.toml`, `Cargo.lock`, `src/`, `scripts/`, `packaging/`, **every workflow file**, and
    Markdown in a subdirectory (a build input: `man/dog.1.md`, `packaging/**/*.md`). The full suite runs.
  - **Only pull requests take the fast path.** A push to `master`, a release (`workflow_call`), a manual run, and any doubt (an API
    error, an empty or truncated file list) run everything. A rename counts both the old and the new name, so moving a code file to
    a docs path does not read as docs-only. `version.yml` still runs on docs-only PRs, because the rule has no carve-out.
- **`CI OK` is `scripts/ci_gate.py`.** It asks the API what every job concluded and does not trust `needs.*.result` alone. During a
  GitHub Actions outage (2026-10-05) the original gate passed a run whose Format and Clippy, Man page and Fedora jobs were all
  *cancelled*: a job cancelled in the runner queue reports **`abandoned`**, not `cancelled`, so `contains(..., 'cancelled')` was
  false. The run's own conclusion was correctly `failure`; only the job-level check was wrong, and branch protection trusts the job.
  It **recomputes the change classification itself** rather than trusting the `changes` job, and checks the jobs that class needs:
  - **code**: all three groups must be exactly `success`. A job the change needs that was *skipped* fails: that is how a
    misclassification would hide.
  - **man**: `Man page` must succeed; the others may be skipped. **docs-only**: all may be skipped.
  - Anything else fails: `failure`, `cancelled`, `abandoned`, a job group missing from the run, a `changes` job that did not succeed,
    an API error, or any result it does not recognise. `if: always()` is needed because a *skipped* required check counts as passing.
  When `release.yml` calls `ci.yml` the caller must grant `actions: read` **and `pull-requests: read`**, because a called workflow
  cannot widen its caller's token (job names then carry a `CI / ` prefix, which the gate allows for).
- **Test a CI gate against the real failure, not against a green run.** `ci_gate.py` and `ci_changes.py` have self-tests with the
  incident data in them, and the whole flow (23 cases: the fast paths, a rename hiding a code file, an API error, a push, and the
  incident replayed) was run through their real entry points under a fake `gh`. A gate that has only ever seen green runs has not been
  shown to fail. Every case must name the message it expects, or it can pass for an unrelated reason.
- **`timeout-minutes` bounds a job that is running and hung. It does not count time spent waiting for a runner**, so it cannot
  shorten a stall in GitHub's queue (about 15 minutes before the job is cancelled). Rerun cancelled jobs once the queue clears.
- **`security.yml`** runs `cargo audit` on dependency changes and weekly.
- **The hickory crates must be updated together.** `hickory-resolver`, `hickory-net` and `hickory-proto` are released as a set, and a
  newer resolver does not compile against an older net or proto even though its manifest allows the older one. Dependabot's
  resolver-only bump (0.26.1 -> 0.26.2) failed to build on every platform with `no variant named Truncated` and similar errors.
  Fix such a PR with `cargo update -p hickory-resolver`, which moves all three. `dependabot.yml` groups `hickory-*` first to keep
  them in one PR; a resolver-only PR is still possible if upstream publishes the resolver before its companions, and CI catches it.
- **`release.yml`** runs on a `v*` tag: it verifies the tag against `Cargo.toml` and `Cargo.lock`, calls `ci.yml` as a
  reusable workflow (`workflow_call`), builds five native targets, and publishes archives plus `SHA256SUMS`. Completions
  are generated by the built binary (`dog --completions <shell>`), so they cannot disagree with the CLI. `workflow_dispatch`
  builds without publishing. Only the `release-*` artifacts become release assets; the `man` artifact is a build input.
  Release steps are in `CONTRIBUTING.md`.
- CI and release builds use `--locked`, so a version bump without a matching `Cargo.lock` fails instead of being rewritten.
- This repo is a fork of `ogham/dog`. Always pass `--repo l1a/dog` to `gh pr create` so a PR cannot go to upstream.

## Dependencies

- **Dependabot opens grouped weekly PRs** (`cargo`, and `github-actions`, with `hickory-*` kept together). **They are never merged.** We
  open our own PR that does the same and more, because Dependabot only bumps *direct* dependencies: on 2026-10-06 it proposed 7 crates
  while `cargo update` had **90** packages behind within our existing version ranges. Its PRs close by themselves once `master` carries
  the update. Our PR follows the normal process, bump included (dependency updates are a **patch**).
- **To check everything is current:** `cargo update --dry-run` (what moves within our ranges); compare each direct dependency with
  crates.io for a newer *incompatible* version, which `cargo update` never offers (a newer `0.x` minor or a new major); and list every
  `uses:` in the workflows against its latest release. `rust-toolchain@stable` and `setup-homebrew@main` track a rolling ref on purpose.
- **Verify an update, do not just compile it:** build with `--locked`, run `just`, run `cargo audit`, and compare the **old and new
  binaries** on the generated completions for all six shells, `--help`, and live queries over UDP, TCP, DNS-over-TLS, DNS-over-HTTPS and
  `--json` (TTLs and answer order normalised: Cloudflare rotates the order of records). The 2026-10-06 update changed one thing: updated
  `clap_complete` stopped offering the literal `[free]...` placeholder as a bash completion candidate, which is a fix.
- **Read the release notes for a major bump.** `actions/checkout` 7 blocks checking out fork PRs under `pull_request_target` and
  `workflow_run`, which we do not use; `extractions/setup-just` 4 had no notes. A workflow change is tested by its own PR's CI.
- **`cargo audit` runs in three places:** `security.yml` in CI (push to `master`, PRs touching `Cargo.toml` or `Cargo.lock`, **weekly on
  Sundays**, manually), which fails on vulnerabilities but not on warnings (unmaintained, unsound, yanked); `just pr`, advisory and only
  if `cargo-audit` is installed; and by hand. It is **not** part of `CI OK`, so it informs and does not block a merge.
- **`datetime` was removed (2021-04-01 was its last release, no advisory named it).** It was a build dependency whose only use was a
  build date, reachable only for a release build with a `-pre` version, which `version_gate.py` rejects, so it was dead code. The
  `--version` string is now just the version, plus a warning on debug builds: no Git hash and no build date, so a build does not need
  `git` and two builds of one source print the same string. If a date is ever wanted again, use `std` or `jiff`, not a stale crate.
- `edition = "2018"` is old but is not a dependency.

## Project description

- **One source, many copies.** The description is written once, in `packaging/metadata.toml`: the one-line `summary`, the long
  `description`, the README `tagline`, the crates.io description, keywords and categories, the GitHub About text and topics, and the COPR
  page. It still has to be *copied* into each artifact that carries it (crates.io reads `Cargo.toml`, the AUR the PKGBUILD and `.SRCINFO`,
  COPR's RPM the spec, Homebrew the formula), so the copies stay where they are and **`scripts/metadata_check.py` fails when any copy
  disagrees**. It runs in `just scripts-check` (so in `just pr`) and in the advisory `Metadata` workflow, which is deliberately separate
  from `packaging.yml` so that a README-only PR does not start the COPR build. Before this the same description was typed into six places
  and had drifted until most of them said the same five words.
- **It proves the copies agree, not that they are right.** Before a release, read the README and `metadata.toml` for claims that are no
  longer true. Every claim in the README was run against the real binary when it was written: argument order, `--color`, `--seconds`,
  `-1`, the exit statuses, the `jq` example, and that there is no OpenSSL in the dependency tree. Do the same for a new claim.
- **Style rules the check enforces** for `summary` and `brew_desc` (what `brew audit`, the AUR and rpmlint expect): at most 80 characters,
  no trailing full stop, no leading article, and not beginning with the package's own name. `crates.io` is exempt from the article rule.
  Keywords: at most 5. Categories: at most 5, and each must be a real crates.io slug (`CATEGORIES` in the script: crates.io rejects an
  unknown one only at publish time, so a typo would otherwise surface on release day).
- **Two copies live on services, not in files, and are pushed:** the COPR project page by `copr.yml` on a release tag, and the GitHub About
  box and topics by **`just github-metadata`**, which prints the change, asks, and sets the topics as an exact list. It is public and
  immediate, so it is run by hand. `just github-metadata` without confirming is a dry run.
- **`--short` described itself wrongly** ("display nothing but the first result") for as long as the project has existed: the code prints
  the data of **every** answer. The help, the man page and the README now say what it does. Check what an option does before describing it.

## Packaging

- **Names:** the crate (crates.io) and AUR package are `dogdns`; the COPR project is `kentobias/dog` (RPM name `dog`); the
  Homebrew tap is `l1a/homebrew-dog`. The installed binary is `dog` everywhere (`[[bin]] name = "dog"`). The crate is not
  called `dog` because that name on crates.io is an abandoned Datadog client, so `cargo install dog` fetched the wrong crate.
  Nothing in `src/` reads the package name, so renaming the crate cannot change behaviour.
- **Templates record nothing about a release.** `packaging/copr/dog.spec` carries `@VERSION@` and `@CHANGELOG@` sentinels that
  `scripts/render_packaging.py` fills from `Cargo.toml` at build time. A stale version cannot be committed when no version is
  committed. The renderer treats a substitution that matches nothing, and a sentinel that survives rendering, as hard errors;
  `just packaging-check` (`--self-test`) proves each guard can fail.
- **COPR** builds `master`'s tip with `make_srpm` (`.copr/Makefile`), using an archive of the checkout as `Source0`, so a PR can
  build its own SRPM. `copr.yml` rebuilds on a `v*` tag and **refuses unless the tag is the tip of master** (COPR clones master,
  not the tag, and a published NEVRA cannot be recalled). It skips cleanly when the `COPR_*` secrets are absent. The man page
  is rendered from `man/dog.1.md` with pandoc at build time, not committed.
- **Test the RPM for real, not just the SRPM.** `packaging.yml` runs `make -f .copr/Makefile srpm`, `dnf builddep`, then
  `rpmbuild --rebuild` (which runs `%build`, `%install` and `%check`), checks the file list, installs it and runs `dog --version`.
  The same sequence runs locally in `podman run registry.fedoraproject.org/fedora:latest`. Install `git` before anything calls it;
  the Makefile installs it itself under mock.
- **`--locked` is load-bearing** in the spec: COPR builds with network access and no vendoring, so `Cargo.lock` is the only thing
  pinning what is built to what CI tested.
- **AUR (`dogdns`) and Homebrew (`l1a/homebrew-dog`)** use the same templates (`packaging/aur/PKGBUILD.in`, `SRCINFO.in`,
  `packaging/homebrew/dog.rb`) and are published by `scripts/publish_packaging.py` (`just publish-aur X`, `just publish-brew X`).
  It downloads the tag tarball, computes the sha256 from what it got, renders, shows the diff, and requires typing the version
  before it pushes. It is tested against local bare repositories (`--remote`, `--tarball`). **`.SRCINFO` is never hand-written**:
  `SRCINFO.in` is derived from `makepkg --printsrcinfo`, and `packaging.yml` fails if the rendered pair disagrees with makepkg.
- **Arch needs `options=('!lto')`.** makepkg's default LTO flags make the C code that `ring` compiles through the `cc` crate into
  GCC LTO bytecode, which Rust's linker cannot read, so the build fails at the link with `undefined symbol: ring_core_*`. Found by
  really building the PKGBUILD in an `archlinux:base-devel` container; parsing it would not have caught it. Fedora's flags differ,
  so the COPR build never showed it.
- **A tag's `Cargo.lock` must match its `Cargo.toml`, or every packaged build fails.** All packaging uses `--locked`. The `v0.6.0`
  tag had a stale lockfile (`0.5.7`; the fix, `2f7d5d4`, landed after the tag), so `cargo fetch --locked` fails on its tarball.
  `release.yml`'s `verify` job now refuses such a tag. The first packaged release must be a fresh tag.
- **A template's comments must not contain a sentinel token.** The renderer rewrites every one, so a header that named the
  placeholders came out as a header quoting a real version and digest. `--self-test` rejects it.
- **Rootless podman uid mapping leaves host-unwritable files** in any directory a container user (such as makepkg's `builder`) was
  given ownership of. Do the whole render, build and diff inside the container from a read-only snapshot instead of sharing a
  writable host directory, or a later host-side write fails and a check silently compares stale files.
- **Homebrew is verified by `packaging.yml`'s `homebrew` job** (`brew audit --strict`, `brew install --HEAD`, `brew test`) through a
  throwaway local tap, because Homebrew only installs formulae from a tap. It cannot be run locally here (no brew), so that job
  is the first real test of the formula.
- Packaging is **not** a required check, so `packaging.yml` may use `paths:` filters. `ci.yml` may not (see above).

## Known issues

- TLS configurations may require appropriate system libraries or cross-compilation toolchains depending on the target OS.
