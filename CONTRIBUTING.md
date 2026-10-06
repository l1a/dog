# Contributing to dog

This is the `l1a/dog` fork of [`ogham/dog`](https://github.com/ogham/dog). DNS parsing and networking
are delegated to [`hickory-resolver`](https://github.com/hickory-dns/hickory-dns).

## Workflow

- `master` is the only long-lived branch. Open pull requests against it from short-lived branches named
  `{feature,fix,chore,docs}/<name>`: `docs/` for a change that touches only documentation. `just pr` enforces both: it
  refuses any other name, and refuses a `docs/` branch that changes anything but documentation (the same classification CI uses for
  the docs-only fast path, so the required version bump does not count against it).
- Write short, imperative commit subjects (50 characters or fewer).
- **Every PR bumps the version in `Cargo.toml`**, with no exception for docs-only, test-only or CI-only changes. Which part
  to bump is explained in [Version numbers](#version-numbers-xyz) below. Commit `Cargo.lock` with it. The bump is past what
  `master` currently has, not only past the last tag.
- Open PRs with `just open-pr`, never `gh pr create` directly. It runs `just pr` first: the version check, a locked
  build, fmt, clippy, the tests, an advisory audit, and a checklist. Run `just install-hooks` once per clone for a
  `pre-push` hook that runs fmt and clippy.
- Every PR must pass the `CI OK` check before it is merged. The `Version bumped` job is advisory.
- Dependabot's own PRs are not merged: they close by themselves once `master` carries the update. Open your own PR
  to resolve what it found, and that PR bumps the version like any other.

## Version numbers: X.Y.Z

The version is `X.Y.Z` (MAJOR.MINOR.PATCH, [semantic versioning](https://semver.org)). **Bump exactly one part per PR, the
highest that applies**, and reset every part to its right to 0.

| Part | Name | Bump it when | Resets |
|---|---|---|---|
| **Z** | PATCH | nothing a user can newly do changes and no correct invocation would notice: a bug fix, tests, docs, CI, packaging, a refactor, a dependency update | nothing |
| **Y** | MINOR | something a user can see is added and nothing breaks: a new flag or option, record type, output mode, transport, platform archive or install channel. **While X is 0, a breaking change also bumps Y** | Z to 0 |
| **X** | MAJOR | the public interface breaks, **from 1.0.0 on**. While X is 0 it is reserved: the move to `1.0.0` is the maintainer's deliberate decision to declare the interface stable, never a side effect of a PR | Y and Z to 0 |

For example: `0.7.3` plus a fix is `0.7.4`; plus a new flag is `0.8.0`; plus a renamed flag is `0.8.0` (breaking, before 1.0).
From `1.4.2`: a fix is `1.4.3`, a new flag is `1.5.0`, a renamed flag is `2.0.0`.

**The interface** is what a user or a script can depend on: the flags, options and arguments and their defaults; the output, above
all the `--json` shape (key names and nesting); the exit codes; and what is installed (the `dog` binary, man page and completions).
It is not the Rust code (this crate is a binary), the dependencies, CI, the docs, or how a package is built.

To decide, stop at the first yes:
1. Could something that worked on the previous release now break or behave differently, on purpose? Removing or renaming a flag,
   changing a JSON key or its structure, changing an exit code or a default that scripts rely on. That is **breaking**: put
   `BREAKING:` in the PR title and bump Y (X from 1.0.0).
2. Can a user now do or see something new? That is **Y**.
3. Otherwise, **Z**.

A bug fix is a **patch even if it changes the output**, when the old output was wrong. A dependency update is a patch even when the
dependency's own version jumped, unless it changes something a user sees. A release needs no bump of its own: the last PR to merge
already bumped it.

## Changing the project description

The description is written once, in `packaging/metadata.toml`. Edit it there, then update the copies it names: `Cargo.toml`, the
PKGBUILD and `.SRCINFO`, the RPM spec, the Homebrew formula and the README tagline. `just metadata-check` (part of `just scripts-check`
and of `just pr`) tells you exactly which copy disagrees. The GitHub About box and topics are pushed by hand with
`just github-metadata`, which shows the change and asks first.

## Running the checks locally

You need a stable Rust toolchain with `rustfmt` and `clippy`, plus [`just`](https://github.com/casey/just).
The man page needs [`pandoc`](https://pandoc.org/).

```sh
just          # build, then fmt check, clippy -D warnings, and tests
just man      # build the man page into target/man
```

`just clippy` runs exactly what CI runs, so a clean local run means a clean CI run. A new Rust release can
add lints, so a PR that did not touch the affected code can still start failing on `master`.

## What CI runs

| Job | What it checks |
|---|---|
| Format and Clippy | `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` |
| Test | build, tests, and a no-network smoke test on Linux (x86_64, aarch64, Fedora), macOS and Windows (x86_64, aarch64) |
| Man page | `just man` builds and renders |
| Security Audit | `cargo audit`, on dependency changes and weekly |
| Version bumped | advisory: the version is past `master`'s and the last tag, and `Cargo.lock` agrees |

**A docs-only PR does not run the full suite.** A PR that changes only Markdown at the repository root, `LICENSE`, the screenshot, or
the issue and PR templates skips format, clippy, the tests and the man page; a PR that changes only `man/` runs just the man page.
Anything else runs everything, including every workflow file and Markdown in a subdirectory (which can be a build input). `CI OK`
always reports, so a docs-only PR is never stuck waiting for a skipped check, and it fails if a job your change needs was skipped.
Pushes to `master`, releases and any doubt run the full suite. The version check still runs on every PR, and the required version
bump in `Cargo.toml` and `Cargo.lock` does not make a docs-only PR count as code, provided it changes nothing but dogdns's own version.

## Packaging

`packaging/` holds the templates for COPR, the AUR (`dogdns`) and Homebrew (`l1a/homebrew-dog`). They record no version: the version comes from
`Cargo.toml` when a package is built. Run `just packaging-check` after touching them. The `Packaging` workflow builds a real RPM
in a Fedora container, so a spec that parses but cannot build fails on the PR and not on the first release.

## Releases

1. **A release needs no bump of its own.** The last PR to merge already bumped the version, so `master` is at the version
   to release. Check with `just version-check`: it should report a bump past the previous tag.
2. Tag the tip of `master` and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`. After the tag, `master` stays
   at that version until the next PR bumps it.
3. The `Release` workflow checks the tag against `Cargo.toml` and `Cargo.lock`, runs the full CI suite, then builds
   Linux (x86_64, aarch64), macOS (aarch64) and Windows (x86_64, aarch64) archives. Each holds the binary, the man
   page, shell completions, `LICENSE` and `README.md`. It publishes them with a `SHA256SUMS` file.
4. A tag with a suffix, such as `vX.Y.Z-rc.1`, is published as a pre-release. Only publish packages for a final tag.
5. Only the 20 most recent releases are kept; older releases and their tags are deleted.
6. **COPR** rebuilds by itself when the tag is pushed (`copr.yml`; the tag must be the tip of `master`).
7. **AUR and Homebrew** are published by hand once the release exists, because they are public and immediate:
   `just publish-aur X.Y.Z` and `just publish-brew X.Y.Z`. Each shows the diff and asks you to type the version.
8. **crates.io** is also by hand and cannot be undone. Check with `cargo publish --dry-run`, then `cargo publish`.

To exercise the pipeline without publishing, run the `Release` workflow manually (`workflow_dispatch`). It builds
everything and leaves the archives in the run's artifacts, but skips the publish and prune jobs.
