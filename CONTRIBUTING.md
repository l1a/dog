# Contributing to dog

This is the `l1a/dog` fork of [`ogham/dog`](https://github.com/ogham/dog). DNS parsing and networking
are delegated to [`hickory-resolver`](https://github.com/hickory-dns/hickory-dns).

## Workflow

- `master` is the only long-lived branch. Open pull requests against it from short-lived branches named
  `{feature,fix,chore}/<name>`.
- Write short, imperative commit subjects (50 characters or fewer).
- **Every PR bumps the version in `Cargo.toml`**, with no exception for docs-only, test-only or CI-only changes: a
  **patch** bump for fixes, tests, docs, CI and dependency updates, a **minor** bump for a new user-visible feature.
  Commit `Cargo.lock` with it. The bump is past what `master` currently has, not only past the last tag.
- Open PRs with `just open-pr`, never `gh pr create` directly. It runs `just pr` first: the version check, a locked
  build, fmt, clippy, the tests, an advisory audit, and a checklist. Run `just install-hooks` once per clone for a
  `pre-push` hook that runs fmt and clippy.
- Every PR must pass the `CI OK` check before it is merged. The `Version bumped` job is advisory.
- Dependabot's own PRs are not merged: they close by themselves once `master` carries the update. Open your own PR
  to resolve what it found, and that PR bumps the version like any other.

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

## Packaging

`packaging/` holds the templates for COPR, the AUR (`dogdns`) and Homebrew (`l1a/homebrew-dog`). They record no version: the version comes from
`Cargo.toml` when a package is built. Run `just packaging-check` after touching them. The `Packaging` workflow builds a real RPM
in a Fedora container, so a spec that parses but cannot build fails on the PR and not on the first release.

## Releases

1. **A release needs no bump of its own.** The last PR to merge already bumped the version, so `master` is at the version
   to release. Check with `just version-check`: it should report a bump past the previous tag.
2. Tag the tip of `master` and push the tag: `git tag v0.7.0 && git push origin v0.7.0`. After the tag, `master` stays
   at that version until the next PR bumps it.
3. The `Release` workflow checks the tag against `Cargo.toml` and `Cargo.lock`, runs the full CI suite, then builds
   Linux (x86_64, aarch64), macOS (aarch64) and Windows (x86_64, aarch64) archives. Each holds the binary, the man
   page, shell completions, `LICENSE` and `README.md`. It publishes them with a `SHA256SUMS` file.
4. A tag with a suffix, such as `v0.7.0-rc.1`, is published as a pre-release. Only publish packages for a final tag.
5. Only the 20 most recent releases are kept; older releases and their tags are deleted.
6. **COPR** rebuilds by itself when the tag is pushed (`copr.yml`; the tag must be the tip of `master`).
7. **AUR and Homebrew** are published by hand once the release exists, because they are public and immediate:
   `just publish-aur 0.7.0` and `just publish-brew 0.7.0`. Each shows the diff and asks you to type the version.
8. **crates.io** is also by hand and cannot be undone. Check with `cargo publish --dry-run`, then `cargo publish`.

To exercise the pipeline without publishing, run the `Release` workflow manually (`workflow_dispatch`). It builds
everything and leaves the archives in the run's artifacts, but skips the publish and prune jobs.
