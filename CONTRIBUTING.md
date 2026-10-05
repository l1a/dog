# Contributing to dog

This is the `l1a/dog` fork of [`ogham/dog`](https://github.com/ogham/dog). DNS parsing and networking
are delegated to [`hickory-resolver`](https://github.com/hickory-dns/hickory-dns).

## Workflow

- `master` is the only long-lived branch. Open pull requests against it from short-lived branches named
  `{feature,fix,chore}/<name>`.
- Write short, imperative commit subjects (50 characters or fewer).
- Every PR must pass the `CI OK` check before it is merged.

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

## Releases

Pushing a `v*` tag runs the release workflow. Bump the version in `Cargo.toml`, update `Cargo.lock`, and
merge that to `master` before tagging.
