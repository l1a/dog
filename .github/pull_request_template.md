## Description

Summarise the change and why it is needed.

Fixes # (issue)

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would change existing behaviour)
- [ ] CI, packaging or other tooling
- [ ] This change requires a documentation update

## How has this been tested?

Describe the checks you ran.

## Checklist

- [ ] `just` passes locally (build, `cargo fmt --check`, `clippy -D warnings`, tests)
- [ ] I added or updated tests for the change
- [ ] I updated `README.md`, `man/dog.1.md` or `AGENTS.md` if behaviour or workflow changed
- [ ] **The version is bumped** in `Cargo.toml` (Z for fixes, tests, docs, CI and dependency updates; Y for a new user-visible feature; a breaking change is Y before 1.0.0 and X after; see CONTRIBUTING.md, Version numbers) and `Cargo.lock` is committed with it. Every PR bumps, with no exceptions
- [ ] Opened with `just open-pr`, which runs the pre-PR gate (`just pr`)
- [ ] No failure mode I introduced can degrade silently: it errors, or it is reported
