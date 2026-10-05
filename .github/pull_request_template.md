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
- [ ] If the version was bumped, `Cargo.lock` was updated and committed with it
- [ ] No failure mode I introduced can degrade silently: it errors, or it is reported
