# Release, Packaging, Versioning & CI Reference (`dog`)

Loaded on demand before tagging, publishing, updating `README.md`/`packaging/metadata.toml`, bumping dependencies, or editing packaging templates and CI workflows.
*(See `~/.agents/docs/ops/rust-ci-packaging.md` for shared cross-repo CI, AUR, COPR, Homebrew, Scoop, and Claude Code Review invariants.)*

---

## 1. Semantic Versioning & Bump Gate
`Cargo.toml` uses `X.Y.Z` (`vX.Y.Z-rc.N` pre-release suffixes live only on git tags). **Every merged PR bumps `Cargo.toml` + `Cargo.lock` (no carve-out for docs/tests/CI):**

| Part | Bump when | Resets |
|---|---|---|
| **Z** (PATCH) | Bug fix (even if fixing wrong output), tests, docs, CI, packaging, refactor, dependency update | — |
| **Y** (MINOR) | New user-visible flag/option, record type, output mode, transport, platform/channel; **or any breaking change while X == 0** (`BREAKING:` in PR title/body) | `Z = 0` |
| **X** (MAJOR) | Breaking change from `1.0.0` onward (moving to `1.0.0` is a deliberate maintainer decision) | `Y = 0, Z = 0` |

- **What "the interface" is:** CLI flags/options/args/defaults, text and `--json` output shapes, exit codes, and installed artifacts (`dog`, man page, shell completions) — NOT internal Rust code, dependencies, CI, or docs.
- **Enforcement:** `scripts/version_gate.py --base origin/master` checks numeric bumps against `master` (not just the last tag) and verifies `Cargo.lock` matches (`v0.6.0` once shipped with a stale lockfile; `release.yml`'s `verify` job refuses mismatched tags). `version.yml` is an advisory CI check (skipped for `dependabot[bot]`).

---

## 2. Dependency Updates & Security Audits
- **Dependabot PRs:** Grouped weekly (`cargo` with `hickory-*` first, and `github-actions`). **Never merged directly** — fold/expand via `cargo update` in our own gated PR (bump = patch), because Dependabot only bumps direct deps (`cargo update` moves transitive crates too). Leave Dependabot PRs open to auto-close.
- **Check current state:** `cargo update --dry-run`; compare direct deps on crates.io for incompatible minor/major bumps; check workflow `uses:` SHAs (`rust-toolchain@stable` and `setup-homebrew@main` intentionally float).
- **Verify an update (not just compile):** Build `--locked`, run `just`, `cargo audit`, and compare old vs new binaries on `--completions` for all 6 shells, `--help`, and live UDP/TCP/DoT/DoH/`--json` queries plus hostname nameserver resolution (`@dns.google`, which broke unnoticed from v0.6.0–v0.7.15 because `hickory 0.26`'s `ResolverConfig::default()` has no nameservers — always grep `default()`/`new()` on major bumps!). Note `--json` answers embed TTLs inside zone strings and DoH takes `-H @1.1.1.1` (not a URL).
- **`cargo audit`:** Runs in `security.yml` (fails on vulnerabilities, not warnings/yanked) and advisories in `just pr`. Run `cargo publish --dry-run --locked` (`just publish-check`) before tagging to catch yanked crates (e.g. `tokio 1.54.0`).

---

## 3. Project Description & `packaging/metadata.toml`
- **Single source of truth:** `packaging/metadata.toml` governs crates.io (`Cargo.toml`), AUR (`PKGBUILD`/`.SRCINFO`), COPR spec, Homebrew formula, Scoop manifest, GitHub About (`just github-metadata`, dry-run without confirming), and COPR project page (`copr.yml` on tag).
- **`scripts/metadata_check.py`** (`just metadata-check` in `just pr`) enforces parity and style rules: `summary`/`brew_desc` <= 80 chars, no trailing `.`, no leading article (crates.io exempt), not starting with package name; <= 5 keywords; <= 5 real crates.io category slugs.
- **Verify claims live:** Before releasing, run every README/help claim against the real binary (argument order, `--color`, `--seconds`, `-1`, exit codes, `jq` example, no OpenSSL in dep tree, `--short` prints all answers).

---

## 4. Six-Channel Packaging & Publishing
- **Names:** crate & AUR = **`dogdns`** (avoids abandoned `dog` crate on crates.io); COPR = `kentobias/dog` (RPM `dog`); Homebrew = `l1a/homebrew-dog`; Scoop = `l1a/scoop-dog`; installed binary = `dog`.
- **Zero-drift templates (`scripts/render_packaging.py`):** `packaging/copr/dog.spec`, `packaging/aur/{PKGBUILD.in,SRCINFO.in}`, `packaging/homebrew/dog.rb`, `packaging/scoop/dog.json` carry `@VERSION@`, `@CHANGELOG@`, `@SHA256@`, `@SHA256_X86_64@`, `@SHA256_ARM64@` sentinels. Never put sentinel tokens inside template comments (`just packaging-check` `--self-test` rejects it).
- **Channel quirks:**
  - **COPR:** `.copr/Makefile` builds SRPM from checkout; test full RPM in `podman run registry.fedoraproject.org/fedora:latest` (`install git`, `dnf builddep`, `rpmbuild --rebuild`, `rpm -ivh --nodeps --nosignature` on F45/RPM6, `dog --version`). `--locked` in spec is load-bearing.
  - **AUR:** `options=('!lto')` is required (`ring`'s C code compiled with GCC LTO breaks Rust linking). Never hand-write `.SRCINFO` (`makepkg --printsrcinfo`; build inside container from read-only snapshot so rootless uid mapping never leaves host-unwritable files).
  - **Homebrew:** `packaging.yml` runs `brew trust --formula l1a/test/dog` (required since Homebrew 7.0.11) before `brew audit --strict`.
  - **Scoop:** `dog --version` emits a trailing blank line -> in PowerShell `(& dog --version) -join " "` before `-match`/`-notmatch`.
- **Publishing (`just publish`):** Once tag `v<VERSION>` exists and `release.yml` finishes, `just publish` refuses unless `HEAD == v<VERSION>` and tree is clean; chains crates.io, `just aur-publish` (`AUR_CONFIRM=y`), `just brew-publish` (`BREW_CONFIRM=y`), `just scoop-publish` (`SCOOP_CONFIRM=y`; `PUBLISH_CONFIRM=y` sets all). Release steps live in `CONTRIBUTING.md`. Never run `just install`/`just install-tag` on `dogdns`.

---

## 5. `Claude Code Review` Workflow (`v0.9.4`)
Hardened `claude-code-review.yml` + `.claude/commands/ci-code-review.md` (`v0.9.4`, aligned with `retch`/`etr`/`rusticprofile`). Keep `CLAUDE_CODE_OAUTH_TOKEN` synced in Actions & Dependabot secrets. See `~/.agents/docs/ops/rust-ci-packaging.md` §1.
