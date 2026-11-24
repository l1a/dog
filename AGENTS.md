# Dog — DNS Client (`AGENTS.md`)

A command-line DNS client (like `dig`, but friendlier) using [`hickory-resolver`](https://github.com/hickory-dns/hickory-dns).
**Trunk branch is `master`** (fork of `ogham/dog` — always pass `--repo l1a/dog` to `gh`, or use `just open-pr`).

---

# Part 1 — Core Rules & Workflow

## STEP ONE — READ IN FULL BEFORE ANYTHING ELSE
1. **Read `~/AGENTS.md` (if present), this file (`AGENTS.md`), and `WIP.md` in full** before editing code or running commands (never `head`/`grep`-skim).
2. **Load Tier 1 docs on trigger:** Read `docs/RELEASE.md` in full before tagging, publishing, bumping dependencies, or editing `packaging/` / `README.md` / `CONTRIBUTING.md` / CI workflows; read `~/.gemini/skills/chezmoi-manager/SKILL.md` before any `chezmoi` command.
3. **Agent-agnostic & no agent-only memory:** Enforce rules via `Justfile` + `scripts/hooks/pre-push` rather than `.claude/`-only config. Record durable learnings in `AGENTS.md`/`docs/` in the same turn.

## 1. Source Control, PRs & Attribution
- **Branch first:** Switch to `{feature,fix,chore,docs}/<name>` **before** modifying files (`docs/` is enforced by `scripts/branch_gate.py` for root Markdown / `man/` / `.github/ISSUE_TEMPLATE/` + `Cargo.{toml,lock}` version-only bumps; changes touching `docs/RELEASE.md`, `src/`, `scripts/`, `packaging/`, or `.github/workflows/` MUST use `feature/`, `fix/`, or `chore/`).
- **Authorization gates:** NEVER run `git commit`, `git push`, `gh pr create`, or merge without explicit authorization (`ask_question` with clickable options + prose context).
- **Commit & attribution:** Imperative subject <= 50 chars; bare `Assisted-By: <model name>` (no suffixes/URLs, never `Co-Authored-By:`). Never include personal machine hostnames in public PRs, commits, comments, or docs.
- **Pre-merge checks:** Inspect all 3 review channels (`reviewThreads`, `latestReviews`, top-level `comments`) plus CodeQL alerts (`just merge-pr` enforces fail-closed). Check `gh pr list --repo l1a/dog --author "app/dependabot"`, fold updates into a gated PR, and **never manually close Dependabot PRs**.

## 2. `WIP.md` Handoff
Read `WIP.md` at session start; update outside `<!-- BEGIN merge-pr state -->` / `<!-- END merge-pr state -->` when switching branches, pushing, or ending a session (`just merge-pr` runs `scripts/reset_wip.py` to update the marked state block). Keep pure LF (`just wip-check`).

---

# Part 2 — Project-Specific: `dog`

## 1. Build & Project Structure
```sh
cargo build --release   # may need libssl-dev (or vendored TLS if configured)
```
- `src/main.rs` — entry point & `hickory-resolver` (`DogDnsHandle` wrapping `RetryDnsHandle<NameServerPool>` + `CachingClient`)
- `src/options.rs` — CLI parsing
- `src/output.rs` — JSON/Text formatting & terminal control-char sanitization
- `src/table.rs` — columnar terminal table rendering
- `src/hints.rs` — bounded `/etc/hosts` advisory local-hostname hints
- **`src/stdout.rs` — ONLY allowed stdout writer.** Never use `print!` or `println!` in `src/` (Rust ignores `SIGPIPE` -> panic exit 101 on `dog ... | head`). `stdout::emit*` exits `0` quietly (`#![deny(clippy::print_stdout)]` + `tests/broken_pipe.rs`; `eprintln!` is fine).

## 2. Testing & Smoke Gate
- `cargo test` (`just test`): unit tests (`options`, `main`, `output`, `table`, `hints`), `tests/broken_pipe.rs`, and offline loopback UDP/TCP DNS tests (`tests/protocol_and_security.rs`). *(Legacy `xtests/` and `dns/` wire tests are obsolete.)*
- **`scripts/smoke_dns.sh` (`just smoke-dns`):** Live online smoke check in CI (`test` job on all matrix OSes). Queries `8.8.8.8` (`ANY`, `--json A`, `--short NS`) and `@dns.google` (UDP + DoH), checking response shapes with 3 retries. (`dog`'s `ANY` sends per-type queries, 8 responses / 27 answers for `google.com`.) `.gitattributes` pins LF on `*.sh`.

## 3. Versioning, Pre-PR Gate & CI
- **Every merged PR bumps `Cargo.toml` + `Cargo.lock`** (`Z` for fixes/tests/docs/CI/deps, `Y` for user-visible features or pre-1.0 breaking changes — full rules in `docs/RELEASE.md`).
- **Man page (`man/dog.1.md` -> committed `man/dog.1`):** Run `just man` after every version bump or `man/dog.1.md` edit (`just man-check` checks worktree and `HEAD`).
- **Pre-PR gate:** Run `just pr` (feature branch, clean tree, `version_gate.py --base origin/master`, `just check` = `fmt-check`, `clippy`, `standard-check`, `man-check`, `packaging-check`, `scripts-check`, `text-check`, `wip-check`, `cargo build --locked`, `just test`, advisory `cargo audit`, manual checklist with `PR_CONFIRM=y`), or `just open-pr` (`[positional-arguments]` + `"$@"`, passes `--repo l1a/dog --base master`). Install `pre-push` hook with `just install-hooks` (`GIT_NO_CHECK=1` skips once).
- **CI (`ci.yml`, `CI OK` = `scripts/ci_gate.py`):** Checks every job group (`Format and Clippy`, `Test (...)`, `Man page`) explicitly for `success` — GitHub queue cancellations (~15m `timeout-minutes` excludes queue wait) report `abandoned`, not `cancelled`! Check queue reasons via `gh api repos/l1a/dog/check-runs/<id>/annotations` and rerun failed legs with `gh run rerun <id> --failed`.
- **Hickory crate rule:** Always update `hickory-resolver`, `hickory-net`, and `hickory-proto` together (`cargo update -p hickory-resolver`).
- **Merging (`just merge-pr`):** Verifies checks green and zero unresolved bot/review findings via GraphQL (`MERGE_ALLOW_COMMENTS=1` after verification), merges with `--merge`, and resets `WIP.md`.
- **Packaging / Releases:** Read `docs/RELEASE.md` (and `~/.agents/docs/ops/rust-ci-packaging.md`) before touching `packaging/`, `metadata.toml`, `release.yml`, or running `just publish`.

---

## 4. Sandbox Bypass (`BypassSandbox: true`) & Learning Loop
Per `~/AGENTS.md` §3, pass `BypassSandbox: true` on the **first** invocation of:
- **All `gh` / `ghpub` commands** (`gh pr`, `gh run`, `gh workflow`, `gh api`, `gh issue`).
- **All `git` write or remote commands** (`checkout`, `switch`, `branch`, `add`, `rm`, `mv`, `commit`, `merge`, `rebase`, `tag`, `fetch`, `pull`, `push`).
- **`just` shebang, network, and container recipes:** `just pr` / `PR_CONFIRM=y just pr`, `PR_CONFIRM=y just open-pr --fill`, `just merge-pr`, `just prune-branches`, `just install-tag`, `just smoke-dns` / `scripts/smoke_dns.sh`, `just github-metadata`, `just aur-publish`/`publish-aur`, `just brew-publish`/`publish-brew`, `just scoop-publish`/`publish-scoop`, `just publish`, `just publish-check`, `just audit`, `just update-deps`, `just coverage-docker`.
- **Cargo network/unpack ops:** `cargo --config net.retry=0 update`, `cargo fetch`, `cargo publish`, `cargo audit`, and first `cargo` build/test when a locked crate is uncached/unpacked in `~/.cargo/registry/src/`.
- **Works inside sandbox (`BypassSandbox: false`):** `just`, `just build`, `build-release`, `build-quick`, `check`, `test`, `test-release`, `test-quick`, `fmt`, `fmt-check`, `clippy`, `lint`, `standard-check`, `man`, `man-check`, `packaging-check`, `render-check`, `copr-check`, `scoop-check`, `copr-render`, `scripts-check`, `metadata-check`, `text-check`, `wip-check`, `version-check`, `python3 scripts/*.py --self-test`, and read-only `git` (`status`, `diff`, `log`, `show`, `rev-parse`, `for-each-ref`).
- **Repo-Local Sandbox Learning Loop:** Stage new exceptions in `WIP.md` (`## Sandbox Exceptions (staged for AGENTS.md)`) if tree must stay clean; fold into this section on the next PR.

## 5. Known Issues
- TLS configurations may require system libraries or cross-compilation toolchains depending on target OS.
