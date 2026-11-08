#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 l1a
"""Build and check the tracked man page (`man/dog.1`).

WHY THIS SCRIPT EXISTS
----------------------
1. **Cross-platform `just check` without `bash`**: `just check` runs on Linux, macOS, and
   Windows. A Python implementation needs only `python3` / `python` (via `{{PY}}`) and
   `git`, with no POSIX shell dependency.
2. **Worktree AND `HEAD` verification**: `man-check` verifies both the working-tree
   `man/dog.1` against the working-tree `Cargo.toml` version and `HEAD:man/dog.1`
   against `HEAD:Cargo.toml` so an uncommitted `just man` cannot slip past `pre-push`.
3. **Graceful skip when `mandown` is absent**: On CI runners or contributor machines that
   do not have `mandown` installed, `--check` prints a skip notice and exits 0 (while
   `--build` exits 1 with installation instructions).
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

TEMPLATE_VERSION = 2

REPO_ROOT = Path(__file__).resolve().parent.parent

PAGES: tuple[tuple[Path, str, Path], ...] = (
    (Path("man/dog.1.md"), "DOG", Path("man/dog.1")),
)

Renderer = Callable[[Path, str, str], bytes]

_GIT_LOCAL_ENV_VARS = frozenset(
    {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_PREFIX",
        "GIT_SUPER_PREFIX",
    }
)


class ManPageError(Exception):
    """Raised when `Cargo.toml` cannot be parsed or `mandown` / `git` fails."""


def parse_cargo_version(cargo_toml_text: str) -> str:
    """Extract `version = "X.Y.Z"` from the `[package]` table of `Cargo.toml`."""
    in_package = False
    for raw_line in cargo_toml_text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_package = line == "[package]"
            continue
        if in_package:
            m = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    raise ManPageError("could not find `version = \"...\"` in [package] of Cargo.toml")


def expected_th_header(name: str, version: str) -> bytes:
    """Return the canonical line-1 `.TH` header for `name` and `version`."""
    return f'.TH "{name}" "1" "" "dog {version}" "DNS Client"'.encode("utf-8")


def rewrite_th_header(roff_bytes: bytes, name: str, version: str) -> bytes:
    """Replace line 1 of `mandown` output with `.TH "<NAME>" "1" "" "dog <ver>" ...` and LF."""
    lf_bytes = roff_bytes.replace(b"\r\n", b"\n")
    lf_bytes = lf_bytes.replace(b"\\fB\\fB", b"\\fB").replace(b"\\fP\\fP", b"\\fP")
    header = expected_th_header(name, version)
    _, sep, rest = lf_bytes.partition(b"\n")
    if not sep:
        return header + b"\n"
    return header + b"\n" + rest


def render_with_mandown(md_path: Path, name: str, version: str) -> bytes:
    """Render `md_path` via the `mandown` binary and rewrite its `.TH` header."""
    proc = subprocess.run(
        ["mandown", str(md_path), name, "1"],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        raise ManPageError(f"mandown failed on {md_path} (exit {proc.returncode}): {stderr}")
    return rewrite_th_header(proc.stdout, name, version)


def _unified_diff_preview(actual: bytes, expected: bytes, fromfile: str, tofile: str) -> str:
    actual_lines = actual.decode("utf-8", errors="replace").splitlines(keepends=True)
    expected_lines = expected.decode("utf-8", errors="replace").splitlines(keepends=True)
    diff = list(difflib.unified_diff(actual_lines, expected_lines, fromfile=fromfile, tofile=tofile))
    return "".join(diff[:20]).rstrip("\n")


def build_pages(
    repo_root: Path = REPO_ROOT,
    renderer: Renderer | None = None,
    mandown_lookup: Callable[[str], str | None] = shutil.which,
) -> tuple[int, str]:
    """Render `man/dog.1` into `repo_root`. Returns (exit_code, message)."""
    if renderer is None:
        if mandown_lookup("mandown") is None:
            return 1, "ERROR: mandown is required to build man pages (cargo install mandown)"
        renderer = render_with_mandown

    cargo_toml = repo_root / "Cargo.toml"
    version = parse_cargo_version(cargo_toml.read_text(encoding="utf-8"))
    for md_rel, name, out_rel in PAGES:
        rendered = renderer(repo_root / md_rel, name, version)
        (repo_root / out_rel).write_bytes(rendered)
    return 0, f"Built man/dog.1 (version {version})"


def _git_env(repo_root: Path, *, isolate_config: bool = False) -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in _GIT_LOCAL_ENV_VARS
        and not k.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))
    }
    env["GIT_TERMINAL_PROMPT"] = "0"
    if isolate_config:
        for k in list(env):
            if k.startswith(("GIT_AUTHOR_", "GIT_COMMITTER_")):
                del env[k]
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        env["HOME"] = str(repo_root)
        env["XDG_CONFIG_HOME"] = str(repo_root)
    return env


def _git_has_head(repo_root: Path) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "-q", "--verify", "HEAD"],
        cwd=repo_root,
        env=_git_env(repo_root),
        capture_output=True,
        check=False,
    )
    return proc.returncode == 0


def _git_short_head(repo_root: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--short", "HEAD"],
        cwd=repo_root,
        env=_git_env(repo_root),
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def _git_show_bytes(repo_root: Path, rev_path: str) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "show", rev_path],
        cwd=repo_root,
        env=_git_env(repo_root),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        raise ManPageError(f"`git show {rev_path}` failed: {stderr}")
    return proc.stdout


def _check_header_and_lf(raw: bytes, label: str, name: str, version: str) -> str | None:
    """Verify LF line endings and the `.TH` version header even when mandown is absent."""
    if not raw:
        return f"error: {label} is missing or empty — run 'just man' and commit the result."
    if b"\r" in raw:
        return f"error: {label} contains carriage returns (CRLF) — run 'just man' to normalise to LF."
    first_line = raw.partition(b"\n")[0]
    expected_th = expected_th_header(name, version)
    if first_line != expected_th:
        return (
            f"error: {label} is stale (line 1 is {first_line.decode('utf-8', errors='replace')!r}, "
            f"expected {expected_th.decode('utf-8')!r}) — run 'just man' and commit the result."
        )
    return None


def check_pages(
    repo_root: Path = REPO_ROOT,
    renderer: Renderer | None = None,
    mandown_lookup: Callable[[str], str | None] = shutil.which,
) -> tuple[int, str]:
    """Verify worktree and HEAD man pages are current. Returns (exit_code, message)."""
    if renderer is None and mandown_lookup("mandown") is not None:
        renderer = render_with_mandown

    # 1. Worktree check (.TH header + LF always; full mandown render when available).
    version = parse_cargo_version((repo_root / "Cargo.toml").read_text(encoding="utf-8"))
    for md_rel, name, man_rel in PAGES:
        man_path = repo_root / man_rel
        actual = man_path.read_bytes() if man_path.is_file() else b""
        hdr_err = _check_header_and_lf(actual, man_rel.as_posix(), name, version)
        if hdr_err is not None and renderer is None:
            return 1, hdr_err
        if renderer is not None:
            expected = renderer(repo_root / md_rel, name, version)
            if actual != expected:
                preview = _unified_diff_preview(
                    actual, expected, str(man_rel.as_posix()), f"{man_rel.as_posix()} (rendered)"
                )
                msg = (
                    f"error: {man_rel.as_posix()} is stale — run 'just man' and commit the result.\n"
                    "       (the .TH line embeds the version, so a version bump always changes it)"
                )
                if preview:
                    msg = f"{msg}\n{preview}"
                return 1, msg

    # 2. HEAD check, against itself.
    if not _git_has_head(repo_root):
        return 0, (
            f"man pages are current (version {version}); "
            "no HEAD commit, committed-tree check skipped"
        )

    head_cargo = _git_show_bytes(repo_root, "HEAD:Cargo.toml").decode("utf-8")
    head_version = parse_cargo_version(head_cargo)

    if renderer is None:
        for _, name, man_rel in PAGES:
            committed_man = _git_show_bytes(repo_root, f"HEAD:{man_rel.as_posix()}")
            hdr_err = _check_header_and_lf(
                committed_man, f"the COMMITTED {man_rel.as_posix()}", name, head_version
            )
            if hdr_err is not None:
                return 1, hdr_err
        return 0, (
            f"man pages .TH headers are current (worktree {version}, HEAD {head_version}); "
            "mandown not installed — skipping body re-render (cargo install mandown)"
        )

    docs_dir = repo_root / "man"
    with tempfile.TemporaryDirectory(prefix=".man-check.", dir=docs_dir) as tmp:
        tmp_dir = Path(tmp)
        for md_rel, name, man_rel in PAGES:
            committed_md = _git_show_bytes(repo_root, f"HEAD:{md_rel.as_posix()}")
            committed_man = _git_show_bytes(repo_root, f"HEAD:{man_rel.as_posix()}")
            tmp_md = tmp_dir / md_rel.name
            tmp_md.write_bytes(committed_md)
            expected_head = renderer(tmp_md, name, head_version)
            if committed_man != expected_head:
                short_sha = _git_short_head(repo_root)
                preview = _unified_diff_preview(
                    committed_man,
                    expected_head,
                    f"HEAD:{man_rel.as_posix()}",
                    f"HEAD:{man_rel.as_posix()} (rendered for {head_version})",
                )
                msg = (
                    f"error: the COMMITTED {man_rel.as_posix()} (HEAD {short_sha}) is stale for the\n"
                    f"       committed Cargo.toml version {head_version}, although the worktree copy is current.\n"
                    "       Usually a commit or --amend made without staging man/dog.1. Fix:\n"
                    "         git add man/dog.1 && git commit --amend --no-edit"
                )
                if preview:
                    msg = f"{msg}\n{preview}"
                return 1, msg

    return 0, f"man pages are current (worktree {version}, HEAD {head_version})"


def _stub_renderer(md_path: Path, name: str, version: str) -> bytes:
    body = md_path.read_bytes().replace(b"\r\n", b"\n")
    raw = f'.TH "{name}" 1\n.SH "NAME"\n'.encode("utf-8") + body
    return rewrite_th_header(raw, name, version)


def _git_fixture(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=root,
        env=_git_env(root, isolate_config=True),
        capture_output=True,
        check=True,
    )


def _init_fixture_repo(root: Path, version: str = "0.2.0") -> None:
    (root / "man").mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        f'[package]\nname = "dog"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    (root / "man/dog.1.md").write_text("# dog(1)\nBackup body.\n", encoding="utf-8")
    rc, _ = build_pages(root, renderer=_stub_renderer)
    assert rc == 0
    _git_fixture(root, "init", "-q")
    _git_fixture(root, "add", "Cargo.toml", "man/dog.1.md", "man/dog.1")
    _git_fixture(root, "commit", "-q", "-m", "initial")


def self_test() -> int:
    failures: list[str] = []

    def check(label: str, cond: bool, detail: str = "") -> None:
        if not cond:
            failures.append(f"{label}: {detail}")

    sample_toml = (
        '[workspace]\nmembers = ["."]\n\n'
        '[package]\nname = "dog"\nversion = "1.2.3"\n\n'
        '[dependencies]\nfoo = { version = "9.9.9" }\n'
    )
    check(
        "[package] version parsed, ignoring [dependencies]",
        parse_cargo_version(sample_toml) == "1.2.3",
        parse_cargo_version(sample_toml),
    )

    rewritten = rewrite_th_header(
        b'.TH "DOG" 1\r\n.SH "NAME"\r\n\\fB\\fBdog\\fP\\fP\r\n',
        "DOG",
        "1.2.3",
    )
    check(
        ".TH header rewritten, double escapes collapsed, and CRLF normalised to LF",
        rewritten
        == b'.TH "DOG" "1" "" "dog 1.2.3" "DNS Client"\n.SH "NAME"\n\\fBdog\\fP\n'
        and b"\r" not in rewritten,
        repr(rewritten),
    )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "clean"
        _init_fixture_repo(root, "0.2.0")
        rc, msg = check_pages(root, renderer=_stub_renderer)
        check("clean worktree + HEAD passes", rc == 0, msg)

        (root / "Cargo.toml").write_text(
            '[package]\nname = "dog"\nversion = "0.2.1"\n',
            encoding="utf-8",
        )
        rc, msg = check_pages(root, renderer=_stub_renderer)
        check(
            "worktree version bump without 'just man' is refused",
            rc == 1 and "man/dog.1 is stale" in msg,
            f"rc={rc} msg={msg!r}",
        )

        _git_fixture(root, "add", "Cargo.toml")
        _git_fixture(root, "commit", "-q", "-m", "bump without man")
        build_pages(root, renderer=_stub_renderer)
        rc, msg = check_pages(root, renderer=_stub_renderer)
        check(
            "uncommitted 'just man' after a version-bump commit is refused (HEAD check)",
            rc == 1 and "COMMITTED man/dog.1" in msg and "0.2.1" in msg,
            f"rc={rc} msg={msg!r}",
        )

        _git_fixture(root, "add", "man/dog.1")
        _git_fixture(root, "commit", "-q", "--amend", "--no-edit")
        rc, msg = check_pages(root, renderer=_stub_renderer)
        check("amending man/dog.1 into HEAD restores green", rc == 0, msg)

        man_file = root / "man/dog.1"
        man_file.write_bytes(man_file.read_bytes().replace(b"\n", b"\r\n"))
        rc, msg = check_pages(root, renderer=_stub_renderer)
        check("CRLF in worktree man/dog.1 is refused", rc == 1, f"rc={rc} msg={msg!r}")
        man_file.write_bytes(man_file.read_bytes().replace(b"\r\n", b"\n"))

        rc_skip, msg_skip = check_pages(root, renderer=None, mandown_lookup=lambda _: None)
        check(
            "missing mandown checks .TH and skips body render with exit 0",
            rc_skip == 0 and "skipping" in msg_skip,
            f"rc={rc_skip} msg={msg_skip!r}",
        )
        (root / "Cargo.toml").write_text(
            '[package]\nname = "dog"\nversion = "0.9.9"\n',
            encoding="utf-8",
        )
        rc_stale, msg_stale = check_pages(root, renderer=None, mandown_lookup=lambda _: None)
        check(
            "missing mandown still catches stale .TH version",
            rc_stale == 1 and "man/dog.1 is stale" in msg_stale,
            f"rc={rc_stale} msg={msg_stale!r}",
        )
        rc_build, msg_build = build_pages(root, renderer=None, mandown_lookup=lambda _: None)
        check(
            "missing mandown fails --build with exit 1",
            rc_build == 1 and "mandown is required" in msg_build,
            f"rc={rc_build} msg={msg_build!r}",
        )

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1
    print(f"man_pages.py self-test passed (template v{TEMPLATE_VERSION})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--build", action="store_true", help="render man/dog.1 from man/dog.1.md")
    group.add_argument("--check", action="store_true", help="verify worktree and HEAD man pages are current")
    group.add_argument("--self-test", action="store_true", help="run the guard's negative controls")
    args = parser.parse_args()

    try:
        if args.self_test:
            return self_test()
        if args.build:
            rc, msg = build_pages()
        else:
            rc, msg = check_pages()
    except ManPageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    stream = sys.stderr if rc != 0 else sys.stdout
    print(msg, file=stream)
    return rc


if __name__ == "__main__":
    sys.exit(main())
