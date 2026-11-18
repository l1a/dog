#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Publish a released version to the AUR or the Homebrew tap.

    publish_packaging.py aur  [X.Y.Z]   # ssh://aur@aur.archlinux.org/dogdns.git
    publish_packaging.py brew [X.Y.Z]   # git@github.com:l1a/homebrew-dog.git
    publish_packaging.py brew 1.2.3 --dry-run
    publish_packaging.py --self-test

Publishing is PUBLIC AND IMMEDIATE (an AUR push is what users install from), so this:

  * downloads the tag tarball and computes the checksum from the bytes it actually got, never
    from a value typed or committed, so the checksum cannot disagree with the tarball;
  * renders from the templates with scripts/render_packaging.py, whose guards refuse a
    substitution that matches nothing or a sentinel that survives;
  * shows the exact diff and requires confirming with the version or 'y' (or AUR_CONFIRM=y /
    BREW_CONFIRM=y / PUBLISH_CONFIRM=y) before it pushes;
  * does nothing if the remote already carries exactly what it would push.

The tag must already exist on GitHub, and the release workflow must have passed: the workflow
refuses a tag whose Cargo.lock is stale, and a package built with --locked cannot be built
from one. --remote and --tarball exist so the whole path can be tested against a local bare
repository without touching a real remote.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render_packaging as rp  # noqa: E402

TARBALL_URL = "https://github.com/l1a/dog/archive/refs/tags/v{version}.tar.gz"

# channel -> (default remote, branch, {target in the render script: path in the remote}, message)
CHANNELS = {
    "aur": (
        "ssh://aur@aur.archlinux.org/dogdns.git",
        "master",  # the AUR only accepts pushes to master
        {"aur-pkgbuild": "PKGBUILD", "aur-srcinfo": ".SRCINFO"},
        "Update to {version}",
    ),
    "brew": (
        "git@github.com:l1a/homebrew-dog.git",
        "main",
        {"brew": "Formula/dog.rb"},
        "dog {version}",
    ),
}


def fetch(source: str) -> bytes:
    """Read a tarball from a URL, or from a local path (used by tests)."""
    if Path(source).is_file():
        return Path(source).read_bytes()
    try:
        with urllib.request.urlopen(source, timeout=60) as r:  # noqa: S310 - https, fixed host
            return r.read()
    except urllib.error.HTTPError as e:
        raise rp.RenderError(
            f"could not download {source} (HTTP {e.code}). Has the tag been pushed to GitHub?"
        ) from e
    except (urllib.error.URLError, ValueError, OSError) as e:
        raise rp.RenderError(f"could not read {source}: {e}") from e


def git(*args: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, check=check, text=True, capture_output=True)


def confirm_publish(channel: str, version: str) -> bool:
    """Ask for explicit confirmation via env var or terminal input."""
    confirm_name = "AUR_CONFIRM" if channel == "aur" else "BREW_CONFIRM"
    for name in (confirm_name, "PUBLISH_CONFIRM"):
        val = os.environ.get(name)
        if val is not None and val != "":
            typed = val.strip()
            print(f"Confirm publish ({name}): {typed}")
            return typed == version or typed.lower() in ("y", "yes")
    try:
        typed = input(f"Type the version ({version}) or 'y' to publish, anything else to abort: ").strip()
    except EOFError:
        print(
            f"error: no terminal to confirm on; re-run with {confirm_name}=y or PUBLISH_CONFIRM=y",
            file=sys.stderr,
        )
        return False
    return typed == version or typed.lower() in ("y", "yes")


def resolve_git_identity() -> list[str]:
    """Return -c user.name/email args from REPO_ROOT when configured."""
    args: list[str] = []
    for key in ("user.name", "user.email"):
        res = git("config", key, cwd=rp.REPO_ROOT, check=False)
        val = res.stdout.strip()
        if res.returncode == 0 and val:
            args.extend(["-c", f"{key}={val}"])
    return args


def self_test() -> None:
    """Verify dry-run, confirm, no-op, abort, default version, and v-prefix handling."""
    saved_env = {
        k: os.environ.get(k)
        for k in (
            "AUR_CONFIRM",
            "BREW_CONFIRM",
            "PUBLISH_CONFIRM",
            "GIT_AUTHOR_NAME",
            "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME",
            "GIT_COMMITTER_EMAIL",
        )
    }
    try:
        for k in ("AUR_CONFIRM", "BREW_CONFIRM", "PUBLISH_CONFIRM"):
            os.environ.pop(k, None)
        os.environ.setdefault("GIT_AUTHOR_NAME", "Test User")
        os.environ.setdefault("GIT_AUTHOR_EMAIL", "test@example.com")
        os.environ.setdefault("GIT_COMMITTER_NAME", "Test User")
        os.environ.setdefault("GIT_COMMITTER_EMAIL", "test@example.com")

        cargo_ver = rp.cargo_version((rp.REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tarball = root / "src.tar.gz"
            tarball.write_bytes(b"test tarball bytes")

            for channel, branch, expected_files in (
                ("aur", "master", ("PKGBUILD", ".SRCINFO")),
                ("brew", "main", ("Formula/dog.rb",)),
            ):
                remote = root / f"{channel}.git"
                subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)

                # 1. --dry-run renders and shows diff without pushing.
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = main([channel, "v1.2.3", "--dry-run", "--remote", str(remote), "--tarball", str(tarball)])
                assert rc == 0, f"{channel} dry-run failed: {buf.getvalue()}"
                assert "dry run: not pushing" in buf.getvalue()
                heads = subprocess.run(["git", "--git-dir", str(remote), "branch"], capture_output=True, text=True, check=True)
                assert not heads.stdout.strip(), f"{channel} dry-run pushed to bare repo"

                # 2. PUBLISH_CONFIRM=no aborts and returns 1 without pushing.
                os.environ["PUBLISH_CONFIRM"] = "no"
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = main([channel, "v1.2.3", "--remote", str(remote), "--tarball", str(tarball)])
                assert rc == 1, f"{channel} abort returned {rc}"
                assert "aborted; nothing was pushed" in buf.getvalue()
                heads = subprocess.run(["git", "--git-dir", str(remote), "branch"], capture_output=True, text=True, check=True)
                assert not heads.stdout.strip(), f"{channel} aborted run pushed to bare repo"

                # 3. PUBLISH_CONFIRM=y pushes rendered files with v-prefix normalized and no sentinels.
                os.environ["PUBLISH_CONFIRM"] = "y"
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = main([channel, "v1.2.3", "--remote", str(remote), "--tarball", str(tarball)])
                assert rc == 0, f"{channel} publish failed: {buf.getvalue()}"
                for path in expected_files:
                    blob = subprocess.run(
                        ["git", "--git-dir", str(remote), "show", f"{branch}:{path}"],
                        capture_output=True,
                        text=True,
                        check=True,
                    ).stdout
                    assert "1.2.3" in blob, f"{channel} {path} missing version 1.2.3"
                    assert not rp.SENTINEL_RE.search(blob), f"{channel} {path} has surviving sentinel"

                # 4. Re-running reports already up to date and exits 0.
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = main([channel, "1.2.3", "--remote", str(remote), "--tarball", str(tarball)])
                assert rc == 0, f"{channel} idempotent re-run failed: {rc}"
                assert "already carries exactly this release" in buf.getvalue()

            # 5. Omitted version defaults to Cargo.toml's version.
            os.environ.pop("PUBLISH_CONFIRM", None)
            brew_remote = root / "brew-default.git"
            subprocess.run(["git", "init", "--bare", "-q", str(brew_remote)], check=True)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["brew", "--dry-run", "--remote", str(brew_remote), "--tarball", str(tarball)])
            assert rc == 0, f"default version dry-run failed: {rc}"
            assert f"/tags/v{cargo_ver}.tar.gz" in buf.getvalue(), (
                f"expected default Cargo.toml version {cargo_ver} in diff:\n{buf.getvalue()}"
            )
        print("publish_packaging.py self-test passed")
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("channel", nargs="?", choices=sorted(CHANNELS))
    ap.add_argument("version", nargs="?")
    ap.add_argument("--dry-run", action="store_true", help="render and show the diff; never push")
    ap.add_argument("--remote", help="override the remote (for tests)")
    ap.add_argument("--tarball", help="override the tarball URL or local path (for tests)")
    ap.add_argument("--self-test", action="store_true", help="run offline self-tests against a local bare repo")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        return 0
    if not args.channel:
        ap.error("channel is required (or pass --self-test)")

    default_remote, branch, files, message = CHANNELS[args.channel]
    remote = args.remote or default_remote
    try:
        raw_version = args.version
        if not raw_version or not raw_version.strip():
            raw_version = rp.cargo_version((rp.REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        version = rp.validate_version(raw_version.strip().lstrip("v"))
        source = args.tarball or TARBALL_URL.format(version=version)
        data = fetch(source)
        sha = hashlib.sha256(data).hexdigest()
        print(f"tarball: {source}\n  {len(data)} bytes, sha256 {sha}")
        rendered = {path: rp.render(target, version, sha) for target, path in files.items()}
    except rp.RenderError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        clone = subprocess.run(["git", "clone", "-q", remote, str(work)], text=True, capture_output=True)
        if clone.returncode != 0:
            print(f"error: could not clone {remote}:\n{clone.stderr}", file=sys.stderr)
            return 1
        # A brand-new repository may have an unborn HEAD (or a default branch differing from
        # `branch`); check out `origin/{branch}` when it exists, otherwise start `{branch}`.
        has_remote_branch = (
            git("rev-parse", "--verify", "-q", f"refs/remotes/origin/{branch}", cwd=work, check=False).returncode
            == 0
        )
        if has_remote_branch:
            git("checkout", "-q", "-B", branch, f"origin/{branch}", cwd=work)
        else:
            git("checkout", "-q", "-B", branch, cwd=work)

        for path, text in rendered.items():
            dest = work / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
        git("add", "-A", cwd=work)

        status = git("status", "--porcelain", cwd=work).stdout
        if not status.strip():
            print(f"{remote} already carries exactly this release. Nothing to publish.")
            return 0

        # `git diff --cached` is empty on an unborn branch for new files in some versions, so
        # show the files themselves when there is no history to diff against.
        print("\n--- what would be pushed ---")
        diff = git("diff", "--cached", "--stat", "-p", cwd=work).stdout
        print(diff if diff.strip() else status)

        if args.dry_run:
            print(f"dry run: not pushing to {remote}")
            return 0

        print(f"This is PUBLIC and IMMEDIATE: {remote} (branch {branch})")
        if not confirm_publish(args.channel, version):
            print("aborted; nothing was pushed")
            return 1

        git(*resolve_git_identity(), "commit", "-q", "-m", message.format(version=version), cwd=work)
        push = subprocess.run(
            ["git", "push", "origin", f"HEAD:{branch}"], cwd=work, text=True, capture_output=True
        )
        if push.returncode != 0:
            print(f"error: push failed:\n{push.stderr}", file=sys.stderr)
            return 1
        print(f"published {args.channel} {version} to {remote}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
