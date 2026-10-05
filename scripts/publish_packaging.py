#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Publish a released version to the AUR or the Homebrew tap.

    publish_packaging.py aur  0.6.1     # ssh://aur@aur.archlinux.org/dogdns.git
    publish_packaging.py brew 0.6.1     # git@github.com:l1a/homebrew-dog.git
    publish_packaging.py brew 0.6.1 --dry-run

Publishing is PUBLIC AND IMMEDIATE (an AUR push is what users install from), so this:

  * downloads the tag tarball and computes the checksum from the bytes it actually got, never
    from a value typed or committed, so the checksum cannot disagree with the tarball;
  * renders from the templates with scripts/render_packaging.py, whose guards refuse a
    substitution that matches nothing or a sentinel that survives;
  * shows the exact diff and requires you to TYPE THE VERSION before it pushes;
  * does nothing if the remote already carries exactly what it would push.

The tag must already exist on GitHub, and the release workflow must have passed: the workflow
refuses a tag whose Cargo.lock is stale, and a package built with --locked cannot be built
from one. --remote and --tarball exist so the whole path can be tested against a local bare
repository without touching a real remote.
"""

from __future__ import annotations

import argparse
import hashlib
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("channel", choices=sorted(CHANNELS))
    ap.add_argument("version")
    ap.add_argument("--dry-run", action="store_true", help="render and show the diff; never push")
    ap.add_argument("--remote", help="override the remote (for tests)")
    ap.add_argument("--tarball", help="override the tarball URL or local path (for tests)")
    args = ap.parse_args()

    default_remote, branch, files, message = CHANNELS[args.channel]
    remote = args.remote or default_remote
    try:
        version = rp.validate_version(args.version)
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
        # A brand-new AUR package is an empty repository; make sure we push to the right branch.
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
        typed = input(f"Type the version ({version}) to publish, anything else to abort: ").strip()
        if typed != version:
            print("aborted; nothing was pushed")
            return 1

        git("commit", "-q", "-m", message.format(version=version), cwd=work)
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
