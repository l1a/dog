#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 l1a
"""Install man page(s) to the XDG man directory. Canonical across repos.

TEMPLATE v3 — vendored verbatim in rusticprofile, retch and etr. Change it here, bump
TEMPLATE_VERSION, and propagate in each repo's own PR. `just standard-check` runs
`--self-test`.

Python rather than a just recipe for the reason retch established: no `sh`, no `cygpath`,
no POSIX `install(1)`, and nothing from Git's `usr\\bin` on Windows.

`--from-tag <TAG>` reads each page out of that git tag instead of the working tree, which
is what `install-tag` needs. Installing a tag's binary beside the worktree's man page —
a v0.2.22 binary with a v0.2.23 page because the checkout had moved on — is exactly the
kind of individually-plausible mismatch these projects exist to refuse. A page that is
not tracked at that tag (etr's pages lived in a gitignored `man/build/` before its #72) is
reported as skipped rather than failing the run, because the binary and completions are
still correctly installed and saying so is more useful than aborting.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

TEMPLATE_VERSION = 3


def man_dir(env, home):
    """The XDG man directory. Pure, so it is testable without touching the environment."""
    xdg_data = Path(env.get("XDG_DATA_HOME") or home / ".local" / "share")
    return xdg_data / "man"


def install_from_tree(page, dest_dir):
    src = Path(page)
    if not src.is_file():
        raise RuntimeError(f"{page} does not exist — run `just man` first")
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    shutil.copyfile(src, dest)
    os.chmod(dest, 0o644)
    return dest


def install_from_tag(page, dest_dir, tag):
    """Read the page out of `tag`. Returns None when it is not tracked there."""
    probe = subprocess.run(["git", "cat-file", "-e", f"{tag}:{page}"], capture_output=True)
    if probe.returncode != 0:
        return None
    res = subprocess.run(["git", "show", f"{tag}:{page}"], capture_output=True)
    if res.returncode != 0:
        raise RuntimeError(f"git show {tag}:{page} failed: {res.stderr.decode(errors='replace')}")
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / Path(page).name
    dest.write_bytes(res.stdout)
    os.chmod(dest, 0o644)
    return dest


def self_test():
    home = Path("/home/u")
    failures = []

    def check(name, got, want):
        if got != want:
            failures.append(f"  {name}\n    expected: {want}\n    got:      {got}")

    check("default man dir", man_dir({}, home), home / ".local" / "share" / "man")
    check("XDG_DATA_HOME honoured", man_dir({"XDG_DATA_HOME": "/x/data"}, home), Path("/x/data") / "man")
    # An empty variable is not a location — otherwise the page lands at /man.
    check("empty XDG_DATA_HOME falls back", man_dir({"XDG_DATA_HOME": ""}, home),
          home / ".local" / "share" / "man")

    if failures:
        print(f"self-test FAILED (template v{TEMPLATE_VERSION}):", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"install_man.py self-test passed (template v{TEMPLATE_VERSION})")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()

    tag = None
    if "--from-tag" in argv:
        i = argv.index("--from-tag")
        if i + 1 >= len(argv):
            print("error: --from-tag needs a tag", file=sys.stderr)
            return 2
        tag = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]

    pages = [a for a in argv if not a.startswith("-")]
    if not pages:
        print("usage: install_man.py <page.1> [page.1...] [--from-tag TAG] | --self-test",
              file=sys.stderr)
        return 2

    dest_dir = man_dir(os.environ, Path.home()) / "man1"
    for page in pages:
        if tag:
            dest = install_from_tag(page, dest_dir, tag)
            if dest is None:
                print(f"  note: {page} is not tracked at {tag}; left as-is "
                      f"(run `just install-man` from a checkout at that tag)")
                continue
            print(f"  {dest.name} <- {tag}")
        else:
            dest = install_from_tree(page, dest_dir)
            print(f"  {dest.name} <- working tree")

    print(f"Man page(s) installed to {dest_dir}")
    print(f"  add {dest_dir.parent} to MANPATH if it is not already there")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
