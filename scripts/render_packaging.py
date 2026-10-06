#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Render a packaging template for a version.

The templates under packaging/ record NOTHING about a release: the version and any checksum
are @SENTINELS@, filled in here at build or publish time. The alternative is writing the
version down in the spec, the PKGBUILD, .SRCINFO and the Homebrew formula and keeping them in
step forever, which is how a sibling project's AUR package ended up eleven releases behind
with every CI run green. A stale value cannot be committed when no value is committed.

Two rules matter more than the rest, and both exist because the opposite has bitten before:

  * A substitution that matches nothing is a HARD ERROR. A renderer whose pattern stopped
    matching silently emits the previous release's value.
  * A sentinel that survives rendering is a HARD ERROR. A published package containing a
    literal @VERSION@ is one nobody can build.

No network: a checksum is computed by the caller from the artifact it actually downloaded and
passed in with --sha256. That keeps `--self-test` runnable anywhere.

    render_packaging.py --print-version
    render_packaging.py --target copr --version X.Y.Z --out build/dog.spec
    render_packaging.py --self-test
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Any @UPPERCASE@ token is a sentinel. Deliberately broad, so a sentinel added to a template
# without teaching this script about it fails loudly instead of shipping verbatim.
SENTINEL_RE = re.compile(r"@[A-Z0-9_]+@")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+)+$")

# Attributed to the project, not to `git config user.name`: the COPR render runs inside mock,
# where there is no git configuration and no repository at all.
MAINTAINER = "Ken Tobias <634380+l1a@users.noreply.github.com>"

# target -> (template path, the sentinels it must contain and this script fills)
#
# The AUR is two files rendered from one set of values, which is why they are rendered
# together: PKGBUILD and .SRCINFO restate the same version and checksum, and hand-maintaining
# that agreement is the classic AUR footgun. `.SRCINFO` is never hand-written.
TARGETS = {
    "copr": ("packaging/copr/dog.spec", ("@VERSION@", "@CHANGELOG@")),
    "aur-pkgbuild": ("packaging/aur/PKGBUILD.in", ("@VERSION@", "@SHA256@")),
    "aur-srcinfo": ("packaging/aur/SRCINFO.in", ("@VERSION@", "@SHA256@")),
    "brew": ("packaging/homebrew/dog.rb", ("@VERSION@", "@SHA256@")),
}

# The placeholder digest the self-test renders with. It is never a real checksum.
FAKE_SHA256 = "0" * 64


class RenderError(Exception):
    """The render could not be completed safely."""


def cargo_version(text: str) -> str:
    """Return the [package] version from a Cargo.toml, looking only inside [package].

    Section-aware on purpose: a bare `grep '^version'` would answer confidently about a
    dependency table that carries its own `version`.
    """
    section = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        if section == "package":
            m = re.match(r'^version\s*=\s*"([^"]+)"', stripped)
            if m:
                return m.group(1)
    raise RenderError("no [package] version found in Cargo.toml")


def validate_version(version: str) -> str:
    if not VERSION_RE.match(version):
        raise RenderError(f"not a version number: {version!r}")
    return version


def changelog_entry(version: str, now: float | None = None) -> str:
    """The %changelog entry, generated in the same pass as Version: so they cannot disagree."""
    stamp = time.strftime("%a %b %d %Y", time.gmtime(now if now is not None else time.time()))
    return (
        f"* {stamp} {MAINTAINER} - {version}-1\n"
        f"- Release {version}: https://github.com/l1a/dog/releases/tag/v{version}"
    )


def substitute(template: str, values: dict[str, str], what: str) -> str:
    """Replace each sentinel in `values`. Every one must be present, and none may remain."""
    out = template
    for sentinel, value in values.items():
        if sentinel not in out:
            raise RenderError(f"{what}: template has no {sentinel}; the render would be a no-op")
        out = out.replace(sentinel, value)
    left = sorted(set(SENTINEL_RE.findall(out)))
    if left:
        raise RenderError(f"{what}: unfilled sentinel(s) after rendering: {', '.join(left)}")
    return out


def validate_sha256(sha: str) -> str:
    if not SHA256_RE.match(sha):
        raise RenderError(f"not a lowercase sha256 hex digest: {sha!r}")
    return sha


def render(
    target: str,
    version: str,
    sha256: str | None = None,
    root: Path = REPO_ROOT,
    now: float | None = None,
) -> str:
    if target not in TARGETS:
        raise RenderError(f"unknown target {target!r}; choose from {', '.join(sorted(TARGETS))}")
    path, sentinels = TARGETS[target]
    template = (root / path).read_text(encoding="utf-8")
    values = {"@VERSION@": validate_version(version)}
    if "@CHANGELOG@" in sentinels:
        values["@CHANGELOG@"] = changelog_entry(version, now)
    if "@SHA256@" in sentinels:
        if sha256 is None:
            raise RenderError(f"{path} needs --sha256 (the digest of the tarball actually downloaded)")
        values["@SHA256@"] = validate_sha256(sha256)
    elif sha256 is not None:
        raise RenderError(f"{path} takes no checksum, but --sha256 was given")
    return substitute(template, values, path)


def self_test() -> None:
    """Prove the guards can FAIL, not just that the happy path passes."""
    assert cargo_version('[package]\nname = "x"\nversion = "1.2.3"\n') == "1.2.3"
    # The version of a dependency table must never be mistaken for the package's.
    assert cargo_version('[dependencies.x]\nversion = "9.9.9"\n[package]\nversion = "1.2.3"\n') == "1.2.3"
    for text in ('[dependencies.x]\nversion = "9.9.9"\n', ""):
        try:
            cargo_version(text)
        except RenderError:
            pass
        else:
            raise AssertionError("cargo_version accepted a manifest with no [package] version")

    for bad in ("", "1", "v1.2.3", "1.2.3-rc.1", "1.2.x", "1.2.3 "):
        try:
            validate_version(bad)
        except RenderError:
            pass
        else:
            raise AssertionError(f"validate_version accepted {bad!r}")

    # A substitution that matches nothing must fail...
    try:
        substitute("no sentinels here", {"@VERSION@": "1.2.3"}, "t")
    except RenderError:
        pass
    else:
        raise AssertionError("a no-op substitution was accepted")
    # ...and so must a sentinel the script does not know about.
    try:
        substitute("@VERSION@ @SURPRISE@", {"@VERSION@": "1.2.3"}, "t")
    except RenderError:
        pass
    else:
        raise AssertionError("a surviving sentinel was accepted")

    for bad in ("", "abc", "G" * 64, "A" * 64, "0" * 63, "0" * 65):
        try:
            validate_sha256(bad)
        except RenderError:
            pass
        else:
            raise AssertionError(f"validate_sha256 accepted {bad!r}")
    # A checksum is required where the template has a sentinel for it, and refused where not.
    for args in (("aur-pkgbuild", "1.2.3", None), ("copr", "1.2.3", FAKE_SHA256)):
        try:
            render(*args)
        except RenderError:
            pass
        else:
            raise AssertionError(f"render accepted {args!r}")

    # 2026-10-05 was a Monday; rpm rejects a changelog whose weekday does not match the date.
    assert changelog_entry("1.2.3", now=1791201600.0).startswith("* Mon Oct 05 2026 ")

    # Every real template still carries its sentinels and renders cleanly.
    for target, (path, sentinels) in TARGETS.items():
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        for s in sentinels:
            assert s in text, f"{path} lost {s}"
        # No release may be recorded in a template: a literal version here would drift.
        rendered = render(target, "0.0.1", FAKE_SHA256 if "@SHA256@" in sentinels else None)
        assert "0.0.1" in rendered and not SENTINEL_RE.search(rendered)
        # A sentinel written inside a comment is rewritten along with the real ones, so the
        # published file's own header ends up quoting a version and a digest instead of
        # naming the placeholders. Comments describe the sentinels; they never contain them.
        for n, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("#") and SENTINEL_RE.search(line):
                raise AssertionError(f"{path}:{n}: a sentinel inside a comment would be rewritten: {line.strip()}")
        # A checksum must never be committed in a template either.
        assert not SHA256_RE.search(text.replace("@SHA256@", "")), f"{path} records a checksum"
    print("self-test passed")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--print-version", action="store_true", help="print Cargo.toml's [package] version")
    ap.add_argument("--target", choices=sorted(TARGETS))
    ap.add_argument("--version")
    ap.add_argument("--sha256", help="digest of the source tarball, for targets that pin one")
    ap.add_argument("--out", help="write here instead of stdout")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    try:
        if args.self_test:
            self_test()
        elif args.print_version:
            print(cargo_version((REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8")))
        elif args.target:
            if not args.version:
                raise RenderError("--version is required with --target")
            text = render(args.target, args.version, args.sha256)
            if args.out:
                Path(args.out).write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
        else:
            ap.error("give --print-version, --target, or --self-test")
    except RenderError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
