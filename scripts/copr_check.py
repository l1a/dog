#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 l1a
"""Assert packaging/copr/dog.spec is still a template that records no release.

WHAT IT CHECKS
--------------
All offline, deterministic, and free:

  1. `Version:` is exactly `@VERSION@`.
  2. Nothing else in the preamble records a version number.
  3. `Source0` is the LOCAL `%{name}-%{version}.tar.gz`.
  4. `cargo build` still passes `--locked`.
  5. `%license LICENSE` is present in `%files`.
  6. The newest `%changelog` entry is a real historical entry, not a sentinel.
  7. In `--self-test`, executes `.github/workflows/copr.yml`'s `Configure copr-cli` step to
     verify that missing credentials FAIL on `l1a/dog` and skip only on a fork.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

TEMPLATE_VERSION = 1

CREDS_STEP = "Configure copr-cli"
CANONICAL_REPO = "l1a/dog"


class ParseError(Exception):
    """The spec used a construct this parser does not understand."""


def _preamble(text: str) -> str:
    """Everything before the first `%`-section directive."""
    out = []
    for line in text.splitlines():
        if re.match(r"^%(prep|build|install|check|files|changelog|description|package)\b", line):
            break
        out.append(line)
    return "\n".join(out)


def spec_tag(text: str, tag: str) -> str:
    m = re.search(rf"^{tag}:\s*(\S.*?)\s*$", _preamble(text), re.MULTILINE)
    if not m:
        raise ParseError(f"spec has no `{tag}:` tag in its preamble")
    return m.group(1)


def spec_version(text: str) -> str:
    return spec_tag(text, "Version")


def spec_source0(text: str) -> str:
    return spec_tag(text, "Source0")


def newest_changelog_entry(text: str) -> str:
    m = re.search(r"^%changelog\s*$(.*)", text, re.MULTILINE | re.DOTALL)
    if not m:
        raise ParseError("spec has no %changelog section")
    for line in m.group(1).splitlines():
        if line.strip() == "@CHANGELOG@":
            return "0.0.0-1"
        if line.startswith("*"):
            trailer = re.search(r"-\s*(\S+)\s*$", line)
            if not trailer:
                raise ParseError(f"newest %changelog entry has no `- <version>-<release>`: {line!r}")
            return trailer.group(1)
    raise ParseError("%changelog section contains no entries")


VERSIONISH_RE = re.compile(r"\b[0-9]+\.[0-9]+\.[0-9]+\b")
LOCAL_SOURCE0 = "%{name}-%{version}.tar.gz"


def check_template(spec_text: str) -> list[str]:
    """Return a list of human-readable problems; empty means the spec is still a template."""
    problems: list[str] = []

    version = spec_version(spec_text)

    if version != "@VERSION@":
        problems.append(
            f"Version: is {version!r}, not '@VERSION@' — this spec is a template; "
            ".copr/Makefile renders it from Cargo.toml when it builds the SRPM"
        )

    for line in _preamble(spec_text).splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = VERSIONISH_RE.search(line)
        if m:
            problems.append(f"preamble line records a version ({m.group(0)}): {line.strip()!r}")

    source0 = spec_source0(spec_text)
    if source0 != LOCAL_SOURCE0:
        problems.append(
            f"Source0 is {source0!r}, not {LOCAL_SOURCE0!r} — .copr/Makefile builds the "
            "source archive from the checkout"
        )

    if not re.search(r"^\s*cargo build\b.*--locked", spec_text, re.MULTILINE):
        problems.append(
            "the %build `cargo build` does not pass --locked — with internet-enabled COPR "
            "builds and no vendor tarball it is the only thing pinning dependency resolution"
        )

    if not re.search(r"^%license\s+.*\bLICENSE\b", spec_text, re.MULTILINE):
        problems.append("%files does not carry `%license LICENSE`")

    newest = newest_changelog_entry(spec_text)
    if "@" in newest:
        problems.append(
            f"the newest %changelog entry is a sentinel ({newest}) — render_packaging.py "
            "prepends the entry for the rendered version, so this one must be history"
        )

    return problems


def step_run_script(workflow_text: str, step_name: str) -> str:
    lines = workflow_text.splitlines()
    name_re = re.compile(rf"^\s*-\s+name:\s*{re.escape(step_name)}\s*$")
    start = next((i for i, line in enumerate(lines) if name_re.match(line)), None)
    if start is None:
        raise ParseError(f"workflow has no step named {step_name!r}")
    for j in range(start + 1, len(lines)):
        if re.match(r"^\s*-\s+name:", lines[j]):
            break
        m = re.match(r"^(\s*)run:\s*\|\s*$", lines[j])
        if m:
            indent = len(m.group(1))
            body = []
            for line in lines[j + 1 :]:
                if line.strip() and len(line) - len(line.lstrip()) <= indent:
                    break
                body.append(line)
            return textwrap.dedent("\n".join(body)) + "\n"
    raise ParseError(f"step {step_name!r} has no `run: |` block")


def creds_step_outcome(script: str, repo: str, with_creds: bool) -> tuple[int, str, str, bool]:
    with tempfile.TemporaryDirectory() as home:
        github_env = os.path.join(home, "github_env")
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": home,
            "GITHUB_ENV": github_env,
            "GITHUB_REPOSITORY": repo,
        }
        if with_creds:
            env.update(COPR_LOGIN="login", COPR_USERNAME="user", COPR_TOKEN="token")
        proc = subprocess.run(
            ["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30
        )
        written = ""
        if os.path.isfile(github_env):
            with open(github_env, encoding="utf-8") as fh:
                written = fh.read()
        wrote_config = os.path.isfile(os.path.join(home, ".config", "copr"))
        return proc.returncode, proc.stdout + proc.stderr, written, wrote_config


def check_creds_step(workflow_text: str) -> list[str]:
    problems: list[str] = []
    script = step_run_script(workflow_text, CREDS_STEP)

    code, out, genv, _ = creds_step_outcome(script, CANONICAL_REPO, with_creds=False)
    if code == 0:
        problems.append(f"{CANONICAL_REPO} without credentials exits 0: a green run that rebuilds nothing")
    if "::error::" not in out:
        problems.append(f"{CANONICAL_REPO} without credentials prints no ::error:: annotation")
    if "skip=true" in genv:
        problems.append(f"{CANONICAL_REPO} without credentials still marks the rebuild skipped")

    code, out, genv, _ = creds_step_outcome(script, "someone/dog", with_creds=False)
    if code != 0:
        problems.append(f"a fork without credentials fails (exit {code}); it must skip: {out.strip()}")
    if "skip=true" not in genv:
        problems.append("a fork without credentials does not set skip=true")

    code, out, genv, wrote = creds_step_outcome(script, CANONICAL_REPO, with_creds=True)
    if code != 0 or not wrote or "skip=false" not in genv:
        problems.append(
            f"{CANONICAL_REPO} WITH credentials does not configure copr-cli "
            f"(exit {code}, config written: {wrote}, GITHUB_ENV {genv!r})"
        )
    return problems


# --------------------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------------------

_GOOD_SPEC = """\
# COPR spec for dog. A comment may cite 0.2.35 as history without that being a pin.
Name:           dog
Version:        @VERSION@
Release:        1%{?dist}
Summary:        A local, per-machine scheduler and orchestrator for rustic backups

License:        GPL-3.0-or-later
URL:            https://github.com/l1a/dog
Source0:        %{name}-%{version}.tar.gz

%description
dog is a backup scheduler. Version: numbers in prose must not be
read as the package's own version, and neither must a 1.2.3 written here.

%build
export RUSTFLAGS="%{build_rustflags}"
cargo build --release --locked

%files
%license LICENSE
%doc README.md
%{_bindir}/dog

%changelog
* Thu Nov 05 2026 Ken Tobias <nobody@example.com> - 0.2.56-1
- Update to 0.2.56

* Wed Sep 09 2026 Ken Tobias <nobody@example.com> - 0.2.35-1
- Initial COPR packaging
"""


def _self_test() -> int:
    failures = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        if not cond:
            failures.append(f"{name}: {detail}")

    clean = check_template(_GOOD_SPEC)
    check("template fixture clean", clean == [], f"got {clean}")

    live = Path(__file__).resolve().parent.parent / "packaging" / "copr" / "dog.spec"
    if live.is_file():
        live_problems = check_template(live.read_text(encoding="utf-8"))
        check("live spec clean", live_problems == [], f"got {live_problems}")

    pinned = _GOOD_SPEC.replace("Version:        @VERSION@", "Version:        0.2.56")
    probs = check_template(pinned)
    check("pinned Version detected", any("Version:" in p for p in probs), f"got {probs}")

    smuggled = _GOOD_SPEC.replace(
        "License:        GPL-3.0-or-later",
        "Provides:       dog = 0.2.56\nLicense:        GPL-3.0-or-later",
    )
    probs = check_template(smuggled)
    check("preamble version detected", any("records a version" in p for p in probs), f"got {probs}")

    check(
        "prose version ignored",
        not any("records a version" in p for p in check_template(_GOOD_SPEC)),
        "the 1.2.3 in %description was read as a pin",
    )

    url_source = _GOOD_SPEC.replace(
        "Source0:        %{name}-%{version}.tar.gz",
        "Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz",
    )
    probs = check_template(url_source)
    check("URL Source0 detected", any("Source0" in p for p in probs), f"got {probs}")

    unlocked = _GOOD_SPEC.replace("cargo build --release --locked", "cargo build --release")
    probs = check_template(unlocked)
    check("--locked removal detected", any("--locked" in p for p in probs), f"got {probs}")

    bad_lic = _GOOD_SPEC.replace("%license LICENSE", "%doc LICENSE")
    probs = check_template(bad_lic)
    check("%license downgraded to %doc detected", any("%license" in p for p in probs), f"got {probs}")

    sentinel_log = _GOOD_SPEC.replace("- 0.2.56-1", "- @VERSION@-1")
    probs = check_template(sentinel_log)
    check("sentinel changelog detected", any("%changelog" in p for p in probs), f"got {probs}")

    check("preamble scoped", spec_version(_GOOD_SPEC) == "@VERSION@", f"got {spec_version(_GOOD_SPEC)}")
    check("newest changelog entry", newest_changelog_entry(_GOOD_SPEC) == "0.2.56-1", f"got {newest_changelog_entry(_GOOD_SPEC)!r}")

    try:
        spec_version("Name: dog\n")
        check("missing Version raises", False, "spec_version accepted a spec with no Version:")
    except ParseError:
        pass

    if os.name == "nt" or not shutil.which("bash"):
        print("copr_check.py: credentials-guard checks skipped (no POSIX bash here)")
    else:
        live_wf = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "copr.yml"
        if live_wf.is_file():
            live_problems = check_creds_step(live_wf.read_text(encoding="utf-8"))
            check("live copr.yml credentials guard", live_problems == [], f"got {live_problems}")

        old_guard = textwrap.dedent("""\
            jobs:
              copr:
                steps:
                  - name: Configure copr-cli
                    run: |
                      set -euo pipefail
                      if [ -z "${COPR_LOGIN:-}" ] || [ -z "${COPR_TOKEN:-}" ] || [ -z "${COPR_USERNAME:-}" ]; then
                        echo "::notice::COPR credentials not configured; skipping the rebuild"
                        echo "skip=true" >> "$GITHUB_ENV"
                        exit 0
                      fi
                      mkdir -p ~/.config
                      echo "[copr-cli]" > ~/.config/copr
                      echo "skip=false" >> "$GITHUB_ENV"

                  - name: Next step
                    run: |
                      echo "must not be read as part of the step above"
            """)
        probs = check_creds_step(old_guard)
        check("skip-everywhere guard detected", any("exits 0" in p for p in probs), f"got {probs}")
        check("a fork skipping is not what fires", not any("fork" in p for p in probs), f"got {probs}")
        check(
            "the step body stops at the next step",
            "must not be read" not in step_run_script(old_guard, CREDS_STEP),
            step_run_script(old_guard, CREDS_STEP),
        )
        try:
            step_run_script(old_guard, "No such step")
            check("missing step raises", False, "step_run_script accepted a missing step")
        except ParseError:
            pass

    if failures:
        for f in failures:
            print(f"  FAIL {f}", file=sys.stderr)
        print(f"copr_check.py self-test FAILED ({len(failures)})", file=sys.stderr)
        return 1
    print(f"copr_check.py self-test passed (template v{TEMPLATE_VERSION})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true", help="run built-in tests and exit")
    ap.add_argument("--root", default=None, help="repository root (default: this script's parent)")
    args = ap.parse_args()

    if args.self_test:
        return _self_test()

    root = Path(args.root) if args.root else Path(__file__).resolve().parent.parent
    spec = root / "packaging" / "copr" / "dog.spec"
    if not spec.is_file():
        print(f"error: {spec} not found", file=sys.stderr)
        return 1

    try:
        problems = check_template(spec.read_text(encoding="utf-8"))
    except ParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if problems:
        print(f"error: {spec} is no longer a valid template:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print("\nThe version comes from Cargo.toml at SRPM time; see .copr/Makefile.", file=sys.stderr)
        return 1

    print("packaging/copr/dog.spec is a template (records no version, builds from the checkout)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
