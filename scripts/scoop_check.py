#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assert packaging/scoop/dog.json is still a template that records no release.

WHY THIS EXISTS
---------------
`packaging/scoop/dog.json` is the Windows Scoop sibling of `packaging/homebrew/dog.rb`,
`packaging/aur/PKGBUILD.in` and `packaging/copr/dog.spec`. Like them, it records no released
version and no checksum in the repository: `scripts/render_packaging.py` fills in `@VERSION@`,
`@SHA256_X86_64@` and `@SHA256_ARM64@` at publish time (`just scoop-publish [version]`),
computing the hashes from the real GitHub Release `.zip` archives.

WHAT IT CHECKS
--------------
All offline, deterministic and free:

  1. The manifest parses as valid JSON and its top-level `version` is `"@VERSION@"`.
  2. `architecture.64bit` and `architecture.arm64` carry the exact sentinel URLs
     (`.../releases/download/v@VERSION@/dog-v@VERSION@-windows-{x86_64,aarch64}.zip`),
     sentinel hashes (`"@SHA256_X86_64@"` and `"@SHA256_ARM64@"`), and sentinel
     `extract_dir` values (`"dog-v@VERSION@-windows-{x86_64,aarch64}"`).
  3. `"bin"` is `"bin\\dog.exe"`, `"checkver"` is `"github"`, and `"autoupdate"` carries
     the matching `v$version` URLs and `extract_dir` values for `64bit` and `arm64`.
  4. Nothing anywhere in the file records a literal semver version or 64-hex sha256 digest.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TEMPLATE_VERSION = 1

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "packaging" / "scoop" / "dog.json"

EXPECTED_URL_X64 = (
    "https://github.com/l1a/dog/releases/download/v@VERSION@/dog-v@VERSION@-windows-x86_64.zip"
)
EXPECTED_URL_ARM64 = (
    "https://github.com/l1a/dog/releases/download/v@VERSION@/dog-v@VERSION@-windows-aarch64.zip"
)
EXPECTED_EXTRACT_X64 = "dog-v@VERSION@-windows-x86_64"
EXPECTED_EXTRACT_ARM64 = "dog-v@VERSION@-windows-aarch64"

EXPECTED_AUTO_X64 = (
    "https://github.com/l1a/dog/releases/download/v$version/dog-v$version-windows-x86_64.zip"
)
EXPECTED_AUTO_ARM64 = (
    "https://github.com/l1a/dog/releases/download/v$version/dog-v$version-windows-aarch64.zip"
)
EXPECTED_AUTO_EXTRACT_X64 = "dog-v$version-windows-x86_64"
EXPECTED_AUTO_EXTRACT_ARM64 = "dog-v$version-windows-aarch64"

SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
VERSIONISH_RE = re.compile(r"\b[0-9]+\.[0-9]+\.[0-9]+\b")


def check_template(text: str) -> list[str]:
    """Return a list of problems; empty means the Scoop manifest is still a valid template."""
    problems: list[str] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [f"invalid JSON: {exc}"]

    if not isinstance(data, dict):
        return ["manifest root must be a JSON object"]

    if data.get("version") != "@VERSION@":
        problems.append(
            f"version is {data.get('version')!r}, not '@VERSION@' — this manifest is a template; "
            "scripts/render_packaging.py fills the version in at publish time"
        )

    arch = data.get("architecture")
    if not isinstance(arch, dict):
        problems.append("missing `architecture` object")
    else:
        x64 = arch.get("64bit") if isinstance(arch.get("64bit"), dict) else {}
        arm = arch.get("arm64") if isinstance(arch.get("arm64"), dict) else {}
        if x64.get("url") != EXPECTED_URL_X64:
            problems.append(f"architecture.64bit.url is {x64.get('url')!r}, not {EXPECTED_URL_X64!r}")
        if x64.get("hash") != "@SHA256_X86_64@":
            problems.append(
                f"architecture.64bit.hash is {x64.get('hash')!r}, not '@SHA256_X86_64@'"
            )
        if x64.get("extract_dir") != EXPECTED_EXTRACT_X64:
            problems.append(
                f"architecture.64bit.extract_dir is {x64.get('extract_dir')!r}, not {EXPECTED_EXTRACT_X64!r}"
            )
        if arm.get("url") != EXPECTED_URL_ARM64:
            problems.append(f"architecture.arm64.url is {arm.get('url')!r}, not {EXPECTED_URL_ARM64!r}")
        if arm.get("hash") != "@SHA256_ARM64@":
            problems.append(
                f"architecture.arm64.hash is {arm.get('hash')!r}, not '@SHA256_ARM64@'"
            )
        if arm.get("extract_dir") != EXPECTED_EXTRACT_ARM64:
            problems.append(
                f"architecture.arm64.extract_dir is {arm.get('extract_dir')!r}, not {EXPECTED_EXTRACT_ARM64!r}"
            )

    if data.get("bin") != "bin\\dog.exe":
        problems.append(f"bin is {data.get('bin')!r}, not 'bin\\\\dog.exe'")

    if data.get("checkver") != "github":
        problems.append(f"checkver is {data.get('checkver')!r}, not 'github'")

    autoupdate = data.get("autoupdate")
    if not isinstance(autoupdate, dict) or not isinstance(autoupdate.get("architecture"), dict):
        problems.append("missing `autoupdate.architecture` object")
    else:
        auto_arch = autoupdate["architecture"]
        auto_x64 = auto_arch.get("64bit") if isinstance(auto_arch.get("64bit"), dict) else {}
        auto_arm = auto_arch.get("arm64") if isinstance(auto_arch.get("arm64"), dict) else {}
        if auto_x64.get("url") != EXPECTED_AUTO_X64:
            problems.append(
                f"autoupdate.architecture.64bit.url is {auto_x64.get('url')!r}, not {EXPECTED_AUTO_X64!r}"
            )
        if auto_x64.get("extract_dir") != EXPECTED_AUTO_EXTRACT_X64:
            problems.append(
                f"autoupdate.architecture.64bit.extract_dir is {auto_x64.get('extract_dir')!r}, "
                f"not {EXPECTED_AUTO_EXTRACT_X64!r}"
            )
        if auto_arm.get("url") != EXPECTED_AUTO_ARM64:
            problems.append(
                f"autoupdate.architecture.arm64.url is {auto_arm.get('url')!r}, not {EXPECTED_AUTO_ARM64!r}"
            )
        if auto_arm.get("extract_dir") != EXPECTED_AUTO_EXTRACT_ARM64:
            problems.append(
                f"autoupdate.architecture.arm64.extract_dir is {auto_arm.get('extract_dir')!r}, "
                f"not {EXPECTED_AUTO_EXTRACT_ARM64!r}"
            )

    for line in text.splitlines():
        for regex, what in ((SHA256_RE, "a sha256 digest"), (VERSIONISH_RE, "a version number")):
            m = regex.search(line)
            if m:
                problems.append(f"manifest records {what} ({m.group(0)}): {line.strip()!r}")

    return problems


# ── self-test ────────────────────────────────────────────────────────────────

_GOOD_MANIFEST = """\
{
    "version": "@VERSION@",
    "description": "Command-line DNS client with colourful output, DoT, DoH and JSON",
    "homepage": "https://github.com/l1a/dog",
    "license": "GPL-3.0-or-later",
    "architecture": {
        "64bit": {
            "url": "https://github.com/l1a/dog/releases/download/v@VERSION@/dog-v@VERSION@-windows-x86_64.zip",
            "hash": "@SHA256_X86_64@",
            "extract_dir": "dog-v@VERSION@-windows-x86_64"
        },
        "arm64": {
            "url": "https://github.com/l1a/dog/releases/download/v@VERSION@/dog-v@VERSION@-windows-aarch64.zip",
            "hash": "@SHA256_ARM64@",
            "extract_dir": "dog-v@VERSION@-windows-aarch64"
        }
    },
    "bin": "bin\\\\dog.exe",
    "checkver": "github",
    "autoupdate": {
        "architecture": {
            "64bit": {
                "url": "https://github.com/l1a/dog/releases/download/v$version/dog-v$version-windows-x86_64.zip",
                "extract_dir": "dog-v$version-windows-x86_64"
            },
            "arm64": {
                "url": "https://github.com/l1a/dog/releases/download/v$version/dog-v$version-windows-aarch64.zip",
                "extract_dir": "dog-v$version-windows-aarch64"
            }
        }
    }
}
"""

_REAL_SHA = "77ccf85843d24ac3216ab31d2584ff4a95869266c59ddb8bc83819425cfc2033"


def _self_test() -> int:
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        if not cond:
            failures.append(f"{name}: {detail}")

    def expect_problem(label: str, text: str, needle: str) -> None:
        probs = check_template(text)
        check(label, any(needle in p for p in probs), f"got {probs}")

    clean = check_template(_GOOD_MANIFEST)
    check("template fixture clean", clean == [], f"got {clean}")

    if MANIFEST.is_file():
        live_problems = check_template(MANIFEST.read_text(encoding="utf-8"))
        check("live manifest clean", live_problems == [], f"got {live_problems}")

    expect_problem("invalid json detected", "{not json", "invalid JSON")
    expect_problem(
        "pinned version detected",
        _GOOD_MANIFEST.replace('"@VERSION@"', '"0.8.8"'),
        "version is",
    )
    expect_problem(
        "pinned x86_64 hash detected",
        _GOOD_MANIFEST.replace('"@SHA256_X86_64@"', f'"{_REAL_SHA}"'),
        "architecture.64bit.hash is",
    )
    expect_problem(
        "pinned arm64 hash detected",
        _GOOD_MANIFEST.replace('"@SHA256_ARM64@"', f'"{_REAL_SHA}"'),
        "architecture.arm64.hash is",
    )
    expect_problem(
        "wrong extract_dir detected",
        _GOOD_MANIFEST.replace('"dog-v@VERSION@-windows-x86_64"', '"dog"'),
        "architecture.64bit.extract_dir is",
    )
    expect_problem(
        "wrong bin detected",
        _GOOD_MANIFEST.replace('"bin": "bin\\\\dog.exe"', '"bin": "dog.exe"'),
        "bin is",
    )
    expect_problem(
        "broken autoupdate detected",
        _GOOD_MANIFEST.replace("v$version/dog-v$version-windows-aarch64.zip", "v0.8.8/dog-v0.8.8-windows-aarch64.zip"),
        "autoupdate.architecture.arm64.url is",
    )

    if failures:
        for f in failures:
            print(f"  FAIL {f}", file=sys.stderr)
        print(f"scoop_check.py self-test FAILED ({len(failures)})", file=sys.stderr)
        return 1
    print(f"scoop_check.py self-test passed (template v{TEMPLATE_VERSION})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true", help="run built-in tests and exit")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()

    if not MANIFEST.is_file():
        print(f"error: {MANIFEST} does not exist", file=sys.stderr)
        return 1
    problems = check_template(MANIFEST.read_text(encoding="utf-8"))
    if problems:
        for p in problems:
            print(f"[scoop-check] {p}", file=sys.stderr)
        return 1
    print("[scoop-check] dog.json is a template (records no version, no checksum)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
