#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check that every copy of dog's project description agrees with packaging/metadata.toml.

    metadata_check.py              # check the repository
    metadata_check.py --self-test

The description is written once, in packaging/metadata.toml. It still has to be COPIED into each
artifact that carries it (crates.io reads Cargo.toml, the AUR the PKGBUILD, COPR's RPM the spec,
Homebrew the formula), so this fails when a copy has drifted from the source, and when a text
breaks the style rules of the channel that shows it. It proves the copies AGREE; it cannot prove
they are RIGHT, so read the README and the text in metadata.toml for claims that are no longer
true before a release.

  copies that must EQUAL the source   Cargo.toml description, keywords and categories; PKGBUILD
                                      pkgdesc; .SRCINFO pkgdesc; spec Summary and %description;
                                      Homebrew desc; every declared licence
  must CONTAIN                        the README, which must carry the tagline verbatim
  style rules                         summary, brew_desc: at most 80 characters, no trailing full
                                      stop, no leading article, and not beginning with the
                                      package's own name; GitHub: description at most 350
                                      characters, at most 20 topics, each a valid topic
  COPR page                           both files exist, and no paragraph line is indented four or
                                      more spaces outside a code fence (COPR would render it as code)

The GitHub About box and the COPR project page live on the services, not in an artifact, and are
PUSHED from the source (scripts/github_metadata.py, .github/workflows/copr.yml).
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
META = "packaging/metadata.toml"

FILES = {
    "cargo": "Cargo.toml",
    "pkgbuild": "packaging/aur/PKGBUILD.in",
    "srcinfo": "packaging/aur/SRCINFO.in",
    "spec": "packaging/copr/dog.spec",
    "brew": "packaging/homebrew/dog.rb",
    "readme": "README.md",
}

# Every slug must be a real crates.io category (https://crates.io/category_slugs): crates.io rejects
# a publish that names an unknown one. Add a slug here only after checking that page.
CATEGORIES = {"command-line-utilities", "network-programming"}

KEYWORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+-]{0,19}")
TOPIC_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,49}")
ARTICLE_RE = re.compile(r"(a|an|the)\s", re.IGNORECASE)


def norm(text: str) -> str:
    """All whitespace collapsed, so a wrapped paragraph compares equal to its source."""
    return " ".join(text.split())


def line_style(label: str, text: str, limit: int, own_name: str | None = None, article: bool = True) -> list[str]:
    found = []
    if not text:
        found.append(f"{label} is empty")
    if len(text) > limit:
        found.append(f"{label} is {len(text)} characters; the limit is {limit}")
    if text.endswith("."):
        found.append(f"{label} ends with a full stop")
    if article and ARTICLE_RE.match(text):
        found.append(f"{label} begins with an article")
    if own_name and text.lower().startswith(own_name.lower()):
        found.append(f"{label} begins with the package's own name ({own_name})")
    return found


def grab(label: str, pattern: str, text: str, flags: int = re.MULTILINE) -> tuple[str | None, list[str]]:
    m = re.search(pattern, text, flags)
    if not m:
        return None, [f"{label}: could not find it (pattern {pattern!r})"]
    return m.group(1), []


def spec_description(spec: str) -> str | None:
    m = re.search(r"^%description\s*\n(.*?)^%", spec, re.MULTILINE | re.DOTALL)
    return norm(m.group(1)) if m else None


def copr_problems(label: str, text: str | None) -> list[str]:
    if text is None:
        return [f"{label} does not exist"]
    if not text.strip():
        return [f"{label} is empty"]
    found, fenced = [], False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced and re.match(r" {4,}\S", line):
            found.append(f"{label}:{n} is indented four or more spaces, which COPR renders as a code block")
    return found


def check(root: Path = REPO_ROOT, overrides: dict[str, str] | None = None) -> list[str]:
    """Everything wrong, as a list of messages. Empty means every copy agrees with the source."""
    overrides = overrides or {}

    def read(rel: str) -> str | None:
        if rel in overrides:
            return overrides[rel]
        p = root / rel
        return p.read_text(encoding="utf-8") if p.is_file() else None

    meta_text = read(META)
    if meta_text is None:
        return [f"{META} does not exist"]
    meta = tomllib.loads(meta_text)
    found: list[str] = []

    summary, brew_desc = meta["summary"], meta["brew_desc"]
    licence, tagline = meta["license"], meta["tagline"]
    long_desc = norm(meta["description"])

    # --- style rules for the source texts themselves
    found += line_style("metadata summary", summary, 80, "dog")
    found += line_style("metadata brew_desc", brew_desc, 80, "dog")
    # "A ..." is normal on crates.io; the article rule is a packaging-channel convention.
    found += line_style("metadata crates.description", meta["crates"]["description"], 200, article=False)
    gh = meta["github"]
    if len(gh["description"]) > 350:
        found.append(f"github.description is {len(gh['description'])} characters; GitHub caps it at 350")
    if len(gh["topics"]) > 20:
        found.append(f"github.topics has {len(gh['topics'])} entries; GitHub allows 20")
    if len(set(gh["topics"])) != len(gh["topics"]):
        found.append("github.topics contains a duplicate")
    found += [f"github topic {t!r} is not lowercase letters, digits and hyphens (at most 50)"
              for t in gh["topics"] if not TOPIC_RE.fullmatch(t)]
    kw, cats = meta["crates"]["keywords"], meta["crates"]["categories"]
    if len(kw) > 5:
        found.append(f"crates.keywords has {len(kw)} entries; crates.io allows 5")
    found += [f"crates keyword {k!r} is not valid on crates.io" for k in kw if not KEYWORD_RE.fullmatch(k)]
    if len(cats) > 5:
        found.append(f"crates.categories has {len(cats)} entries; crates.io allows 5")
    found += [f"crates category {c!r} is not a known crates.io slug (see CATEGORIES in this script)"
              for c in cats if c not in CATEGORIES]

    # --- the copies
    texts = {name: read(path) for name, path in FILES.items()}
    for name, path in FILES.items():
        if texts[name] is None:
            found.append(f"{path} does not exist")
    if any(t is None for t in texts.values()):
        return found

    try:
        cargo = tomllib.loads(texts["cargo"])["package"]
    except (tomllib.TOMLDecodeError, KeyError) as e:
        return found + [f"Cargo.toml has no readable [package]: {e}"]
    for field, want in (("description", meta["crates"]["description"]),
                        ("keywords", kw), ("categories", cats), ("license", licence)):
        if cargo.get(field) != want:
            found.append(f"Cargo.toml {field} is {cargo.get(field)!r}; metadata.toml says {want!r}")

    pairs = []
    value, err = grab("PKGBUILD pkgdesc", r'^pkgdesc="(.*)"$', texts["pkgbuild"]); found += err
    pairs.append(("PKGBUILD pkgdesc", value, summary))
    value, err = grab("PKGBUILD license", r"^license=\('(.*)'\)$", texts["pkgbuild"]); found += err
    pairs.append(("PKGBUILD license", value, licence))
    value, err = grab(".SRCINFO pkgdesc", r"^\s*pkgdesc = (.*)$", texts["srcinfo"]); found += err
    pairs.append((".SRCINFO pkgdesc", value, summary))
    value, err = grab(".SRCINFO license", r"^\s*license = (.*)$", texts["srcinfo"]); found += err
    pairs.append((".SRCINFO license", value, licence))
    value, err = grab("spec Summary", r"^Summary:\s+(.*?)\s*$", texts["spec"]); found += err
    pairs.append(("spec Summary", value, summary))
    value, err = grab("spec License", r"^License:\s+(.*?)\s*$", texts["spec"]); found += err
    pairs.append(("spec License", value, licence))
    value, err = grab("Homebrew desc", r'^\s*desc "(.*)"$', texts["brew"]); found += err
    pairs.append(("Homebrew desc", value, brew_desc))
    value, err = grab("Homebrew license", r'^\s*license "(.*)"$', texts["brew"]); found += err
    pairs.append(("Homebrew license", value, licence))
    pairs.append(("spec %description", spec_description(texts["spec"]), long_desc))
    for label, have, want in pairs:
        if have is not None and have != want:
            found.append(f"{label} is {have!r}; metadata.toml says {want!r}")

    if tagline not in texts["readme"]:
        found.append("README.md does not contain the tagline from metadata.toml verbatim")

    # --- the COPR project page, pushed to the service by copr.yml
    for key in ("description", "instructions"):
        rel = meta["copr"][key]
        found += copr_problems(rel, read(rel))
    return found


def self_test() -> None:
    """Prove the check can FAIL: a clean state, then one corruption per rule."""
    base = check()
    assert base == [], f"the repository itself must pass first: {base}"

    def corrupt(path: str, old: str, new: str) -> list[str]:
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        assert old in text, f"test setup: {old!r} not found in {path}"
        return check(overrides={path: text.replace(old, new, 1)})

    def must_fail(label: str, problems: list[str], needle: str) -> None:
        assert any(needle in p for p in problems), f"{label}: expected a problem containing {needle!r}, got {problems}"

    summary = tomllib.loads((REPO_ROOT / META).read_text(encoding="utf-8"))["summary"]

    # A drifted copy, one per channel.
    must_fail("Cargo description", corrupt("Cargo.toml", 'description = "A command-line DNS client, like dig', 'description = "A DNS client, like dig'), "Cargo.toml description")
    must_fail("Cargo license", corrupt("Cargo.toml", 'license = "GPL-3.0-or-later"', 'license = "MIT"'), "Cargo.toml license")
    must_fail("PKGBUILD pkgdesc", corrupt("packaging/aur/PKGBUILD.in", f'pkgdesc="{summary}"', 'pkgdesc="Command-line DNS client"'), "PKGBUILD pkgdesc")
    must_fail(".SRCINFO pkgdesc", corrupt("packaging/aur/SRCINFO.in", f"pkgdesc = {summary}", "pkgdesc = Command-line DNS client"), ".SRCINFO pkgdesc")
    must_fail("spec Summary", corrupt("packaging/copr/dog.spec", f"Summary:        {summary}", "Summary:        Command-line DNS client"), "spec Summary")
    must_fail("spec %description", corrupt("packaging/copr/dog.spec", "knows 35 record types", "knows 12 record types"), "spec %description")
    must_fail("Homebrew desc", corrupt("packaging/homebrew/dog.rb", f'desc "{summary}"', 'desc "Command-line DNS client"'), "Homebrew desc")
    must_fail("Homebrew license", corrupt("packaging/homebrew/dog.rb", 'license "GPL-3.0-or-later"', 'license "MIT"'), "Homebrew license")
    must_fail("README tagline", corrupt("README.md", "friendlier.", "friendlier!"), "tagline")

    # The SOURCE changing while the copies stay put must be caught everywhere at once.
    drift = corrupt(META, f'summary = "{summary}"', 'summary = "Command-line DNS client for people"')
    for needle in ("PKGBUILD pkgdesc", ".SRCINFO pkgdesc", "spec Summary"):
        must_fail("source drift", drift, needle)

    # Style rules on the source text.
    must_fail("too long", corrupt(META, f'summary = "{summary}"', 'summary = "' + "x" * 81 + '"'), "limit is 80")
    must_fail("full stop", corrupt(META, f'summary = "{summary}"', f'summary = "{summary}."'), "ends with a full stop")
    must_fail("article", corrupt(META, f'summary = "{summary}"', 'summary = "A command-line DNS client"'), "begins with an article")
    must_fail("own name", corrupt(META, f'summary = "{summary}"', 'summary = "dog is a DNS client"'), "package's own name")
    must_fail("topic", corrupt(META, '"dns-client",', '"Has_Caps",'), "not lowercase")
    must_fail("duplicate topic", corrupt(META, '"dns-client",', '"dns",'), "duplicate")
    must_fail("keywords", corrupt(META, 'keywords = ["dns", "dig", "dns-over-https", "dns-over-tls", "resolver"]', 'keywords = ["a", "b", "c", "d", "e", "f"]'), "allows 5")
    must_fail("category", corrupt(META, 'categories = ["command-line-utilities", "network-programming"]', 'categories = ["command-line-utilities", "made-up"]'), "not a known crates.io slug")
    must_fail("github length", corrupt(META, 'description = "A command-line DNS client, like dig but friendlier. Colourful', 'description = "' + "x" * 351 + ' Colourful'), "caps it at 350")

    # The COPR page: an indented line renders as code; a missing file is a failure.
    must_fail("COPR indent", check(overrides={"packaging/copr/project-description.md": "**dog** is a DNS client.\n\n    indented\n"}), "code block")
    assert check(overrides={"packaging/copr/project-description.md": "text\n\n```\n    inside a fence\n```\n"}) == [], "an indented line inside a fence is fine"
    must_fail("COPR missing", check(root=REPO_ROOT / "no-such-dir"), "does not exist")
    print("self-test passed")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0
    problems = check()
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if problems:
        return 1
    print("metadata: every copy agrees with packaging/metadata.toml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
