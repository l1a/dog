#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 l1a
"""Refuse control characters and carriage returns in tracked text files.

TEMPLATE v2 — vendored verbatim across etr, retch and rusticprofile. Change it here, bump
TEMPLATE_VERSION, and propagate in each repo's own PR. Run by `just text-check` (in `just check`).

Two defect classes, both of which these repositories have actually shipped, and both of which
are invisible to review because the damage is a byte rather than a word.

1. A LONE CONTROL BYTE, from a backslash collapsing in transport. `~/AGENTS.md` sec.14
   records the mechanism: a double backslash in a command handed to an agent's shell
   arrives as a single one BEFORE the shell sees it, so `usr\\bin` in the intended text
   becomes `usr` + 0x08, and `%APPDATA%\\nushell\\autoload` becomes `%APPDATA%` + a real
   newline + `ushell` + 0x07. A quoted heredoc does not prevent it:
   - `etr` carried both in `NOTES.md` for eight releases (the second SPLIT A PARAGRAPH in
     half, which is why nobody spotted it: the file still rendered, just wrongly).
   - `templates/justfile-common.just` carried `usr` + 0x08 + `in` across the repos that
     vendor it.
   - `retch` carried the Win32 device path `\\\\?\\acpi#...` in `win_setupapi.rs` as
     `\\?` + 0x07 + `cpi#` inside a `///` doc comment that shipped to docs.rs.

   The danger is not cosmetic. Whatever consumes the text next reads the surviving single
   backslash as an escape, so the same collapse has previously written a non-comment line
   into a nushell config and aborted the rest of the file.

2. A CARRIAGE RETURN. `.gitattributes` pins `* text=auto eol=lf` because these trees are
   Syncthing-shared across Linux, macOS and Windows. A CRLF worktree copy is therefore
   always drift, and git NORMALISES IT OUT OF ITS OWN VIEW rather than reporting it clearly.
   Measured on git 2.55.0 by planting CRLF in one tracked file:

       git status --short   ->  ` M <file>`
       git diff             ->  NOTHING. No hunk, no name, just a stderr warning.
       git add <file>       ->  git status is now CLEAN, and every CR is still on disk.

   So the drift is visible exactly once, as an ` M` with no diff behind it -- which reads as
   noise -- and the first `git add` that touches the file erases the only signal while
   leaving every byte in place. Thereafter chezmoi, python and every shell see the CRs and
   git sees nothing (`etr` shipped `scripts/install_man.py` CRLF in the worktree while its
   committed blob was LF). The unambiguous oracle is `git ls-files --eol` (`i/lf w/crlf`).

   (Template v1 in `etr` overstated this as "`git status` CANNOT report it"; the real
   mechanism above is narrower and worse. Template v2 unifies the three repos' copies, which
   had drifted while all three still declared `TEMPLATE_VERSION = 1`.)

   NOTE: `WIP.md` is gitignored, so `git ls-files` never offers it and this guard cannot
   reach it. `just wip-check` supplies the same LF guarantee for `WIP.md`.

WHY THIS IS A CHECK AND NOT A CONVENTION: every instance above was found by reading bytes,
never by reading the file. A guard is the only thing that looks.

DO NOT BUILD THIS OUT OF `grep`. `grep -c $'\\r'` from an agent shell is the subject of
`~/AGENTS.md` sec.17 -- the pattern collapses to empty, `grep` matches every line, and the
answer that comes back is the file's LINE COUNT wearing a carriage-return costume. It is
wrong in both directions, and the tell is that it equals `wc -l`. Count bytes in a language
that has them.
"""

import subprocess
import sys
from pathlib import Path

TEMPLATE_VERSION = 2

# Every C0 control except TAB and LF, plus DEL. Nothing legitimate in this repository's text
# contains one -- verified across every tracked text file, which is why there are no
# per-file exemptions here. An exemption list is where a guard goes to die.
FORBIDDEN = (set(range(0x00, 0x20)) - {0x09, 0x0A}) | {0x7F}

NAMES = {0x07: "BEL", 0x08: "BACKSPACE", 0x09: "TAB", 0x0D: "CARRIAGE RETURN",
         0x1B: "ESC", 0x7F: "DEL"}


def tracked_files(root: Path) -> list[str]:
    """Tracked paths, NUL-separated so a filename with a space or newline survives."""
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    return [p.decode() for p in out.split(b"\0") if p]


def is_binary(data: bytes) -> bool:
    """A NUL in the first 8 KiB, which is the heuristic git itself uses.

    Sniffed rather than taken from an extension list: an extension list has to be
    maintained, and the failure mode of forgetting an entry is a confusing error on a
    legitimate binary rather than a missed defect.
    """
    return b"\0" in data[:8192]


def scan(data: bytes) -> list[tuple[int, int, bytes]]:
    """Return (line_no, byte, line) for every forbidden byte. Pure, so it is testable."""
    hits = []
    for lineno, line in enumerate(data.split(b"\n"), 1):
        for b in sorted({c for c in line if c in FORBIDDEN}):
            hits.append((lineno, b, line))
    return hits


def describe(byte: int) -> str:
    return f"0x{byte:02x} ({NAMES[byte]})" if byte in NAMES else f"0x{byte:02x}"


def check_tree(root: Path) -> list[str]:
    problems = []
    for rel in tracked_files(root):
        path = root / rel
        try:
            data = path.read_bytes()
        except (FileNotFoundError, IsADirectoryError):
            continue  # a submodule, or a path staged for deletion
        if is_binary(data):
            continue
        for lineno, byte, line in scan(data):
            excerpt = line.decode("utf-8", "replace")[:70]
            problems.append(f"{rel}:{lineno}: {describe(byte)} in: {excerpt!r}")
    return problems


def _self_test() -> int:
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        if not cond:
            failures.append(f"{name}: {detail}")

    # Positive: ordinary text, tabs and LFs are all fine.
    check("plain text passes", scan(b"hello\tworld\nsecond line\n") == [],
          "clean text was flagged")

    # The real defects across etr, retch and rusticprofile, reproduced as the bytes that
    # actually shipped. Built with chr(92) rather than a backslash literal, because writing
    # one into a shell command is the very transport bug being guarded against.
    bs = chr(92)
    check("backspace caught",
          any(b == 0x08 for _, b, _ in scan(b"# Git's `usr\x08in` on PATH.")),
          "the NOTES.md / justfile-common.just backspace defect passed")
    check("BEL (nushell path) caught",
          any(b == 0x07 for _, b, _ in scan(b"`%APPDATA%\nushell\x07utoload`")),
          "the NOTES.md BEL defect passed")
    check("BEL (Win32 device path) caught",
          any(b == 0x07 for _, b, _ in scan(b"`\\?\x07cpi#pnp0c0a#0#`")),
          "the win_setupapi.rs rustdoc BEL defect passed")
    check("repaired text passes",
          scan(f"# Git's `usr{bs}bin` on PATH.".encode()) == [],
          "the CORRECT text was flagged -- the guard would block its own fix")

    # Carriage returns, in both directions.
    check("CR caught", any(b == 0x0D for _, b, _ in scan(b"line one\r\nline two\r\n")),
          "a CRLF file passed")
    check("LF passes", scan(b"line one\nline two\n") == [], "an LF file was flagged")

    # The sec.17 trap, asserted as a property: a CR count must not equal the line count of a
    # file that has no CRs. This is what `grep -c $'\r'` returns from an agent shell.
    no_cr = b"a\nb\nc\nd\n"
    check("CR count is not the line count",
          len([1 for _, b, _ in scan(no_cr) if b == 0x0D]) == 0,
          "counted lines instead of carriage returns")

    # Byte offsets must be reported as the line they are on, not the whole file.
    hits = scan(b"clean\nalso clean\nbad\x1bhere\n")
    check("line number reported", hits and hits[0][0] == 3, f"got {hits}")

    # Binary content is skipped rather than reported as thousands of problems.
    check("binary sniffed", is_binary(b"\x89PNG\r\n\x1a\n\0\0\0"),
          "a PNG was treated as text")
    check("text not sniffed as binary", not is_binary(b"ordinary text\n"),
          "text called binary")

    # And the live tree passes. If this fails the tree is genuinely wrong, and the message
    # names the file and the byte.
    live = check_tree(Path(__file__).resolve().parent.parent)
    check("live tree clean", not live, "; ".join(live))

    if failures:
        for f in failures:
            print(f"  FAIL {f}", file=sys.stderr)
        print(f"text_check.py self-test FAILED ({len(failures)})", file=sys.stderr)
        return 1
    print(f"text_check.py self-test passed (template v{TEMPLATE_VERSION})")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return _self_test()

    root = Path(__file__).resolve().parent.parent
    problems = check_tree(root)
    if problems:
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print(
            f"\ntext_check: {len(problems)} forbidden byte(s) in tracked text.\n"
            "  A control byte is usually a backslash that collapsed in transport "
            "(~/AGENTS.md sec.14).\n"
            "  A CARRIAGE RETURN is worktree drift that git normalises out of its own view: "
            "`git diff` shows\n"
            "  nothing, and one `git add` makes `git status` clean while every CR stays on "
            "disk. Confirm with\n"
            "  `git ls-files --eol <file>` (look for `i/lf w/crlf`) and repair the worktree "
            "copy in place.",
            file=sys.stderr,
        )
        return 1
    print("text: no control characters or carriage returns in tracked files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
