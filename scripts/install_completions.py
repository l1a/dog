#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 l1a
"""Install shell completions for one or more binaries. Canonical across repos.

TEMPLATE v3 — vendored verbatim in rusticprofile, retch and etr. Change it here,
bump TEMPLATE_VERSION, and propagate in each repo's own PR. `just standard-check`
runs `--self-test` below, so the behavioural invariants are asserted rather than
compared as text: three separate repositories cannot diff each other's files, but
each can prove it still behaves the way the standard requires.

WHY PYTHON RATHER THAN A JUST RECIPE
------------------------------------
retch established this and it is the more portable mechanism: no `sh`, no
`cygpath`, no coreutils, and nothing from Git's `usr\\bin` on Windows. A `bash`
shebang recipe cannot run on Windows at all without `cygpath`, and a plain `sh`
recipe still needs an `sh` on PATH. This needs only an interpreter that Windows
users of a Rust project already have.

THE FOUR THINGS THIS GETS RIGHT, EACH MEASURED THE HARD WAY
-----------------------------------------------------------
1. nushell's autoload directory is NOT the XDG one on Windows. `$nu.user-autoload-dirs`
   there is exactly `%APPDATA%\\nushell\\autoload`, one entry; nushell does not read
   `~/.config/nushell/autoload` at all, whatever XDG_CONFIG_HOME says. Getting it wrong
   is SILENT — the installer reports success and delivers nothing. This was found only
   because a set of shell aliases turned out to have been missing for months while
   existing in the dotfiles the whole time.

2. zsh reads completion functions ONLY from directories named in `fpath`, and
   `~/.local/share/zsh/site-functions` is not on it by default on any distribution.
   Printing "auto-loaded" is therefore a lie on such a machine: the file exists, zsh
   never reads it, and `<cmd> <TAB>` produces nothing with no indication why. So this
   CHECKS instead of claiming — and it must use an INTERACTIVE zsh, because a
   non-interactive one sources neither .zshrc nor anything it includes, so its `fpath`
   is the built-in default. Checking the wrong one reported NOT ACTIVE on a machine
   where completion worked perfectly: the mirror of the bug it replaced, equally
   confident and equally wrong.

3. A shell whose generation FAILS must fail the whole run. The predecessor logged the
   error to stderr, carried on, and then printed "Installed completions for <bin>:"
   with the full path list regardless — a step reporting success having partly done
   nothing, which is the exact failure class these projects exist to refuse.

4. PowerShell's directory is very likely wrong on Windows and is left as the XDG path
   DELIBERATELY. `~/.config/powershell` is right for pwsh on Linux and macOS; on Windows
   the profile directory is `Split-Path $PROFILE`, which OneDrive folder-redirection can
   move and which no other platform can compute. Measured: `$PROFILE` sat under
   `OneDrive\\Documents\\PowerShell` and did not source `~/.config/powershell`, so the
   file written there is dead. Replacing a known-harmless wrong answer with a guessed one
   is the wrong trade — this wants a design decision, not a substitution. Reported as
   NOT ACTIVE below rather than silently claimed.
"""

import os
import subprocess
import sys
from pathlib import Path

TEMPLATE_VERSION = 3


def completion_dirs(env, home):
    """Where each shell's completions belong. Pure, so the Windows branch is testable.

    `env` and `home` are arguments rather than read from the process, because a helper
    that reaches for its own environment can only be tested on the platform it is run on
    — and the one branch that matters most here is the one Unix hosts never take.
    """
    xdg_data = Path(env.get("XDG_DATA_HOME") or home / ".local" / "share")
    xdg_config = Path(env.get("XDG_CONFIG_HOME") or home / ".config")
    appdata = env.get("APPDATA")

    # Invariant 1. Windows nushell reads ONLY %APPDATA%\nushell\autoload.
    nu = Path(appdata) / "nushell" / "autoload" if appdata else xdg_config / "nushell" / "autoload"

    return {
        "bash": (xdg_data / "bash-completion" / "completions", "{bin}"),
        "zsh": (xdg_data / "zsh" / "site-functions", "_{bin}"),
        "fish": (xdg_config / "fish" / "completions", "{bin}.fish"),
        "elvish": (xdg_config / "elvish" / "lib", "{bin}.elv"),
        "nushell": (nu, "50{bin}-completions.nu"),
        "power-shell": (xdg_config / "powershell", "{bin}.ps1"),
    }


def zsh_reads(directory):
    """Whether an INTERACTIVE zsh has `directory` on its fpath.

    Returns None when zsh is absent or could not be asked — deliberately distinct from
    False, because "not installed" and "installed but will not load this" call for
    different messages, and collapsing them would state something nobody measured.
    """
    try:
        res = subprocess.run(
            ["zsh", "-i", "-c", "print -l $fpath"],
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return str(directory) in res.stdout.splitlines()


def reject_path_like(binary):
    """Refuse a path where a command NAME belongs. Invariant 4.

    `out = directory / pattern.format(bin=binary)` — and `Path("/dest") / "/abs/path"`
    DISCARDS the left operand. So an absolute `binary` silently relocates the write out of
    the completion directory and onto the path itself, which for `--from-path` is the
    installed binary: the helper overwrites the very executable it was asked to read.

    Measured 2026-08-24: `install_completions.py ~/.cargo/bin/rusticprofile --from-path`
    replaced a 3.6 MB binary with a 21 KB bash completion script, on a host taking hourly
    backups. It fails in the worst possible way — `--from-path` runs `[binary]`, so an
    absolute path WORKS for the read and only breaks the write. Generation succeeds, then
    destroys its own input, and the flag is *called* `--from-path`, which invites exactly
    the argument that breaks it.

    Made unexpressible rather than documented, on the precedent of refusing a snapshot-set
    name beginning with `-`: a note in a docstring would not have stopped it, because the
    person passing the path has already read the flag name and concluded it wants one.
    """
    if os.sep in binary or (os.altsep and os.altsep in binary) or Path(binary).is_absolute():
        raise RuntimeError(
            f"`{binary}` looks like a path; this takes a command NAME.\n"
            f"  Use:  install_completions.py {Path(binary).name} --from-path\n"
            "  (--from-path means 'run the binary as resolved on PATH', not "
            "'here is a path to the binary'.)"
        )


def generate(binary, shell, out_path, repo_root, from_path=False):
    """Write one completion file, or raise. Invariant 3: a failure is not survivable.

    `from_path=True` runs the binary as resolved on PATH instead of one built here, which
    is what `install-tag` needs: completions must come from the binary that was actually
    installed, or they can silently describe a different CLI than the one on the machine.
    """
    if from_path:
        cmd = [binary]
    else:
        candidates = [
            repo_root / "target" / "release" / f"{binary}.exe",
            repo_root / "target" / "release" / binary,
            repo_root / "target" / "debug" / f"{binary}.exe",
            repo_root / "target" / "debug" / binary,
        ]
        exe = next((c for c in candidates if c.exists()), None)
        cmd = [str(exe)] if exe else ["cargo", "run", "-q", "--bin", binary, "--"]
    res = subprocess.run(cmd + ["--completions", shell], capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(
            f"generating {shell} completions for {binary} failed "
            f"(exit {res.returncode}): {res.stderr.strip() or '<no stderr>'}"
        )
    if not res.stdout.strip():
        raise RuntimeError(f"{binary} --completions {shell} produced no output")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(res.stdout, encoding="utf-8")


def self_test():
    """Assert the invariants the standard requires. Run by `just standard-check`.

    This replaces a text diff. Three separate repositories cannot compare each other's
    files, but each can prove its vendored copy still behaves correctly — which is the
    stronger property anyway, and the one that was actually violated when two repos
    quietly shipped the pre-fix nushell path for months.
    """
    home = Path("/home/u")
    failures = []

    def check(name, got, want):
        if got != want:
            failures.append(f"  {name}\n    expected: {want}\n    got:      {got}")

    # Invariant 1, the branch Unix hosts never take and therefore never notice.
    win = completion_dirs({"APPDATA": r"C:\Users\u\AppData\Roaming"}, home)
    check("windows nushell dir",
          win["nushell"][0], Path(r"C:\Users\u\AppData\Roaming") / "nushell" / "autoload")

    unix = completion_dirs({}, home)
    check("unix nushell dir", unix["nushell"][0], home / ".config" / "nushell" / "autoload")

    # APPDATA must not disturb anything else — a Windows-only fix that moved the other
    # five directories would be a fleet-wide regression.
    for shell in ("bash", "zsh", "fish", "elvish", "power-shell"):
        check(f"{shell} dir unaffected by APPDATA", win[shell][0], unix[shell][0])

    # XDG overrides still honoured.
    over = completion_dirs({"XDG_DATA_HOME": "/x/data", "XDG_CONFIG_HOME": "/x/cfg"}, home)
    check("XDG_DATA_HOME honoured", over["zsh"][0], Path("/x/data") / "zsh" / "site-functions")
    check("XDG_CONFIG_HOME honoured", over["fish"][0], Path("/x/cfg") / "fish" / "completions")

    # An empty variable is not a location. `os.environ.get` returning "" would otherwise
    # resolve every path against the filesystem root.
    empty = completion_dirs({"XDG_DATA_HOME": "", "XDG_CONFIG_HOME": ""}, home)
    check("empty XDG_DATA_HOME falls back", empty["zsh"][0], unix["zsh"][0])

    # All six shells present, so a silently dropped one cannot pass.
    check("shell count", len(unix), 6)

    # Invariant 4: a path where a NAME belongs must be refused, because pathlib would
    # otherwise discard the destination directory and write over the binary itself.
    def refuses(arg):
        try:
            reject_path_like(arg)
            return False
        except RuntimeError:
            return True

    check("rejects an absolute path", refuses(str(Path.home() / ".cargo/bin/rusticprofile")), True)
    check("rejects a relative path", refuses(f"bin{os.sep}rusticprofile"), True)
    check("accepts a bare name", refuses("rusticprofile"), False)
    # The failure it prevents, stated as the property rather than the mechanism: joining a
    # directory with an absolute string must never be how an output path is chosen.
    check("pathlib really does discard the left operand",
          str(Path("/dest/dir") / "/abs/path"), str(Path("/abs/path")))

    if failures:
        print(f"self-test FAILED (template v{TEMPLATE_VERSION}):", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"install_completions.py self-test passed (template v{TEMPLATE_VERSION})")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()

    from_path = "--from-path" in argv
    binaries = [a for a in argv if not a.startswith("-")]
    if not binaries:
        print(
            "usage: install_completions.py <binary> [binary...] [--from-path] | --self-test",
            file=sys.stderr,
        )
        return 2

    repo_root = Path(__file__).resolve().parent.parent
    dirs = completion_dirs(os.environ, Path.home())

    for binary in binaries:
        reject_path_like(binary)  # invariant 4 — before ANY file is written

    for binary in binaries:
        for shell, (directory, pattern) in dirs.items():
            out = directory / pattern.format(bin=binary)
            generate(binary, shell, out, repo_root, from_path)  # raises — invariant 3
        src = "the installed binary" if from_path else "this checkout"
        print(f"Installed completions for {binary} (from {src})")

    print()
    zsh_dir = dirs["zsh"][0]
    state = zsh_reads(zsh_dir)
    if state is True:
        print(f"  zsh        auto-loaded from {zsh_dir}")
    elif state is False:
        print(f"  zsh        NOT ACTIVE -- {zsh_dir} is not on your $fpath.")
        print("             The file is written but zsh will never read it. Add this to")
        print("             ~/.zshrc BEFORE compinit runs, then restart the shell:")
        print()
        print(f"                 fpath+=({zsh_dir})")
        print()
    else:
        print("  zsh        not checked -- zsh is not installed, or could not be asked")

    print(f"  bash       source {dirs['bash'][0]}/<cmd>  (or restart shell)")
    print(f"  fish       auto-loaded from {dirs['fish'][0]}")
    print(f"  elvish     add to rc.elv:  eval (slurp < {dirs['elvish'][0]}/<cmd>.elv)")
    print(f"  nushell    auto-loaded from {dirs['nushell'][0]}")
    if os.environ.get("APPDATA"):
        print("  powershell NOT ACTIVE on Windows -- $PROFILE is under Documents\\PowerShell")
        print(f"             (OneDrive may move it) and does not source {dirs['power-shell'][0]}.")
        print("             Dot-source the file from your $PROFILE to use it.")
    else:
        print(f"  powershell add to $PROFILE:  . {dirs['power-shell'][0]}/<cmd>.ps1")
    print()
    print("  Shell aliases do not inherit completions. For an alias, tell your shell they")
    print("  are the same command:   zsh  compdef <alias>=<cmd>")
    print("                          fish complete -c <alias> -w <cmd>")
    print("                          bash complete -o default -F _<cmd> <alias>")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
