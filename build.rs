//! This build script gets run during every build. Its purpose is to put
//! together the files used for the `--version`, which need to
//! come in both coloured and non-coloured variants. To make it easier to edit,
//! backslashes (\) are used instead of the beginning of ANSI escape codes.
//!
//! The version string is the version from Cargo.toml, with a warning added to
//! *debug* builds. Nothing else is stamped into it: no Git hash and no build
//! date, so a build does not need `git` and two builds of the same source
//! produce the same string.
//!
//! This script generates the string from the environment variables
//! that Cargo adds (http://doc.crates.io/environment-variables.html)
//! and writes the strings into files, which we can include during
//! compilation. It also generates the shell completions.

use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

use clap_complete::{generate_to, Shell};
use clap_complete_nushell::Nushell;

#[path = "src/cli.rs"]
mod cli;

/// The build script entry point.
fn main() -> io::Result<()> {
    #![allow(clippy::write_with_newline)]

    let tagline = "dog \\1;32m●\\0m command-line DNS client";

    let ver = if is_debug_build() {
        format!(
            "{}\nv{} \\1;31m(pre-release debug build!)\\0m",
            tagline,
            version_string()
        )
    } else {
        format!("{}\nv{}", tagline, version_string())
    };

    // We need to create these files in the Cargo output directory.
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Pretty version text
    let mut f = File::create(out.join("version.pretty.txt"))?;
    writeln!(f, "{}", convert_codes(&ver))?;

    // Bland version text
    let mut f = File::create(out.join("version.bland.txt"))?;
    writeln!(f, "{}", strip_codes(&ver))?;

    let mut cmd = cli::build_cli();
    let comp_dir = out.join("completions");
    std::fs::create_dir_all(&comp_dir)?;

    generate_to(Shell::Bash, &mut cmd, "dog", &comp_dir)?;
    generate_to(Shell::Fish, &mut cmd, "dog", &comp_dir)?;
    generate_to(Shell::Zsh, &mut cmd, "dog", &comp_dir)?;
    generate_to(Shell::PowerShell, &mut cmd, "dog", &comp_dir)?;
    generate_to(Shell::Elvish, &mut cmd, "dog", &comp_dir)?;
    generate_to(Nushell, &mut cmd, "dog", &comp_dir)?;

    Ok(())
}

/// Converts the escape codes to ANSI escape codes.
fn convert_codes(input: &str) -> String {
    input.replace("\\", "\x1B[")
}

/// Removes escape codes.
fn strip_codes(input: &str) -> String {
    input
        .replace("\\0m", "")
        .replace("\\1m", "")
        .replace("\\4m", "")
        .replace("\\32m", "")
        .replace("\\33m", "")
        .replace("\\1;31m", "")
        .replace("\\1;32m", "")
        .replace("\\1;33m", "")
        .replace("\\1;4;34", "")
}

/// Whether we are building in debug mode.
fn is_debug_build() -> bool {
    env::var("PROFILE").unwrap() == "debug"
}

/// Retrieves the [package] version in Cargo.toml as a string.
fn cargo_version() -> String {
    env::var("CARGO_PKG_VERSION").unwrap()
}

/// Returns the version and build parameters string.
/// Previously appended feature indicators (-idna, -https), but these were removed
/// as they did not correspond to any actual Cargo features or gated code.
fn version_string() -> String {
    cargo_version()
}
