//! `dog ... | head` must not panic when the reader of the pipe has gone away.
//!
//! The pipe is made with its reader already closed before `dog` starts, so the first write is
//! certain to fail with `EPIPE`; closing it after the spawn would be a race.

use std::process::{Command, Stdio};

fn run_with_closed_reader(args: &[&str]) -> (Option<i32>, String) {
    let (reader, writer) = std::io::pipe().expect("create pipe");
    drop(reader);

    let output = Command::new(env!("CARGO_BIN_EXE_dog"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .expect("run dog");

    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn assert_quiet_success(args: &[&str]) {
    let (code, stderr) = run_with_closed_reader(args);
    assert_eq!(
        code,
        Some(0),
        "dog {:?} exited {:?}; stderr: {}",
        args,
        code,
        stderr
    );
    assert!(
        stderr.is_empty(),
        "dog {:?} wrote to stderr: {}",
        args,
        stderr
    );
}

#[test]
fn version() {
    assert_quiet_success(&["--version"]);
}

#[test]
fn list() {
    assert_quiet_success(&["--list"]);
}

#[test]
fn completions_bash() {
    assert_quiet_success(&["--completions", "bash"]);
}

#[test]
fn completions_zsh() {
    assert_quiet_success(&["--completions", "zsh"]);
}

#[test]
fn completions_fish() {
    assert_quiet_success(&["--completions", "fish"]);
}

#[test]
fn completions_nushell() {
    assert_quiet_success(&["--completions", "nushell"]);
}
