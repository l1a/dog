/*
 * dog - A command-line DNS client
 * Copyright (c) 2026 l1a and contributors
 * Original code Copyright (c) Benjamin Sago
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Writing to standard output without panicking when the reader goes away.
//!
//! Rust ignores `SIGPIPE`, so a write to a pipe whose reader has exited returns an error instead of
//! killing the process, and `print!` and `println!` turn that error into a **panic**: a Rust panic
//! message and exit status 101. That is the wrong thing to do to someone who ran `dog example.com | head -1`.
//!
//! Every write to standard output goes through this module, and `#![deny(clippy::print_stdout)]` in
//! `main.rs` makes `just clippy` fail if anything uses `print!` or `println!` instead. When the reader has
//! gone away there is nobody to tell, so `dog` stops quietly with a success status, as `head` itself does.
//! Any other write error is a real I/O error and is reported with the I/O error status.

use std::io::{self, Write};
use std::process::exit;

use crate::exits;

/// What a failed write to standard output means.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The reader closed its end of the pipe: nothing is wrong, there is just nobody to write to.
    ReaderGone,

    /// Anything else: a real I/O error.
    Failed,
}

fn outcome(error: &io::Error) -> Outcome {
    if error.kind() == io::ErrorKind::BrokenPipe {
        Outcome::ReaderGone
    } else {
        Outcome::Failed
    }
}

/// Deals with the result of a write to standard output: nothing if it worked, a quiet successful exit
/// if the reader has gone away, and an error message with the I/O error status for anything else.
pub fn finish(result: io::Result<()>) {
    if let Err(error) = result {
        match outcome(&error) {
            Outcome::ReaderGone => exit(exits::SUCCESS),
            Outcome::Failed => {
                eprintln!("dog: failed to write to standard output: {error}");
                exit(exits::NETWORK_ERROR);
            }
        }
    }
}

/// Writes bytes to standard output and flushes them.
pub fn emit_bytes(bytes: &[u8]) {
    let mut out = io::stdout().lock();
    finish(out.write_all(bytes).and_then(|()| out.flush()));
}

/// Writes text to standard output and flushes it.
pub fn emit(text: &str) {
    emit_bytes(text.as_bytes());
}

/// Writes text and a newline to standard output as one write, so a line is never split.
pub fn emit_line(text: &str) {
    let mut line = String::with_capacity(text.len() + 1);
    line.push_str(text);
    line.push('\n');
    emit(&line);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn a_closed_pipe_is_not_an_error() {
        assert_eq!(
            outcome(&io::Error::from(io::ErrorKind::BrokenPipe)),
            Outcome::ReaderGone
        );
    }

    #[test]
    fn every_other_error_is_reported() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::WriteZero,
            io::ErrorKind::Other,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::NotFound,
        ] {
            assert_eq!(outcome(&io::Error::from(kind)), Outcome::Failed, "{kind:?}");
        }
    }
}
