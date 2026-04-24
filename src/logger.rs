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

//! Debug error logging.

use std::ffi::OsStr;

use ansi_term::{ANSIString, Colour};

/// Sets the internal logger, changing the log level based on the value of an
/// environment variable.
///
/// # Arguments
///
/// * `ev` - The value of the `DOG_DEBUG` environment variable.
pub fn configure<T: AsRef<OsStr>>(ev: Option<T>) {
    let Some(ev) = ev else { return };

    let env_var = ev.as_ref();
    if env_var.is_empty() {
        return;
    }

    if env_var == "trace" {
        log::set_max_level(log::LevelFilter::Trace);
    } else {
        log::set_max_level(log::LevelFilter::Debug);
    }

    let result = log::set_logger(GLOBAL_LOGGER);
    if let Err(e) = result {
        eprintln!("Failed to initialise logger: {e}");
    }
}

/// The global logger instance.
#[derive(Debug)]
struct Logger;

const GLOBAL_LOGGER: &Logger = &Logger;

impl log::Log for Logger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true // no need to filter after using ‘set_max_level’.
    }

    fn log(&self, record: &log::Record<'_>) {
        let open = Colour::Fixed(243).paint("[");
        let level = level(record.level());
        let close = Colour::Fixed(243).paint("]");

        eprintln!(
            "{}{} {}{} {}",
            open,
            level,
            record.target(),
            close,
            record.args()
        );
    }

    fn flush(&self) {
        // no need to flush with ‘eprintln!’.
    }
}

fn level(level: log::Level) -> ANSIString<'static> {
    match level {
        log::Level::Error => Colour::Red.paint("ERROR"),
        log::Level::Warn => Colour::Yellow.paint("WARN"),
        log::Level::Info => Colour::Cyan.paint("INFO"),
        log::Level::Debug => Colour::Blue.paint("DEBUG"),
        log::Level::Trace => Colour::Fixed(245).paint("TRACE"),
    }
}
