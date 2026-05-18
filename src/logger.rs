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
use std::fmt::Display;

use anstyle::{Ansi256Color, AnsiColor, Color, Style};

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
        let bracket_style = Style::new().fg_color(Some(Color::Ansi256(Ansi256Color(243))));
        let open = paint(bracket_style, "[");
        let level = level(record.level());
        let close = paint(bracket_style, "]");

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

fn level(level: log::Level) -> String {
    match level {
        log::Level::Error => paint(
            Style::new().fg_color(Some(Color::Ansi(AnsiColor::Red))),
            "ERROR",
        ),
        log::Level::Warn => paint(
            Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
            "WARN",
        ),
        log::Level::Info => paint(
            Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan))),
            "INFO",
        ),
        log::Level::Debug => paint(
            Style::new().fg_color(Some(Color::Ansi(AnsiColor::Blue))),
            "DEBUG",
        ),
        log::Level::Trace => paint(
            Style::new().fg_color(Some(Color::Ansi256(Ansi256Color(245)))),
            "TRACE",
        ),
    }
}

fn paint<S: Display>(style: Style, text: S) -> String {
    format!("{}{}{}", style.render(), text, style.render_reset())
}
