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

//! Colours, colour schemes, and terminal styling.

use ansi_term::Color::*;
use ansi_term::Style;

/// The **colours** are used to paint the input.
#[derive(Debug, Default)]
pub struct Colours {
    /// The style for the question name.
    pub qname: Style,

    /// The style for the answer section.
    pub answer: Style,

    /// The style for A records.
    pub a: Style,
    /// The style for AAAA records.
    pub aaaa: Style,

    /// The style for CNAME records.
    pub cname: Style,
    /// The style for MX records.
    pub mx: Style,
    /// The style for NS records.
    pub ns: Style,
    /// The style for PTR records.
    pub ptr: Style,
    /// The style for SOA records.
    pub soa: Style,
    /// The style for SRV records.
    pub srv: Style,
    /// The style for TXT records.
    pub txt: Style,
    /// The style for security and cryptography record types.
    pub security: Style,
    /// The style for unknown record types.
    pub default: Style,
}

impl Colours {
    /// Create a new colour palette that has a variety of different styles
    /// defined. This is used by default.
    pub fn pretty() -> Self {
        Self {
            qname: Blue.bold(),
            answer: Style::default(),
            a: Green.bold(),
            aaaa: Green.bold(),

            cname: Yellow.normal(),
            mx: Cyan.normal(),
            ns: Red.normal(),
            ptr: Red.normal(),
            soa: Purple.normal(),
            srv: Cyan.normal(),
            txt: Yellow.normal(),
            security: Yellow.normal(),
            default: White.on(Red),
        }
    }

    /// Create a new colour palette where no styles are defined, causing
    /// output to be rendered as plain text without any formatting.
    /// This is used when output is not to a terminal.
    pub fn plain() -> Self {
        Self::default()
    }
}
