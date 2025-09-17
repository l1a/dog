//! Colours, colour schemes, and terminal styling.

use ansi_term::Style;
use ansi_term::Color::*;


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
    /// The style for CAA records.
    pub caa: Style,
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
            caa: Red.normal(),
            cname: Yellow.normal(),
            mx: Cyan.normal(),
            ns: Red.normal(),
            ptr: Red.normal(),
            soa: Purple.normal(),
            srv: Cyan.normal(),
            txt: Yellow.normal(),
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
