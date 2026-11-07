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

//! Rendering tables of DNS response results.

use std::fmt::Display;
use std::time::Duration;

use hickory_resolver::proto::op::Edns;
use hickory_resolver::proto::rr::{Record, RecordType};
use std::fmt::Write;

use crate::colours::{Colours, Paint};
use crate::output::{sanitize_for_terminal, TextFormat};

/// A **table** is built up from all the response records present in a DNS
/// packet. It then gets displayed to the user.
#[derive(Debug)]
pub struct Table {
    colours: Colours,
    text_format: TextFormat,
    rows: Vec<Row>,
}

/// A row of the table. This contains all the fields
#[derive(Debug)]
struct Row {
    qtype: StyledString,
    qname: String,
    ttl: Option<String>,
    section: Section,
    summary: String,
}

#[derive(Debug)]
struct StyledString {
    content: String,
    display_len: usize,
}

impl Display for StyledString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.content)
    }
}

/// The section of the DNS response that a record was read from.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Section {
    /// This record was found in the **Answer** section.
    Answer,
}

impl Table {
    /// Create a new table with no rows.
    pub fn new(colours: Colours, text_format: TextFormat) -> Self {
        Self {
            colours,
            text_format,
            rows: Vec::new(),
        }
    }

    /// Adds a row to the table, containing the data in the given answer in
    /// the right section.
    pub fn add_row(&mut self, record: &Record, section: Section) {
        let data = &record.data;
        let qtype = self.coloured_record_type(record);
        let qname = sanitize_for_terminal(&record.name.to_string());
        let summary = TextFormat::record_payload_summary(data);
        let ttl = Some(self.text_format.format_duration(record.ttl));
        self.rows.push(Row {
            qtype,
            qname,
            ttl,
            section,
            summary,
        });
    }

    /// Adds a row representing an EDNS OPT pseudo-record (`--edns=show`).
    pub fn add_edns_row(&mut self, edns: &Edns) {
        let qtype = paint_styled(self.colours.default, "OPT");
        let qname = ".".to_string();
        let flags = if edns.flags().dnssec_ok { "do" } else { "none" };
        let summary = format!(
            "UDP payload: {}, version: {}, flags: {}",
            edns.max_payload(),
            edns.version(),
            flags
        );
        self.rows.push(Row {
            qtype,
            qname,
            ttl: None,
            section: Section::Answer,
            summary,
        });
    }

    /// Renders the formatted table to a string.
    pub fn render(&self) -> String {
        let mut output = String::new();

        if !self.rows.is_empty() {
            let qtype_len = self.max_qtype_len();
            let qname_len = self.max_qname_len();
            let ttl_len = self.max_ttl_len();

            for r in &self.rows {
                output.push_str(&" ".repeat(qtype_len - r.qtype.display_len));
                let _ = write!(
                    output,
                    "{} {} ",
                    r.qtype,
                    self.colours.qname.paint(&r.qname)
                );
                output.push_str(&" ".repeat(qname_len - r.qname.chars().count()));

                if let Some(ttl) = &r.ttl {
                    output.push_str(&" ".repeat(ttl_len - ttl.len()));
                    output.push_str(ttl);
                } else {
                    output.push_str(&" ".repeat(ttl_len));
                }

                let _ = writeln!(output, " {} {}", self.format_section(r.section), r.summary);
            }
        }
        output
    }

    /// Prints the formatted table to stdout.
    pub fn print(self, duration: Option<Duration>) {
        crate::stdout::emit(&self.render());

        if let Some(dur) = duration {
            crate::stdout::emit_line(&format!("Ran in {}ms", dur.as_millis()));
        }
    }

    /// Returns a coloured string for a record type.
    fn coloured_record_type(&self, record: &Record) -> StyledString {
        match record.record_type() {
            RecordType::A => paint_styled(self.colours.a, "A"),
            RecordType::AAAA => paint_styled(self.colours.aaaa, "AAAA"),
            RecordType::CNAME => paint_styled(self.colours.cname, "CNAME"),
            RecordType::MX => paint_styled(self.colours.mx, "MX"),
            RecordType::NS => paint_styled(self.colours.ns, "NS"),
            RecordType::PTR => paint_styled(self.colours.ptr, "PTR"),
            RecordType::SOA => paint_styled(self.colours.soa, "SOA"),
            RecordType::SRV => paint_styled(self.colours.srv, "SRV"),
            RecordType::TXT => paint_styled(self.colours.txt, "TXT"),
            RecordType::CAA
            | RecordType::CDS
            | RecordType::CDNSKEY
            | RecordType::CSYNC
            | RecordType::DNSKEY
            | RecordType::DS
            | RecordType::KEY
            | RecordType::NSEC
            | RecordType::NSEC3
            | RecordType::NSEC3PARAM
            | RecordType::OPENPGPKEY
            | RecordType::RRSIG
            | RecordType::SIG
            | RecordType::SSHFP
            | RecordType::TLSA
            | RecordType::TSIG => {
                paint_styled(self.colours.security, record.record_type().to_string())
            }
            _ => paint_styled(self.colours.default, record.record_type().to_string()),
        }
    }

    /// Returns the maximum length of a qtype string.
    fn max_qtype_len(&self) -> usize {
        self.rows
            .iter()
            .map(|r| r.qtype.display_len)
            .max()
            .unwrap_or(0)
    }

    /// Returns the maximum length of a qname string.
    fn max_qname_len(&self) -> usize {
        self.rows
            .iter()
            .map(|r| r.qname.chars().count())
            .max()
            .unwrap_or(0)
    }

    /// Returns the maximum length of a TTL string.
    fn max_ttl_len(&self) -> usize {
        self.rows
            .iter()
            .map(|r| r.ttl.as_ref().map_or(0, String::len))
            .max()
            .unwrap_or(0)
    }

    /// Returns a coloured string for a section.
    fn format_section(&self, section: Section) -> String {
        match section {
            Section::Answer => self.colours.answer.paint(" "),
        }
    }
}

fn paint_styled<S: Display>(style: anstyle::Style, text: S) -> StyledString {
    let text_str = text.to_string();
    let display_len = text_str.len();
    let content = style.paint(text_str);
    StyledString {
        content,
        display_len,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hickory_resolver::proto::rr::rdata::{A, AAAA, MX, NS, TXT};
    use hickory_resolver::proto::rr::{Name, RData};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn aligns_columns_across_multiple_record_types_and_ttls() {
        let mut table = Table::new(
            Colours::plain(),
            TextFormat {
                format_durations: true,
            },
        );
        let name = Name::from_str("example.net.").unwrap();

        table.add_row(
            &Record::from_rdata(
                name.clone(),
                300,
                RData::A(A(Ipv4Addr::new(104, 20, 21, 8))),
            ),
            Section::Answer,
        );
        table.add_row(
            &Record::from_rdata(
                name.clone(),
                300,
                RData::AAAA(AAAA(Ipv6Addr::from_str("2606:4700:10::6814:1508").unwrap())),
            ),
            Section::Answer,
        );
        table.add_row(
            &Record::from_rdata(
                name.clone(),
                86400,
                RData::NS(NS(Name::from_str("hugh.ns.cloudflare.com.").unwrap())),
            ),
            Section::Answer,
        );
        table.add_row(
            &Record::from_rdata(
                name.clone(),
                300,
                RData::MX(MX::new(0, Name::from_str(".").unwrap())),
            ),
            Section::Answer,
        );
        table.add_row(
            &Record::from_rdata(
                name,
                300,
                RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()])),
            ),
            Section::Answer,
        );

        let expected = concat!(
            "   A example.net.      5m00s   104.20.21.8\n",
            "AAAA example.net.      5m00s   2606:4700:10::6814:1508\n",
            "  NS example.net. 1d0h00m00s   hugh.ns.cloudflare.com.\n",
            "  MX example.net.      5m00s   0 .\n",
            " TXT example.net.      5m00s   v=spf1 -all\n",
        );

        assert_eq!(table.render(), expected);
    }
}
