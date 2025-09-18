//! Rendering tables of DNS response results.

use std::time::Duration;

use ansi_term::ANSIString;

use hickory_resolver::proto::rr::{Record, RecordType};

use crate::colours::Colours;
use crate::output::TextFormat;


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
    qtype: ANSIString<'static>,
    qname: String,
    ttl: Option<String>,
    section: Section,
    summary: String,
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
        Self { colours, text_format, rows: Vec::new() }
    }

    /// Adds a row to the table, containing the data in the given answer in
    /// the right section.
    pub fn add_row(&mut self, record: Record, section: Section) {
        if let Some(data) = record.data() {
            let qtype = self.coloured_record_type(&record);
            let qname = record.name().to_string();
            let summary = self.text_format.record_payload_summary(data);
            let ttl = Some(self.text_format.format_duration(record.ttl()));
            self.rows.push(Row { qtype, qname, ttl, summary, section });
        }
    }

    /// Renders the formatted table to a string.
    pub fn render(&self) -> String {
        let mut output = String::new();

        if ! self.rows.is_empty() {
            let qtype_len = self.max_qtype_len();
            let qname_len = self.max_qname_len();
            let ttl_len   = self.max_ttl_len();

            for r in &self.rows {
                output.push_str(&" ".repeat(qtype_len - r.qtype.len()));
                output.push_str(&format!("{} {} ", r.qtype, self.colours.qname.paint(&r.qname)));
                output.push_str(&" ".repeat(qname_len - r.qname.len()));

                if let Some(ttl) = &r.ttl {
                    output.push_str(&" ".repeat(ttl_len - ttl.len()));
                    output.push_str(ttl);
                }
                else {
                    output.push_str(&" ".repeat(ttl_len));
                }

                output.push_str(&format!(" {} {}
", self.format_section(r.section), r.summary));
            }
        }
        output
    }

    /// Prints the formatted table to stdout.
    #[allow(dead_code)]
    pub fn print(self, duration: Option<Duration>) {
        print!("{}", self.render());

        if let Some(dur) = duration {
            println!("Ran in {}ms", dur.as_millis());
        }
    }

    /// Returns a coloured string for a record type.
    fn coloured_record_type(&self, record: &Record) -> ANSIString<'static> {
        match record.record_type() {
            RecordType::A     => self.colours.a.paint("A"),
            RecordType::AAAA  => self.colours.aaaa.paint("AAAA"),
            RecordType::CAA   => self.colours.caa.paint("CAA"),
            RecordType::CNAME => self.colours.cname.paint("CNAME"),
            RecordType::MX    => self.colours.mx.paint("MX"),
            RecordType::NS    => self.colours.ns.paint("NS"),
            RecordType::PTR   => self.colours.ptr.paint("PTR"),
            RecordType::SOA   => self.colours.soa.paint("SOA"),
            RecordType::SRV   => self.colours.srv.paint("SRV"),
            RecordType::TXT   => self.colours.txt.paint("TXT"),
            _                 => self.colours.default.paint(record.record_type().to_string()),
        }
    }

    /// Returns the maximum length of a qtype string.
    fn max_qtype_len(&self) -> usize {
        self.rows.iter().map(|r| r.qtype.len()).max().unwrap_or(0)
    }

    /// Returns the maximum length of a qname string.
    fn max_qname_len(&self) -> usize {
        self.rows.iter().map(|r| r.qname.len()).max().unwrap_or(0)
    }

    /// Returns the maximum length of a TTL string.
    fn max_ttl_len(&self) -> usize {
        self.rows.iter().map(|r| r.ttl.as_ref().map_or(0, String::len)).max().unwrap_or(0)
    }

    /// Returns a coloured string for a section.
    fn format_section(&self, section: Section) -> ANSIString<'static> {
        match section {
            Section::Answer      => self.colours.answer.paint(" "),
        }
    }
}
