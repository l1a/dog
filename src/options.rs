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

//! Command-line option parsing.

use std::fmt;
use std::net::IpAddr;

use log::*;

use hickory_resolver::proto::rr::RecordType;

use crate::output::{OutputFormat, TextFormat, UseColours};

#[path = "cli.rs"]
pub mod cli;

/// The command-line options used when running dog.
#[derive(PartialEq, Debug)]
pub struct Options {
    /// The requests to make and how they should be generated.
    pub requests: Requests,

    /// Whether to display verbose information.
    pub verbose: bool,

    /// How to format the output data.
    pub format: OutputFormat,
}

/// The set of requests to make.
#[derive(PartialEq, Debug, Default)]
pub struct Requests {
    /// The inputs to generate requests from.
    pub inputs: Inputs,

    /// Whether to request DNSSEC validation.
    pub dnssec: bool,
}

/// The transport protocol to use for DNS queries.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum TransportType {
    /// UDP transport.
    UDP,
    /// TCP transport.
    TCP,
    /// TLS transport.
    TLS,
    /// HTTPS transport.
    HTTPS,
}

impl Options {
    /// Parses and interprets a set of options from the user’s command-line
    /// arguments.
    ///
    /// This returns an `Ok` set of options if successful and running
    /// normally, a `Help` or `Version` variant if one of those options is
    /// specified, or an error variant if there’s an invalid option or
    /// inconsistency within the options after they were parsed.
    #[allow(unused_results)]
    pub fn getopts<C>(args: C) -> OptionsResult
    where
        C: IntoIterator,
        C::Item: Into<std::ffi::OsString> + Clone,
    {
        let command = cli::build_cli();

        let matches = match command.try_get_matches_from(args) {
            Ok(m) => m,
            Err(e) => return OptionsResult::InvalidOptionsFormat(e.to_string()),
        };

        let uc = UseColours::deduce(&matches);

        if matches.get_flag("version") {
            OptionsResult::Version(uc)
        } else if matches.get_flag("help") {
            OptionsResult::Help(HelpReason::Flag, uc)
        } else if matches.get_flag("list") {
            OptionsResult::ListTypes
        } else if let Some(shell) = matches.get_one::<String>("completions") {
            OptionsResult::Completions(shell.clone())
        } else {
            let transport_type = if matches.get_flag("udp") {
                Some(TransportType::UDP)
            } else if matches.get_flag("tcp") {
                Some(TransportType::TCP)
            } else if matches.get_flag("tls") {
                Some(TransportType::TLS)
            } else if matches.get_flag("https") {
                Some(TransportType::HTTPS)
            } else {
                None
            };
            match Self::deduce(&matches, transport_type) {
                Ok(opts) => {
                    if opts.requests.inputs.domains.is_empty() {
                        OptionsResult::Help(HelpReason::NoDomains, uc)
                    } else {
                        OptionsResult::Ok(opts)
                    }
                }
                Err(e) => OptionsResult::InvalidOptions(e),
            }
        }
    }

    /// Deduce the options from the command-line matches.
    fn deduce(
        matches: &clap::ArgMatches,
        transport_type: Option<TransportType>,
    ) -> Result<Self, OptionsError> {
        let verbose = matches.get_flag("verbose");
        let format = OutputFormat::deduce(matches);
        let requests = Requests::deduce(matches, transport_type)?;

        Ok(Self {
            requests,
            verbose,
            format,
        })
    }
}

impl Requests {
    /// Deduce the requests from the command-line matches.
    fn deduce(
        matches: &clap::ArgMatches,
        transport_type: Option<TransportType>,
    ) -> Result<Self, OptionsError> {
        let mut dnssec = false;
        let tweaks = matches
            .get_many::<String>("Z")
            .unwrap_or_default()
            .cloned()
            .collect::<Vec<_>>();
        for tweak in tweaks {
            if tweak.eq_ignore_ascii_case("do") || tweak.eq_ignore_ascii_case("dnssec-ok") {
                dnssec = true;
            } else {
                return Err(OptionsError::InvalidTweak(tweak));
            }
        }

        let inputs = Inputs::deduce(matches, transport_type)?;

        Ok(Self { inputs, dnssec })
    }
}

/// Which things the user has specified they want queried.
#[derive(PartialEq, Debug, Default)]
pub struct Inputs {
    /// The list of domain names to query.
    pub domains: Vec<String>,

    /// The list of DNS record types to query for.
    pub record_types: Vec<RecordType>,

    /// Whether the user requested an "ANY" query.
    pub any_query: bool,

    /// The transport protocol to use.
    pub transport_type: Option<TransportType>,

    /// The nameservers to use.
    pub nameservers: Vec<String>,
}

impl Inputs {
    /// Deduce the inputs from the command-line matches.
    fn deduce(
        matches: &clap::ArgMatches,
        transport_type: Option<TransportType>,
    ) -> Result<Self, OptionsError> {
        let mut inputs = Self {
            transport_type,
            ..Self::default()
        };
        inputs.load_named_args(matches)?;
        inputs.load_free_args(matches);
        inputs.load_fallbacks();
        Ok(inputs)
    }

    /// Load the named arguments from the command-line matches.
    fn load_named_args(&mut self, matches: &clap::ArgMatches) -> Result<(), OptionsError> {
        let queries = matches
            .get_many::<String>("query")
            .unwrap_or_default()
            .cloned()
            .collect::<Vec<_>>();
        for domain in queries {
            self.add_domain(&domain);
        }

        let types = matches
            .get_many::<String>("type")
            .unwrap_or_default()
            .cloned()
            .collect::<Vec<_>>();
        for record_name in types {
            if record_name.eq_ignore_ascii_case("ANY") {
                self.add_type(RecordType::ANY);
            } else if let Ok(record_type) = record_name.to_uppercase().parse() {
                self.add_type(record_type);
            } else {
                return Err(OptionsError::InvalidQueryType(record_name));
            }
        }

        let nameservers = matches
            .get_many::<String>("nameserver")
            .unwrap_or_default()
            .cloned()
            .collect::<Vec<_>>();
        for ns in nameservers {
            self.add_nameserver(&ns);
        }

        Ok(())
    }

    /// Load the free arguments from the command-line matches.
    fn load_free_args(&mut self, matches: &clap::ArgMatches) {
        let free_args = matches
            .get_many::<String>("free")
            .unwrap_or_default()
            .cloned()
            .collect::<Vec<_>>();
        for argument in free_args {
            if let Some(nameserver) = argument.strip_prefix('@') {
                self.add_nameserver(nameserver);
            } else if is_constant_name(&argument) {
                if argument.eq_ignore_ascii_case("ANY") {
                    self.add_type(RecordType::ANY);
                } else if let Ok(record_type) = argument.to_uppercase().parse() {
                    trace!("Got qtype -> {:?}", &argument);
                    self.add_type(record_type);
                } else {
                    trace!("Got single-word domain -> {:?}", &argument);
                    self.add_domain(&argument);
                }
            } else {
                trace!("Got domain -> {:?}", &argument);

                if let Ok(ip) = argument.parse::<IpAddr>() {
                    let reverse_domain = reverse_lookup_domain(ip);
                    self.add_domain(&reverse_domain);
                    self.add_type(RecordType::PTR);
                } else {
                    self.add_domain(&argument);
                }
            }
        }
    }

    /// Load the fallback values for the inputs.
    fn load_fallbacks(&mut self) {
        if self.record_types.is_empty() {
            self.record_types.push(RecordType::A);
        }
    }

    /// Add a domain to the list of domains to query.
    fn add_domain(&mut self, input: &str) {
        self.domains.push(input.to_string());
    }

    /// Add a record type to the list of record types to query.
    fn add_type(&mut self, rt: RecordType) {
        if rt == RecordType::ANY {
            self.any_query = true;
        }
        self.record_types.push(rt);
    }

    /// Add a nameserver to the list of nameservers to use.
    fn add_nameserver(&mut self, input: &str) {
        self.nameservers.push(input.to_string());
    }
}

/// The list of record types to query when falling back from an ANY query.
pub const ANY_FALLBACK_TYPES: &[RecordType] = &[
    RecordType::A,
    RecordType::AAAA,
    RecordType::ANAME,
    RecordType::CAA,
    RecordType::CDNSKEY,
    RecordType::CDS,
    RecordType::CNAME,
    RecordType::CSYNC,
    RecordType::DNSKEY,
    RecordType::DS,
    RecordType::HINFO,
    RecordType::HTTPS,
    RecordType::KEY,
    RecordType::MX,
    RecordType::NAPTR,
    RecordType::NS,
    RecordType::NSEC,
    RecordType::NSEC3,
    RecordType::NSEC3PARAM,
    RecordType::OPENPGPKEY,
    RecordType::PTR,
    RecordType::RRSIG,
    RecordType::SIG,
    RecordType::SOA,
    RecordType::SRV,
    RecordType::SSHFP,
    RecordType::SVCB,
    RecordType::TLSA,
    RecordType::TXT,
];

/// Returns `true` if the argument is a constant-like name.
fn is_constant_name(argument: &str) -> bool {
    let Some(first_char) = argument.chars().next() else {
        return false;
    };

    if !first_char.is_ascii_alphabetic() {
        return false;
    }

    argument.chars().all(|c| c.is_ascii_alphanumeric())
}

use std::fmt::Write;
/// Returns the reverse lookup domain for an IP address.
fn reverse_lookup_domain(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            let mut reversed = String::new();
            for octet in v6.octets().iter().rev() {
                let nibble1 = octet & 0x0F;
                let nibble2 = (octet >> 4) & 0x0F;
                let _ = write!(reversed, "{nibble1:x}.{nibble2:x}.");
            }
            reversed.push_str("ip6.arpa");
            reversed
        }
    }
}

impl OutputFormat {
    /// Deduce the output format from the command-line matches.
    fn deduce(matches: &clap::ArgMatches) -> Self {
        if matches.get_flag("short") {
            let summary_format = TextFormat::deduce(matches);
            Self::Short(summary_format)
        } else if matches.get_flag("json") {
            Self::JSON
        } else {
            let use_colours = UseColours::deduce(matches);
            let summary_format = TextFormat::deduce(matches);
            Self::Text(use_colours, summary_format)
        }
    }
}

impl UseColours {
    /// Deduce the colour usage from the command-line matches.
    fn deduce(matches: &clap::ArgMatches) -> Self {
        match matches
            .get_one::<String>("color")
            .cloned()
            .or_else(|| matches.get_one::<String>("colour").cloned())
            .unwrap_or_default()
            .as_str()
        {
            "automatic" | "auto" | "" => Self::Automatic,
            "always" | "yes" => Self::Always,
            "never" | "no" => Self::Never,
            otherwise => {
                warn!("Unknown colour setting {otherwise:?}");
                Self::Automatic
            }
        }
    }
}

impl TextFormat {
    /// Deduce the text format from the command-line matches.
    fn deduce(matches: &clap::ArgMatches) -> Self {
        let format_durations = !matches.get_flag("seconds");
        Self { format_durations }
    }
}

/// The result of the `Options::getopts` function.
#[derive(PartialEq, Debug)]
pub enum OptionsResult {
    /// The options were parsed successfully.
    Ok(Options),

    /// There was an error (from `clap`) parsing the arguments.
    InvalidOptionsFormat(String),

    /// There was an error with the combination of options the user selected.
    InvalidOptions(OptionsError),

    /// Can’t run any checks because there’s help to display!
    Help(HelpReason, UseColours),

    /// One of the arguments was `--version`, to display the version number.
    Version(UseColours),

    /// One of the arguments was `--list`, to display the list of record types.
    ListTypes,

    /// One of the arguments was `--completions`, to generate shell completions.
    Completions(String),
}

/// The reason that help is being displayed. If it’s for the `--help` flag,
/// then we shouldn’t return an error exit status.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum HelpReason {
    /// Help was requested with the `--help` flag.
    Flag,

    /// There were no domains being queried, so display help instead.
    /// Unlike `dig`, we don’t implicitly search for the root domain.
    NoDomains,
}

/// Something wrong with the combination of options the user has picked.
#[derive(PartialEq, Debug)]
pub enum OptionsError {
    /// The query type is invalid.
    InvalidQueryType(String),
    /// The protocol tweak is invalid.
    InvalidTweak(String),
}

impl fmt::Display for OptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQueryType(qt) => write!(f, "Invalid query type {qt:?}"),
            Self::InvalidTweak(tw) => write!(f, "Invalid protocol tweak {tw:?}"),
        }
    }
}

/// A record type, its description, and an example.
pub struct RecordTypeInfo {
    /// The record type.
    pub record_type: RecordType,
    /// A description of the record type.
    pub description: &'static str,
    /// An example of the record type.
    pub example: &'static str,
}

/// Returns a list of all known record types.
pub fn all_record_types() -> Vec<RecordTypeInfo> {
    vec![
        RecordTypeInfo {
            record_type: RecordType::A,
            description: "IPv4 address",
            example: "dog example.com A",
        },
        RecordTypeInfo {
            record_type: RecordType::AAAA,
            description: "IPv6 address",
            example: "dog example.com AAAA",
        },
        RecordTypeInfo {
            record_type: RecordType::ANAME,
            description: "Alias name",
            example: "dog example.com ANAME",
        },
        RecordTypeInfo {
            record_type: RecordType::ANY,
            description: "All records",
            example: "dog example.com ANY",
        },
        RecordTypeInfo {
            record_type: RecordType::AXFR,
            description: "Zone transfer",
            example: "dog example.com AXFR",
        },
        RecordTypeInfo {
            record_type: RecordType::CAA,
            description: "Certification Authority Authorization",
            example: "dog example.com CAA",
        },
        RecordTypeInfo {
            record_type: RecordType::CNAME,
            description: "Canonical name",
            example: "dog www.example.com CNAME",
        },
        RecordTypeInfo {
            record_type: RecordType::DNSKEY,
            description: "DNS Key",
            example: "dog example.com DNSKEY",
        },
        RecordTypeInfo {
            record_type: RecordType::DS,
            description: "Delegation Signer",
            example: "dog example.com DS",
        },
        RecordTypeInfo {
            record_type: RecordType::HINFO,
            description: "Host Information",
            example: "dog example.com HINFO",
        },
        RecordTypeInfo {
            record_type: RecordType::HTTPS,
            description: "HTTPS Binding",
            example: "dog example.com HTTPS",
        },
        RecordTypeInfo {
            record_type: RecordType::IXFR,
            description: "Incremental Zone Transfer",
            example: "dog example.com IXFR",
        },
        RecordTypeInfo {
            record_type: RecordType::MX,
            description: "Mail exchange",
            example: "dog example.com MX",
        },
        RecordTypeInfo {
            record_type: RecordType::NAPTR,
            description: "Naming Authority Pointer",
            example: "dog example.com NAPTR",
        },
        RecordTypeInfo {
            record_type: RecordType::NS,
            description: "Name server",
            example: "dog example.com NS",
        },
        RecordTypeInfo {
            record_type: RecordType::NULL,
            description: "Null record",
            example: "dog example.com NULL",
        },
        RecordTypeInfo {
            record_type: RecordType::OPENPGPKEY,
            description: "OpenPGP Key",
            example: "dog example.com OPENPGPKEY",
        },
        RecordTypeInfo {
            record_type: RecordType::OPT,
            description: "Option",
            example: "dog example.com OPT",
        },
        RecordTypeInfo {
            record_type: RecordType::PTR,
            description: "Pointer",
            example: "dog 1.1.1.1 PTR",
        },
        RecordTypeInfo {
            record_type: RecordType::SOA,
            description: "Start of Authority",
            example: "dog example.com SOA",
        },
        RecordTypeInfo {
            record_type: RecordType::SRV,
            description: "Service locator",
            example: "dog _sip._tcp.example.com SRV",
        },
        RecordTypeInfo {
            record_type: RecordType::SSHFP,
            description: "SSH Public Key Fingerprint",
            example: "dog example.com SSHFP",
        },
        RecordTypeInfo {
            record_type: RecordType::SVCB,
            description: "Service Binding",
            example: "dog example.com SVCB",
        },
        RecordTypeInfo {
            record_type: RecordType::TLSA,
            description: "TLSA certificate association",
            example: "dog _443._tcp.example.com TLSA",
        },
        RecordTypeInfo {
            record_type: RecordType::TXT,
            description: "Text",
            example: "dog example.com TXT",
        },
        RecordTypeInfo {
            record_type: RecordType::RRSIG,
            description: "DNSSEC Signature",
            example: "dog example.com RRSIG",
        },
        RecordTypeInfo {
            record_type: RecordType::NSEC,
            description: "Next Secure record",
            example: "dog example.com NSEC",
        },
        RecordTypeInfo {
            record_type: RecordType::NSEC3,
            description: "Next Secure record version 3",
            example: "dog example.com NSEC3",
        },
        RecordTypeInfo {
            record_type: RecordType::NSEC3PARAM,
            description: "NSEC3 parameters",
            example: "dog example.com NSEC3PARAM",
        },
        RecordTypeInfo {
            record_type: RecordType::TSIG,
            description: "Transaction Signature",
            example: "dog example.com TSIG",
        },
        RecordTypeInfo {
            record_type: RecordType::CDS,
            description: "Child DS",
            example: "dog example.com CDS",
        },
        RecordTypeInfo {
            record_type: RecordType::CDNSKEY,
            description: "Child DNSKEY",
            example: "dog example.com CDNSKEY",
        },
        RecordTypeInfo {
            record_type: RecordType::CSYNC,
            description: "Child-To-Parent Synchronization",
            example: "dog example.com CSYNC",
        },
        RecordTypeInfo {
            record_type: RecordType::KEY,
            description: "Security Key",
            example: "dog example.com KEY",
        },
        RecordTypeInfo {
            record_type: RecordType::SIG,
            description: "Security Signature",
            example: "dog example.com SIG",
        },
    ]
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    impl Inputs {
        fn fallbacks() -> Self {
            Inputs {
                domains: vec![ /* No domains by default */ ],
                record_types: vec![RecordType::A],
                any_query: false,
                transport_type: None,
                nameservers: vec![],
            }
        }
    }

    impl OptionsResult {
        fn unwrap(self) -> Options {
            match self {
                Self::Ok(o) => o,
                _ => panic!("{:?}", self),
            }
        }
    }

    // help tests

    #[test]
    fn help() {
        assert_eq!(
            Options::getopts(&["--help"]),
            OptionsResult::Help(HelpReason::Flag, UseColours::Automatic)
        );
    }

    #[test]
    fn help_no_colour() {
        assert_eq!(
            Options::getopts(&["--help", "--colour=never"]),
            OptionsResult::Help(HelpReason::Flag, UseColours::Never)
        );
    }

    #[test]
    fn version() {
        assert_eq!(
            Options::getopts(&["--version"]),
            OptionsResult::Version(UseColours::Automatic)
        );
    }

    #[test]
    fn version_yes_color() {
        assert_eq!(
            Options::getopts(&["--version", "--color", "always"]),
            OptionsResult::Version(UseColours::Always)
        );
    }

    #[test]
    fn list_types() {
        assert_eq!(Options::getopts(&["--list"]), OptionsResult::ListTypes);
    }

    #[test]
    fn fail() {
        match Options::getopts(&["--pear"]) {
            OptionsResult::InvalidOptionsFormat(_) => (),
            _ => panic!("Expected InvalidOptionsFormat for unknown option"),
        }
    }

    #[test]
    fn empty() {
        let nothing: Vec<&str> = vec![];
        assert_eq!(
            Options::getopts(nothing),
            OptionsResult::Help(HelpReason::NoDomains, UseColours::Automatic)
        );
    }

    #[test]
    fn an_unrelated_argument() {
        match Options::getopts(&["--time"]) {
            OptionsResult::InvalidOptionsFormat(_) => (),
            _ => panic!("Expected InvalidOptionsFormat for unknown option"),
        }
    }

    // query tests

    #[test]
    fn just_domain() {
        let options = Options::getopts(&["lookup.dog"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec!["lookup.dog".to_string()],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn just_named_domain() {
        let options = Options::getopts(&["-q", "lookup.dog"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec!["lookup.dog".to_string()],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn domain_and_type() {
        let options = Options::getopts(&["lookup.dog", "SOA"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec!["lookup.dog".to_string()],
                record_types: vec![RecordType::SOA],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn domain_and_type_lowercase() {
        let options = Options::getopts(&["lookup.dog", "soa"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec!["lookup.dog".to_string()],
                record_types: vec![RecordType::SOA],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn domain_and_single_domain() {
        let options = Options::getopts(&["lookup.dog", "mixes"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec!["lookup.dog".to_string(), "mixes".to_string()],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn all_free() {
        let options = Options::getopts(&["lookup.dog", "NS", "@1.1.1.1"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec!["lookup.dog".to_string()],
                record_types: vec![RecordType::NS],
                nameservers: vec!["1.1.1.1".to_string()],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn all_parameters() {
        let options = Options::getopts(&[
            "-q",
            "lookup.dog",
            "--type",
            "SOA",
            "--nameserver",
            "1.1.1.1",
        ])
        .unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec!["lookup.dog".to_string()],
                record_types: vec![RecordType::SOA],
                nameservers: vec!["1.1.1.1".to_string()],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn all_parameters_lowercase() {
        let options = Options::getopts(&[
            "-q",
            "lookup.dog",
            "--type",
            "soa",
            "--nameserver",
            "1.1.1.1",
        ])
        .unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec!["lookup.dog".to_string()],
                record_types: vec![RecordType::SOA],
                nameservers: vec!["1.1.1.1".to_string()],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn two_types() {
        let options =
            Options::getopts(&["-q", "lookup.dog", "--type", "SRV", "--type", "AAAA"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec!["lookup.dog".to_string()],
                record_types: vec![RecordType::SRV, RecordType::AAAA],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn all_mixed_1() {
        let options = Options::getopts(&["lookup.dog", "SOA", "--nameserver", "1.1.1.1"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec!["lookup.dog".to_string()],
                record_types: vec![RecordType::SOA],
                nameservers: vec!["1.1.1.1".to_string()],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn all_mixed_2() {
        let options = Options::getopts(&["SOA", "MX", "-q", "lookup.dog"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec!["lookup.dog".to_string()],
                record_types: vec![RecordType::SOA, RecordType::MX],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn short_mode() {
        let tf = TextFormat {
            format_durations: true,
        };
        let options = Options::getopts(&["dom.ain", "--short"]).unwrap();
        assert_eq!(options.format, OutputFormat::Short(tf));
    }

    #[test]
    fn short_mode_seconds() {
        let tf = TextFormat {
            format_durations: false,
        };
        let options = Options::getopts(&["dom.ain", "--short", "--seconds"]).unwrap();
        assert_eq!(options.format, OutputFormat::Short(tf));
    }

    #[test]
    fn json_output() {
        let options = Options::getopts(&["dom.ain", "--json"]).unwrap();
        assert_eq!(options.format, OutputFormat::JSON);
    }

    // invalid options tests

    #[test]
    fn invalid_named_type() {
        match Options::getopts(&["-q", "lookup.dog", "-t", "tubes"]) {
            OptionsResult::InvalidOptionsFormat(_) => (),
            _ => panic!("Expected InvalidOptionsFormat for invalid type"),
        }
    }

    #[test]
    fn invalid_named_type_too_big() {
        match Options::getopts(&["-q", "lookup.dog", "-t", "999999"]) {
            OptionsResult::InvalidOptionsFormat(_) => (),
            _ => panic!("Expected InvalidOptionsFormat for invalid type"),
        }
    }

    #[test]
    fn invalid_tweak() {
        assert_eq!(
            Options::getopts(&["lookup.dog", "-Z", "unknown"]),
            OptionsResult::InvalidOptions(OptionsError::InvalidTweak("unknown".into()))
        );
    }

    // dnssec tests

    #[test]
    fn dnssec_ok() {
        let options = Options::getopts(&["dom.ain", "-Z", "do"]).unwrap();
        assert_eq!(options.requests.dnssec, true);
    }

    #[test]
    fn dnssec_ok_alias() {
        let options = Options::getopts(&["dom.ain", "-Z", "dnssec-ok"]).unwrap();
        assert_eq!(options.requests.dnssec, true);
    }

    // reverse lookup tests

    /// Verifies that IPv4 addresses are correctly converted to in-addr.arpa domains
    #[test]
    fn reverse_lookup_ipv4() {
        let ip: IpAddr = "8.8.4.4".parse().unwrap();
        assert_eq!(reverse_lookup_domain(ip), "4.4.8.8.in-addr.arpa");
    }

    /// Verifies that IPv6 addresses are correctly converted to ip6.arpa domains
    #[test]
    fn reverse_lookup_ipv6() {
        let ip: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        // 2001:4860:4860:0000:0000:0000:0000:8888
        // reverse nibbles...
        assert_eq!(
            reverse_lookup_domain(ip),
            "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn extended_record_types() {
        let options =
            Options::getopts(&["lookup.dog", "CDS", "CDNSKEY", "CSYNC", "KEY", "SIG"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec!["lookup.dog".to_string()],
                record_types: vec![
                    RecordType::CDS,
                    RecordType::CDNSKEY,
                    RecordType::CSYNC,
                    RecordType::KEY,
                    RecordType::SIG,
                ],
                ..Inputs::fallbacks()
            }
        );
    }
}
