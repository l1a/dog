//! Command-line option parsing.

use std::ffi::OsStr;
use std::fmt;
use std::net::IpAddr;

use log::*;

use hickory_resolver::proto::rr::RecordType;

use crate::output::{OutputFormat, UseColours, TextFormat};


/// The command-line options used when running dog.
#[derive(PartialEq, Debug)]
pub struct Options {

    /// The requests to make and how they should be generated.
    pub requests: Requests,

    /// Whether to display the time taken after every query.
    pub measure_time: bool,

    /// How to format the output data.
    pub format: OutputFormat,
}

/// The set of requests to make.
#[derive(PartialEq, Debug, Default)]
pub struct Requests {
    /// The inputs to generate requests from.
    pub inputs: Inputs,
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
    where C: IntoIterator,
          C::Item: AsRef<OsStr>,
    {
        let mut opts = getopts::Options::new();

        // Query options
        opts.optmulti("q", "query",       "Host name or domain name to query", "HOST");
        opts.optmulti("t", "type",        "Type of the DNS record being queried (A, MX, NS...)", "TYPE");
        opts.optmulti("n", "nameserver",  "Address of the nameserver to send packets to", "ADDR");
        opts.optmulti("",  "class",       "Network class of the DNS record being queried (IN, CH, HS)", "CLASS");

        // Sending options
        opts.optopt  ("",  "edns",         "Whether to OPT in to EDNS (disable, hide, show)", "SETTING");
        opts.optopt  ("",  "txid",         "Set the transaction ID to a specific value", "NUMBER");
        opts.optmulti("Z", "",             "Set uncommon protocol tweaks", "TWEAKS");

        // Protocol options
        opts.optflag ("U", "udp",          "Use the DNS protocol over UDP");
        opts.optflag ("T", "tcp",          "Use the DNS protocol over TCP");
        opts.optflag ("S", "tls",          "Use the DNS-over-TLS protocol");
        opts.optflag ("H", "https",        "Use the DNS-over-HTTPS protocol");

        // Output options
        opts.optopt  ("",  "color",        "When to use terminal colors",  "WHEN");
        opts.optopt  ("",  "colour",       "When to use terminal colours", "WHEN");
        opts.optflag ("J", "json",         "Display the output as JSON");
        opts.optflag ("",  "seconds",      "Do not format durations, display them as seconds");
        opts.optflag ("1", "short",        "Short mode: display nothing but the first result");
        opts.optflag ("",  "time",         "Print how long the response took to arrive");

        // Meta options
        opts.optflag ("v", "version",      "Print version information");
        opts.optflag ("?", "help",         "Print list of command-line options");
        opts.optflag ("l", "list",         "List known DNS record types");

        let matches = match opts.parse(args) {
            Ok(m)  => m,
            Err(e) => return OptionsResult::InvalidOptionsFormat(e),
        };

        let uc = UseColours::deduce(&matches);

        if matches.opt_present("version") {
            OptionsResult::Version(uc)
        }
        else if matches.opt_present("help") {
            OptionsResult::Help(HelpReason::Flag, uc)
        }
        else if matches.opt_present("list") {
            OptionsResult::ListTypes
        }
        else {
            match Self::deduce(matches) {
                Ok(opts) => {
                    if opts.requests.inputs.domains.is_empty() {
                        OptionsResult::Help(HelpReason::NoDomains, uc)
                    }
                    else {
                        OptionsResult::Ok(opts)
                    }
                }
                Err(e) => {
                    OptionsResult::InvalidOptions(e)
                }
            }
        }
    }

    /// Deduce the options from the command-line matches.
    fn deduce(matches: getopts::Matches) -> Result<Self, OptionsError> {
        let measure_time = matches.opt_present("time");
        let format = OutputFormat::deduce(&matches);
        let requests = Requests::deduce(matches)?;

        Ok(Self { requests, measure_time, format })
    }
}


impl Requests {
    /// Deduce the requests from the command-line matches.
    fn deduce(matches: getopts::Matches) -> Result<Self, OptionsError> {
        let inputs = Inputs::deduce(matches)?;

        Ok(Self { inputs })
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
}


impl Inputs {
    /// Deduce the inputs from the command-line matches.
    fn deduce(matches: getopts::Matches) -> Result<Self, OptionsError> {
        let mut inputs = Self::default();
        inputs.load_named_args(&matches)?;
        inputs.load_free_args(matches)?;
        inputs.load_fallbacks();
        Ok(inputs)
    }

    /// Load the named arguments from the command-line matches.
    fn load_named_args(&mut self, matches: &getopts::Matches) -> Result<(), OptionsError> {
        for domain in matches.opt_strs("query") {
            self.add_domain(&domain);
        }

        for record_name in matches.opt_strs("type") {
            if record_name.eq_ignore_ascii_case("ANY") {
                self.add_any_record_types();
            }
            else if let Ok(record_type) = record_name.to_uppercase().parse() {
                self.add_type(record_type);
            }
            else {
                return Err(OptionsError::InvalidQueryType(record_name));
            }
        }

        Ok(())
    }

    /// Load the free arguments from the command-line matches.
    fn load_free_args(&mut self, matches: getopts::Matches) -> Result<(), OptionsError> {
        for argument in matches.free {
            if let Some(nameserver) = argument.strip_prefix('@') {
                trace!("Got nameserver -> {:?}", nameserver);
            }
            else if is_constant_name(&argument) {
                if argument.eq_ignore_ascii_case("ANY") {
                    self.add_any_record_types();
                }
                else if let Ok(record_type) = argument.to_uppercase().parse() {
                    trace!("Got qtype -> {:?}", &argument);
                    self.add_type(record_type);
                }
                else {
                    trace!("Got single-word domain -> {:?}", &argument);
                    self.add_domain(&argument);
                }
            }
            else {
                trace!("Got domain -> {:?}", &argument);

                if let Ok(ip) = argument.parse::<IpAddr>() {
                    let reverse_domain = reverse_lookup_domain(ip);
                    self.add_domain(&reverse_domain);
                    self.add_type(RecordType::PTR);
                }
                else {
                    self.add_domain(&argument);
                }
            }
        }

        Ok(())
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
        self.record_types.push(rt);
    }

    /// Add a list of common record types to the list of record types to query.
    fn add_any_record_types(&mut self) {
        self.any_query = true;
        self.record_types.extend_from_slice(&[
            RecordType::A,
            RecordType::AAAA,
            RecordType::CAA,
            RecordType::CNAME,
            RecordType::DNSKEY,
            RecordType::DS,
            RecordType::MX,
            RecordType::NS,
            RecordType::PTR,
            RecordType::SOA,
            RecordType::SRV,
            RecordType::SSHFP,
            RecordType::TLSA,
            RecordType::TXT,
            RecordType::RRSIG,
        ]);
    }
}

/// Returns `true` if the argument is a constant-like name.
fn is_constant_name(argument: &str) -> bool {
    let first_char = match argument.chars().next() {
        Some(c)  => c,
        None     => return false,
    };

    if ! first_char.is_ascii_alphabetic() {
        return false;
    }

    argument.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Returns the reverse lookup domain for an IP address.
fn reverse_lookup_domain(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0])
        }
        IpAddr::V6(v6) => {
            let mut reversed = String::new();
            for octet in v6.octets().iter().rev() {
                let nibble1 = octet & 0x0F;
                let nibble2 = (octet >> 4) & 0x0F;
                reversed.push_str(&format!("{:x}.{:x}.", nibble1, nibble2));
            }
            reversed.push_str("ip6.arpa");
            reversed
        }
    }
}


impl OutputFormat {
    /// Deduce the output format from the command-line matches.
    fn deduce(matches: &getopts::Matches) -> Self {
        if matches.opt_present("short") {
            let summary_format = TextFormat::deduce(matches);
            Self::Short(summary_format)
        }
        else if matches.opt_present("json") {
            Self::JSON
        }
        else {
            let use_colours = UseColours::deduce(matches);
            let summary_format = TextFormat::deduce(matches);
            Self::Text(use_colours, summary_format)
        }
    }
}


impl UseColours {
    /// Deduce the colour usage from the command-line matches.
    fn deduce(matches: &getopts::Matches) -> Self {
        match matches.opt_str("color").or_else(|| matches.opt_str("colour")).unwrap_or_default().as_str() {
            "automatic" | "auto" | ""  => Self::Automatic,
            "always"    | "yes"        => Self::Always,
            "never"     | "no"         => Self::Never,
            otherwise => {
                warn!("Unknown colour setting {:?}", otherwise);
                Self::Automatic
            },
        }
    }
}


impl TextFormat {
    /// Deduce the text format from the command-line matches.
    fn deduce(matches: &getopts::Matches) -> Self {
        let format_durations = ! matches.opt_present("seconds");
        Self { format_durations }
    }
}


/// The result of the `Options::getopts` function.
#[derive(PartialEq, Debug)]
pub enum OptionsResult {

    /// The options were parsed successfully.
    Ok(Options),

    /// There was an error (from `getopts`) parsing the arguments.
    InvalidOptionsFormat(getopts::Fail),

    /// There was an error with the combination of options the user selected.
    InvalidOptions(OptionsError),

    /// Can’t run any checks because there’s help to display!
    Help(HelpReason, UseColours),

    /// One of the arguments was `--version`, to display the version number.
    Version(UseColours),

    /// One of the arguments was `--list`, to display the list of record types.
    ListTypes,
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
}

impl fmt::Display for OptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQueryType(qt)   => write!(f, "Invalid query type {:?}", qt),
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
        RecordTypeInfo { record_type: RecordType::A, description: "IPv4 address", example: "dog example.com A" },
        RecordTypeInfo { record_type: RecordType::AAAA, description: "IPv6 address", example: "dog example.com AAAA" },
        RecordTypeInfo { record_type: RecordType::ANAME, description: "Alias name", example: "dog example.com ANAME" },
        RecordTypeInfo { record_type: RecordType::ANY, description: "All records", example: "dog example.com ANY" },
        RecordTypeInfo { record_type: RecordType::AXFR, description: "Zone transfer", example: "dog example.com AXFR" },
        RecordTypeInfo { record_type: RecordType::CAA, description: "Certification Authority Authorization", example: "dog example.com CAA" },
        RecordTypeInfo { record_type: RecordType::CNAME, description: "Canonical name", example: "dog www.example.com CNAME" },
        RecordTypeInfo { record_type: RecordType::DNSKEY, description: "DNS Key", example: "dog example.com DNSKEY" },
        RecordTypeInfo { record_type: RecordType::DS, description: "Delegation Signer", example: "dog example.com DS" },
        RecordTypeInfo { record_type: RecordType::HINFO, description: "Host Information", example: "dog example.com HINFO" },
        RecordTypeInfo { record_type: RecordType::HTTPS, description: "HTTPS Binding", example: "dog example.com HTTPS" },
        RecordTypeInfo { record_type: RecordType::IXFR, description: "Incremental Zone Transfer", example: "dog example.com IXFR" },
        RecordTypeInfo { record_type: RecordType::MX, description: "Mail exchange", example: "dog example.com MX" },
        RecordTypeInfo { record_type: RecordType::NAPTR, description: "Naming Authority Pointer", example: "dog example.com NAPTR" },
        RecordTypeInfo { record_type: RecordType::NS, description: "Name server", example: "dog example.com NS" },
        RecordTypeInfo { record_type: RecordType::NULL, description: "Null record", example: "dog example.com NULL" },
        RecordTypeInfo { record_type: RecordType::OPENPGPKEY, description: "OpenPGP Key", example: "dog example.com OPENPGPKEY" },
        RecordTypeInfo { record_type: RecordType::OPT, description: "Option", example: "dog example.com OPT" },
        RecordTypeInfo { record_type: RecordType::PTR, description: "Pointer", example: "dog 1.1.1.1 PTR" },
        RecordTypeInfo { record_type: RecordType::SOA, description: "Start of Authority", example: "dog example.com SOA" },
        RecordTypeInfo { record_type: RecordType::SRV, description: "Service locator", example: "dog _sip._tcp.example.com SRV" },
        RecordTypeInfo { record_type: RecordType::SSHFP, description: "SSH Public Key Fingerprint", example: "dog example.com SSHFP" },
        RecordTypeInfo { record_type: RecordType::SVCB, description: "Service Binding", example: "dog example.com SVCB" },
        RecordTypeInfo { record_type: RecordType::TLSA, description: "TLSA certificate association", example: "dog _443._tcp.example.com TLSA" },
        RecordTypeInfo { record_type: RecordType::TXT, description: "Text", example: "dog example.com TXT" },
        RecordTypeInfo { record_type: RecordType::RRSIG, description: "DNSSEC Signature", example: "dog example.com RRSIG" },
        RecordTypeInfo { record_type: RecordType::NSEC, description: "Next Secure record", example: "dog example.com NSEC" },
        RecordTypeInfo { record_type: RecordType::NSEC3, description: "Next Secure record version 3", example: "dog example.com NSEC3" },
        RecordTypeInfo { record_type: RecordType::NSEC3PARAM, description: "NSEC3 parameters", example: "dog example.com NSEC3PARAM" },
        RecordTypeInfo { record_type: RecordType::TSIG, description: "Transaction Signature", example: "dog example.com TSIG" },
    ]
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    impl Inputs {
        fn fallbacks() -> Self {
            Inputs {
                domains:         vec![ /* No domains by default */ ],
                record_types:    vec![ RecordType::A ],
                any_query:       false,
            }
        }
    }

    impl OptionsResult {
        fn unwrap(self) -> Options {
            match self {
                Self::Ok(o)  => o,
                _            => panic!("{:?}", self),
            }
        }
    }

    // help tests

    #[test]
    fn help() {
        assert_eq!(Options::getopts(&[ "--help" ]),
                   OptionsResult::Help(HelpReason::Flag, UseColours::Automatic));
    }

    #[test]
    fn help_no_colour() {
        assert_eq!(Options::getopts(&[ "--help", "--colour=never" ]),
                   OptionsResult::Help(HelpReason::Flag, UseColours::Never));
    }

    #[test]
    fn version() {
        assert_eq!(Options::getopts(&[ "--version" ]),
                   OptionsResult::Version(UseColours::Automatic));
    }

    #[test]
    fn version_yes_color() {
        assert_eq!(Options::getopts(&[ "--version", "--color", "always" ]),
                   OptionsResult::Version(UseColours::Always));
    }

    #[test]
    fn list_types() {
        assert_eq!(Options::getopts(&[ "--list" ]),
                   OptionsResult::ListTypes);
    }

    #[test]
    fn fail() {
        assert_eq!(Options::getopts(&[ "--pear" ]),
                   OptionsResult::InvalidOptionsFormat(getopts::Fail::UnrecognizedOption("pear".into())));
    }

    #[test]
    fn empty() {
        let nothing: Vec<&str> = vec![];
        assert_eq!(Options::getopts(nothing),
                   OptionsResult::Help(HelpReason::NoDomains, UseColours::Automatic));
    }

    #[test]
    fn an_unrelated_argument() {
        assert_eq!(Options::getopts(&[ "--time" ]),
                   OptionsResult::Help(HelpReason::NoDomains, UseColours::Automatic));
    }

    // query tests

    #[test]
    fn just_domain() {
        let options = Options::getopts(&[ "lookup.dog" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains: vec![ "lookup.dog".to_string() ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn just_named_domain() {
        let options = Options::getopts(&[ "-q", "lookup.dog" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains: vec![ "lookup.dog".to_string() ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn domain_and_type() {
        let options = Options::getopts(&[ "lookup.dog", "SOA" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:      vec![ "lookup.dog".to_string() ],
            record_types: vec![ RecordType::SOA ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn domain_and_type_lowercase() {
        let options = Options::getopts(&[ "lookup.dog", "soa" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:      vec![ "lookup.dog".to_string() ],
            record_types: vec![ RecordType::SOA ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn domain_and_single_domain() {
        let options = Options::getopts(&[ "lookup.dog", "mixes" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:      vec![ "lookup.dog".to_string(),
                                "mixes".to_string() ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn all_free() {
        let options = Options::getopts(&[ "lookup.dog", "NS", "@1.1.1.1" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:        vec![ "lookup.dog".to_string() ],
            record_types:   vec![ RecordType::NS ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn all_parameters() {
        let options = Options::getopts(&[ "-q", "lookup.dog", "--type", "SOA", "--nameserver", "1.1.1.1" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:        vec![ "lookup.dog".to_string() ],
            record_types:   vec![ RecordType::SOA ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn all_parameters_lowercase() {
        let options = Options::getopts(&[ "-q", "lookup.dog", "--type", "soa", "--nameserver", "1.1.1.1" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:        vec![ "lookup.dog".to_string() ],
            record_types:   vec![ RecordType::SOA ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn two_types() {
        let options = Options::getopts(&[ "-q", "lookup.dog", "--type", "SRV", "--type", "AAAA" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:      vec![ "lookup.dog".to_string() ],
            record_types: vec![ RecordType::SRV, RecordType::AAAA ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn all_mixed_1() {
        let options = Options::getopts(&[ "lookup.dog", "SOA", "--nameserver", "1.1.1.1" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:        vec![ "lookup.dog".to_string() ],
            record_types:   vec![ RecordType::SOA ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn all_mixed_2() {
        let options = Options::getopts(&[ "SOA", "MX", "-q", "lookup.dog" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:      vec![ "lookup.dog".to_string() ],
            record_types: vec![ RecordType::SOA, RecordType::MX ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn short_mode() {
        let tf = TextFormat { format_durations: true };
        let options = Options::getopts(&[ "dom.ain", "--short" ]).unwrap();
        assert_eq!(options.format, OutputFormat::Short(tf));
    }

    #[test]
    fn short_mode_seconds() {
        let tf = TextFormat { format_durations: false };
        let options = Options::getopts(&[ "dom.ain", "--short", "--seconds" ]).unwrap();
        assert_eq!(options.format, OutputFormat::Short(tf));
    }

    #[test]
    fn json_output() {
        let options = Options::getopts(&[ "dom.ain", "--json" ]).unwrap();
        assert_eq!(options.format, OutputFormat::JSON);
    }

    // invalid options tests

    #[test]
    fn invalid_named_type() {
        assert_eq!(Options::getopts(&[ "lookup.dog", "--type", "tubes" ]),
                   OptionsResult::InvalidOptions(OptionsError::InvalidQueryType("tubes".into())));
    }

    #[test]
    fn invalid_named_type_too_big() {
        assert_eq!(Options::getopts(&[ "lookup.dog", "--type", "999999" ]),
                   OptionsResult::InvalidOptions(OptionsError::InvalidQueryType("999999".into())));
    }
}
