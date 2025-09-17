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

#[derive(PartialEq, Debug, Default)]
pub struct Requests {
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

    fn deduce(matches: getopts::Matches) -> Result<Self, OptionsError> {
        let measure_time = matches.opt_present("time");
        let format = OutputFormat::deduce(&matches);
        let requests = Requests::deduce(matches)?;

        Ok(Self { requests, measure_time, format })
    }
}


impl Requests {
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
}


impl Inputs {
    fn deduce(matches: getopts::Matches) -> Result<Self, OptionsError> {
        let mut inputs = Self::default();
        inputs.load_named_args(&matches)?;
        inputs.load_free_args(matches)?;
        inputs.load_fallbacks();
        Ok(inputs)
    }

    fn load_named_args(&mut self, matches: &getopts::Matches) -> Result<(), OptionsError> {
        for domain in matches.opt_strs("query") {
            self.add_domain(&domain);
        }

        for record_name in matches.opt_strs("type") {
            if let Ok(record_type) = record_name.to_uppercase().parse() {
                self.add_type(record_type);
            }
            else {
                return Err(OptionsError::InvalidQueryType(record_name));
            }
        }

        Ok(())
    }

    fn load_free_args(&mut self, matches: getopts::Matches) -> Result<(), OptionsError> {
        for argument in matches.free {
            if let Some(nameserver) = argument.strip_prefix('@') {
                trace!("Got nameserver -> {:?}", nameserver);
            }
            else if is_constant_name(&argument) {
                if let Ok(record_type) = argument.to_uppercase().parse() {
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

    fn load_fallbacks(&mut self) {
        if self.record_types.is_empty() {
            self.record_types.push(RecordType::A);
        }
    }

    fn add_domain(&mut self, input: &str) {
        self.domains.push(input.to_string());
    }

    fn add_type(&mut self, rt: RecordType) {
        self.record_types.push(rt);
    }
}

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
    InvalidQueryType(String),
}

impl fmt::Display for OptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQueryType(qt)   => write!(f, "Invalid query type {:?}", qt),
        }
    }
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
