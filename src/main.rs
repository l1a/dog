//! dog, the command-line DNS client.

#![warn(deprecated_in_future)]
#![warn(future_incompatible)]
#![warn(missing_copy_implementations)]
#![warn(missing_docs)]
#![warn(nonstandard_style)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts, trivial_numeric_casts)]
#![warn(unused)]

#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::enum_glob_use)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::wildcard_imports)]

#![deny(unsafe_code)]

use log::*;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

mod colours;
mod hints;
mod logger;
mod output;
mod table;

mod options;
use self::options::*;


/// Configures logging, parses the command-line options, and handles any
/// errors before passing control over to the Dog type.
#[tokio::main]
async fn main() {
    use std::env;
    use std::process::exit;

    logger::configure(env::var_os("DOG_DEBUG"));

    #[cfg(windows)]
    if let Err(e) = ansi_term::enable_ansi_support() {
        warn!("Failed to enable ANSI support: {}", e);
    }

    match Options::getopts(env::args_os().skip(1)) {
        OptionsResult::Ok(options) => {
            info!("Running with options -> {:#?}", options);
            exit(run(options).await);
        }

        OptionsResult::Help(help_reason, use_colours) => {
            if use_colours.should_use_colours() {
                print!("{}", usage_pretty());
            }
            else {
                print!("{}", usage_bland());
            }

            if help_reason == HelpReason::NoDomains {
                exit(exits::OPTIONS_ERROR);
            }
            else {
                exit(exits::SUCCESS);
            }
        }

        OptionsResult::Version(use_colours) => {
            if use_colours.should_use_colours() {
                print!("{}", version_pretty());
            }
            else {
                print!("{}", version_bland());
            }

            exit(exits::SUCCESS);
        }

        OptionsResult::InvalidOptionsFormat(oe) => {
            eprintln!("dog: Invalid options: {}", oe);
            exit(exits::OPTIONS_ERROR);
        }

        OptionsResult::InvalidOptions(why) => {
            eprintln!("dog: Invalid options: {}", why);
            exit(exits::OPTIONS_ERROR);
        }
    }
}

fn usage_pretty() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/usage.pretty.txt"))
}

fn usage_bland() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/usage.bland.txt"))
}

fn version_pretty() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/version.pretty.txt"))
}

fn version_bland() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/version.bland.txt"))
}


/// Runs dog with some options, returning the status to exit with.
async fn run(Options { requests, format, measure_time }: Options) -> i32 {
    use std::time::Instant;

    let mut responses = Vec::new();
    let timer = if measure_time { Some(Instant::now()) } else { None };

    let mut errored = false;

    let local_host_hints = match hints::LocalHosts::load() {
        Ok(lh) => lh,
        Err(e) => {
            warn!("Error loading local host hints: {}", e);
            hints::LocalHosts::default()
        }
    };

    for hostname_in_query in &requests.inputs.domains {
        if local_host_hints.contains(hostname_in_query) {
            eprintln!("warning: domain '{}' also exists in hosts file", hostname_in_query);
        }
    }

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    for domain in &requests.inputs.domains {
        for qtype in requests.inputs.record_types.iter().copied() {
            let result = resolver.lookup(domain.to_string().as_str(), qtype).await;

            match result {
                Ok(response) => {
                    responses.push(response);
                }
                Err(e) => {
                    format.print_error(e);
                    errored = true;
                }
            }
        }
    }


    let duration = timer.map(|t| t.elapsed());
    if format.print(responses, duration) {
        if errored {
            exits::NETWORK_ERROR
        }
        else {
            exits::SUCCESS
        }
    }
    else {
        exits::NO_SHORT_RESULTS
    }
}


/// The possible status numbers dog can exit with.
mod exits {

    /// Exit code for when everything turns out OK.
    pub const SUCCESS: i32 = 0;

    /// Exit code for when there was at least one network error during execution.
    pub const NETWORK_ERROR: i32 = 1;

    /// Exit code for when there is no result from the server when running in
    /// short mode. This can be any received server error, not just `NXDOMAIN`.
    pub const NO_SHORT_RESULTS: i32 = 2;

    /// Exit code for when the command-line options are invalid.
    pub const OPTIONS_ERROR: i32 = 3;
}
