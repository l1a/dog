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
use hickory_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use hickory_resolver::error::ResolveErrorKind;

use std::collections::HashSet;

mod colours;
mod hints;
mod logger;
mod output;
mod table;

mod options;
use self::options::*;
use futures::future::join_all;


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

        OptionsResult::ListTypes => {
            println!("{:<12} {:<40} {}", "Type", "Description", "Example");
            for info in all_record_types() {
                println!("{:<12} {:<40} {}", info.record_type.to_string(), info.description, info.example);
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

/// Returns the pretty-printed usage string.
fn usage_pretty() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/usage.pretty.txt"))
}

/// Returns the bland usage string.
fn usage_bland() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/usage.bland.txt"))
}

/// Returns the pretty-printed version string.
fn version_pretty() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/version.pretty.txt"))
}

/// Returns the bland version string.
fn version_bland() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/version.bland.txt"))
}


/// Runs dog with some options, returning the status to exit with.
///
/// # Arguments
///
/// * `options` - The command-line options.
///
/// # Returns
///
/// * The process exit code.
async fn run(Options { requests, format, verbose }: Options) -> i32 {
    use std::time::Instant;
    use std::net::{IpAddr, SocketAddr};

    let mut responses = Vec::new();
    let timer = if verbose { Some(Instant::now()) } else { None };

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

    let config = if requests.inputs.nameservers.is_empty() {
        match requests.inputs.transport_type {
            Some(TransportType::TLS) => ResolverConfig::cloudflare_tls(),
            Some(TransportType::HTTPS) => ResolverConfig::google_https(),
            _ => ResolverConfig::default(),
        }
    } else {
        let mut config = ResolverConfig::new();
        for ns_str in &requests.inputs.nameservers {
            if let Some(transport) = requests.inputs.transport_type {
                match (ns_str.as_str(), transport) {
                    ("google", TransportType::HTTPS) => {
                        config = ResolverConfig::google_https();
                        continue;
                    }
                    ("cloudflare", TransportType::HTTPS) => {
                        config = ResolverConfig::cloudflare_https();
                        continue;
                    }
                    ("cloudflare" | "one.one.one.one", TransportType::TLS) => {
                        config = ResolverConfig::cloudflare_tls();
                        continue;
                    }
                    _ => {}
                }
            }

            let protocol = match requests.inputs.transport_type {
                Some(TransportType::UDP) => Protocol::Udp,
                Some(TransportType::TCP) => Protocol::Tcp,
                Some(TransportType::TLS) => Protocol::Tls,
                Some(TransportType::HTTPS) => Protocol::Https,
                None => Protocol::Udp,
            };

            let port = match protocol {
                Protocol::Tls => 853,
                Protocol::Https => 443,
                _ => 53,
            };

            let mut tls_dns_name: Option<String> = None;

            let ip_addr: IpAddr = if let Ok(ip) = ns_str.parse::<IpAddr>() {
                if protocol == Protocol::Tls || protocol == Protocol::Https {
                    tls_dns_name = if ns_str == "8.8.8.8" || ns_str == "8.8.4.4" || ns_str == "2001:4860:4860::8888" || ns_str == "2001:4860:4860::8844" { Some("dns.google".to_string()) } else if ns_str == "1.1.1.1" || ns_str == "1.0.0.1" || ns_str == "2606:4700:4700::1111" || ns_str == "2606:4700:4700::1001" { Some("cloudflare-dns.com".to_string()) } else { Some(ns_str.clone()) };
                }
                ip
            } else {
                if protocol == Protocol::Tls || protocol == Protocol::Https {
                    tls_dns_name = if ns_str == "8.8.8.8" || ns_str == "8.8.4.4" || ns_str == "2001:4860:4860::8888" || ns_str == "2001:4860:4860::8844" { Some("dns.google".to_string()) } else if ns_str == "1.1.1.1" || ns_str == "1.0.0.1" || ns_str == "2606:4700:4700::1111" || ns_str == "2606:4700:4700::1001" { Some("cloudflare-dns.com".to_string()) } else { Some(ns_str.clone()) };
                }

                let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
                match resolver.lookup_ip(ns_str.as_str()).await {
                    Ok(lookup) => {
                        if let Some(ip) = lookup.iter().next() {
                            ip
                        } else {
                            eprintln!("Failed to resolve nameserver '{}': No IP addresses found", ns_str);
                            return exits::OPTIONS_ERROR;
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to resolve nameserver '{}': {}", ns_str, e);
                        return exits::OPTIONS_ERROR;
                    }
                }
            };

            let socket_addr = SocketAddr::new(ip_addr, port);
            let mut ns_config = NameServerConfig::new(socket_addr, protocol);
            if let Some(name) = tls_dns_name {
                ns_config.tls_dns_name = Some(name);
            }
            config.add_name_server(ns_config);
        }
        config
    };

    let resolver = TokioAsyncResolver::tokio(config.clone(), ResolverOpts::default());

    // Collect all lookup futures for parallel execution
    let mut futures = Vec::new();
    for domain in &requests.inputs.domains {
        for qtype in requests.inputs.record_types.iter().copied() {
            let resolver_clone = resolver.clone();
            let domain_str = domain.clone();
            let query_timer = Instant::now();
            futures.push(async move {
                let elapsed = query_timer.elapsed();
                let result = resolver_clone.lookup(&domain_str, qtype).await;
                (domain_str, qtype, result, elapsed)
            });
        }
    }

    // Execute all lookups concurrently and collect results
    let query_results = join_all(futures).await;

    // Sort results by domain, then qtype to maintain output order and blocks
    let mut sorted_results = query_results;
    sorted_results.sort_by_key(|(domain, qtype, _, _)| (domain.clone(), *qtype));

    // Process results in order
    for (domain, qtype, result, elapsed) in sorted_results {
        if verbose {
            let nameservers_set: HashSet<String> = config.name_servers().iter().map(|ns| ns.socket_addr.to_string()).collect();
            let mut nameservers: Vec<String> = nameservers_set.into_iter().collect();
            nameservers.sort();
            let nameserver_str = nameservers.join(", ");
            let transport = requests.inputs.transport_type.map_or("UDP", |t| match t {
                TransportType::UDP => "UDP",
                TransportType::TCP => "TCP",
                TransportType::TLS => "TLS",
                TransportType::HTTPS => "HTTPS",
            });
            let duration_ms = elapsed.as_secs_f64() * 1000.0;
            println!("Query for {} {} on {} ({}) finished in {:.2}ms", domain, qtype, nameserver_str, transport, duration_ms);
        }

        match result {
            Ok(response) => {
                if verbose {
                    format.print(vec![response], None);
                }
                else {
                    responses.push(response);
                }
            }
            Err(e) => {
                if requests.inputs.any_query {
                    if let ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                        // Suppress this specific error for ANY queries
                    } else {
                        format.print_error(e);
                        errored = true;
                    }
                } else {
                    format.print_error(e);
                    errored = true;
                }
            }
        }
    }

    if !verbose {
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
    else {
        let duration = timer.map(|t| t.elapsed());
        if let Some(duration) = duration {
            let duration_ms = duration.as_secs_f64() * 1000.0;
            println!("Ran in {:.2}ms", duration_ms);
        }

        if errored {
            exits::NETWORK_ERROR
        }
        else {
            exits::SUCCESS
        }
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
