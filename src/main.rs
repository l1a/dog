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
// Standard output goes through `stdout`, which does not panic when the reader of a pipe goes away.
#![deny(clippy::print_stdout)]

use hickory_resolver::caching_client::CachingClient;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::{DnsHandle, RetryDnsHandle};
use hickory_resolver::net::NetError;
use hickory_resolver::proto::op::{DnsRequest, DnsRequestOptions, Query};
use hickory_resolver::proto::rr::{DNSClass, IntoName, RecordType};
use hickory_resolver::{NameServerPool, PoolContext, TlsConfig};
use log::*;

use crate::options::ANY_FALLBACK_TYPES;
use crate::output::sanitize_for_terminal;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

// Windows-specific import for retrieving system DNS servers via ipconfig

mod colours;
mod hints;
mod logger;
mod output;
mod stdout;
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

    match Options::getopts(env::args_os().skip(1)) {
        OptionsResult::Ok(options) => {
            info!("Running with options -> {options:#?}");
            exit(run(options).await);
        }

        OptionsResult::Help(help_reason, use_colours) => {
            let mut cmd = options::cli::build_cli();
            if use_colours.should_use_colours() {
                cmd = cmd.color(clap::ColorChoice::Always);
            } else {
                cmd = cmd.color(clap::ColorChoice::Never);
            }

            let _ = cmd.print_help();

            if help_reason == HelpReason::NoDomains {
                exit(exits::OPTIONS_ERROR);
            }
            exit(exits::SUCCESS);
        }

        OptionsResult::Version(use_colours) => {
            if use_colours.should_use_colours() {
                stdout::emit(version_pretty());
            } else {
                stdout::emit(version_bland());
            }

            exit(exits::SUCCESS);
        }

        OptionsResult::ListTypes => {
            stdout::emit_line(&format!("{:<12} {:<40} Example", "Type", "Description"));
            for info in all_record_types() {
                stdout::emit_line(&format!(
                    "{:<12} {:<40} {}",
                    info.record_type.to_string(),
                    info.description,
                    info.example
                ));
            }
            exit(exits::SUCCESS);
        }

        OptionsResult::Completions(shell) => {
            use clap_complete::{generate, Shell};
            use clap_complete_nushell::Nushell;

            let mut cmd = options::cli::build_cli();

            // Generated into a buffer and written once: clap_complete panics if a write to the
            // pipe fails, which `dog --completions bash | head -1` makes it do.
            let mut buffer: Vec<u8> = Vec::new();

            if shell.eq_ignore_ascii_case("nushell") || shell.eq_ignore_ascii_case("nu") {
                generate(Nushell, &mut cmd, "dog", &mut buffer);
            } else if let Ok(s) = shell.parse::<Shell>() {
                generate(s, &mut cmd, "dog", &mut buffer);
            } else {
                eprintln!("dog: Unknown shell: {shell}");
                exit(exits::OPTIONS_ERROR);
            }
            stdout::emit_bytes(&buffer);
            exit(exits::SUCCESS);
        }

        OptionsResult::InvalidOptionsFormat(oe) => {
            eprintln!("dog: Invalid options: {oe}");
            exit(exits::OPTIONS_ERROR);
        }

        OptionsResult::InvalidOptions(why) => {
            eprintln!("dog: Invalid options: {why}");
            exit(exits::OPTIONS_ERROR);
        }
    }
}

/// Returns the pretty-printed version string.
fn version_pretty() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/version.pretty.txt"))
}

/// Returns the bland version string.
fn version_bland() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/version.bland.txt"))
}

/// Wrapper around [`RetryDnsHandle`] that applies header-level overrides
/// (`--txid`, `-Z aa`, `-Z ad`, `-Z cd`) to outgoing DNS requests.
#[derive(Clone)]
struct DogDnsHandle {
    inner: RetryDnsHandle<NameServerPool<TokioRuntimeProvider>>,
    txid: Option<u16>,
    authoritative: bool,
    authentic_data: bool,
    checking_disabled: bool,
}

impl DnsHandle for DogDnsHandle {
    type Response = <RetryDnsHandle<NameServerPool<TokioRuntimeProvider>> as DnsHandle>::Response;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, mut request: DnsRequest) -> Self::Response {
        if let Some(id) = self.txid {
            request.metadata.id = id;
        }
        if self.authoritative {
            request.metadata.authoritative = true;
        }
        if self.authentic_data {
            request.metadata.authentic_data = true;
        }
        if self.checking_disabled {
            request.metadata.checking_disabled = true;
        }
        self.inner.send(request)
    }
}

/// Parses a nameserver specification (`host`, `ip`, `host:port`, `ip:port`, or `[ipv6]:port`)
/// into its host/IP string and an optional port override.
fn parse_nameserver_target(ns_str: &str) -> Result<(String, Option<u16>), String> {
    if ns_str.parse::<IpAddr>().is_ok() {
        return Ok((ns_str.to_string(), None));
    }

    if let Ok(sock) = ns_str.parse::<SocketAddr>() {
        if sock.port() == 0 {
            return Err(format!("invalid port 0 in '{ns_str}'"));
        }
        return Ok((sock.ip().to_string(), Some(sock.port())));
    }

    if let Some(rest) = ns_str.strip_prefix('[') {
        if let Some(ipv6_str) = rest.strip_suffix(']') {
            if ipv6_str.parse::<IpAddr>().is_ok() {
                return Ok((ipv6_str.to_string(), None));
            }
            return Err(format!("invalid IPv6 address in '{ns_str}'"));
        }
        if let Some((ipv6_str, port_str)) = rest.rsplit_once("]:") {
            if ipv6_str.parse::<IpAddr>().is_err() {
                return Err(format!("invalid IPv6 address in '{ns_str}'"));
            }
            let port = port_str
                .parse::<u16>()
                .ok()
                .filter(|&p| p != 0)
                .ok_or_else(|| format!("invalid port '{port_str}' in '{ns_str}'"))?;
            return Ok((ipv6_str.to_string(), Some(port)));
        }
        return Err(format!("unclosed bracket in '{ns_str}'"));
    }

    if let Some((host, port_str)) = ns_str.rsplit_once(':') {
        if !host.contains(':') {
            if host.is_empty() {
                return Err(format!("missing host in '{ns_str}'"));
            }
            let port = port_str
                .parse::<u16>()
                .ok()
                .filter(|&p| p != 0)
                .ok_or_else(|| format!("invalid port '{port_str}' in '{ns_str}'"))?;
            return Ok((host.to_string(), Some(port)));
        }
    }

    Ok((ns_str.to_string(), None))
}

/// Maps well-known public DNS resolver IP addresses to their TLS certificate
/// DNS names when an IP literal is used with `-S` (`--tls`) or `-H` (`--https`).
fn default_tls_server_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => match v4.octets() {
            [8, 8, 8, 8] | [8, 8, 4, 4] => "dns.google".to_string(),
            [1, 1, 1, 1] | [1, 0, 0, 1] => "cloudflare-dns.com".to_string(),
            [9, 9, 9, 9] | [149, 112, 112, 112] => "dns.quad9.net".to_string(),
            _ => ip.to_string(),
        },
        IpAddr::V6(v6) => match v6.segments() {
            [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888 | 0x8844] => "dns.google".to_string(),
            [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111 | 0x1001] => {
                "cloudflare-dns.com".to_string()
            }
            [0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe | 0x0009] => "dns.quad9.net".to_string(),
            _ => ip.to_string(),
        },
    }
}

/// Builds the connection configurations for a nameserver according to the
/// requested transport type and optional port override.
fn build_connections(
    transport_type: Option<TransportType>,
    tls_server_name: Option<&str>,
    ip_addr: IpAddr,
    custom_port: Option<u16>,
) -> Vec<ConnectionConfig> {
    let mut connections = match transport_type {
        Some(TransportType::TCP) => vec![ConnectionConfig::tcp()],
        Some(TransportType::UDP) => vec![ConnectionConfig::udp()],
        None => vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
        Some(TransportType::TLS) => {
            let server_name = tls_server_name
                .map_or_else(|| default_tls_server_name(ip_addr), ToString::to_string);
            vec![ConnectionConfig::tls(Arc::from(server_name.as_str()))]
        }
        Some(TransportType::HTTPS) => {
            let server_name = tls_server_name
                .map_or_else(|| default_tls_server_name(ip_addr), ToString::to_string);
            vec![ConnectionConfig::https(
                Arc::from(server_name.as_str()),
                None,
            )]
        }
    };

    if let Some(port) = custom_port {
        for conn in &mut connections {
            conn.port = port;
        }
    }

    connections
}

/// Executes a single DNS lookup against the [`CachingClient`].
async fn execute_single_lookup(
    client: &CachingClient<DogDnsHandle>,
    domain_str: &str,
    qtype: RecordType,
    qclass: DNSClass,
    request_opts: DnsRequestOptions,
) -> Result<Lookup, NetError> {
    let mut name = domain_str.into_name()?;
    name.set_fqdn(true);
    let mut query = Query::query(name, qtype);
    query.set_query_class(qclass);
    client.lookup(query, request_opts).await
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
async fn run(
    Options {
        requests,
        format,
        verbose,
    }: Options,
) -> i32 {
    use std::time::Instant;

    let mut responses = Vec::new();
    let timer = if verbose { Some(Instant::now()) } else { None };

    let mut errored = false;
    // A default query asks for A and AAAA. An empty family is omitted when the
    // other family answered, and reported only when neither query returned a record.
    let mut answered: HashSet<(String, DNSClass)> = HashSet::new();
    let mut hard_errors: HashSet<(String, DNSClass)> = HashSet::new();
    let mut empty_family: HashMap<(String, DNSClass), NetError> = HashMap::new();

    // Load DNS resolver configuration: use system defaults if no custom nameservers provided
    let config = if requests.inputs.nameservers.is_empty() {
        match requests.inputs.transport_type {
            Some(TransportType::TLS) => ResolverConfig::tls(&hickory_resolver::config::CLOUDFLARE),
            Some(TransportType::HTTPS) => ResolverConfig::https(&hickory_resolver::config::GOOGLE),
            _ => {
                // Cross-platform loading of system DNS servers for UDP/TCP transport
                let nameservers: Vec<IpAddr> = if cfg!(target_os = "windows") {
                    #[cfg(windows)]
                    {
                        // On Windows, use ipconfig to retrieve DNS servers from network adapters
                        ipconfig::get_adapters()
                            .unwrap_or_default()
                            .into_iter()
                            .flat_map(|adapter| adapter.dns_servers().to_vec())
                            .collect()
                    }
                    #[cfg(not(windows))]
                    {
                        vec![]
                    }
                } else {
                    // On Unix/Linux, parse /etc/resolv.conf for DNS server entries
                    match fs::read_to_string("/etc/resolv.conf") {
                        Ok(content) => content
                            .lines()
                            .filter_map(|line| {
                                let line = line.trim();
                                line.strip_prefix("nameserver ")?
                                    .trim()
                                    .parse::<IpAddr>()
                                    .ok()
                            })
                            .collect(),
                        Err(_) => vec![],
                    }
                };
                let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
                for ns in nameservers {
                    let connections =
                        build_connections(requests.inputs.transport_type, None, ns, None);
                    let ns_config = NameServerConfig::new(ns, true, connections);
                    config.add_name_server(ns_config);
                }
                if config.name_servers().is_empty() {
                    let fallback = ResolverConfig::udp_and_tcp(&hickory_resolver::config::GOOGLE);
                    for ns in fallback.name_servers() {
                        let connections =
                            build_connections(requests.inputs.transport_type, None, ns.ip, None);
                        config.add_name_server(NameServerConfig::new(ns.ip, true, connections));
                    }
                    config
                } else {
                    config
                }
            }
        }
    } else {
        let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
        for ns_str in &requests.inputs.nameservers {
            if let Some(transport) = requests.inputs.transport_type {
                match (ns_str.as_str(), transport) {
                    ("google", TransportType::HTTPS) => {
                        config = ResolverConfig::https(&hickory_resolver::config::GOOGLE);
                        continue;
                    }
                    ("cloudflare", TransportType::HTTPS) => {
                        config = ResolverConfig::https(&hickory_resolver::config::CLOUDFLARE);
                        continue;
                    }
                    ("cloudflare" | "one.one.one.one", TransportType::TLS) => {
                        config = ResolverConfig::tls(&hickory_resolver::config::CLOUDFLARE);
                        continue;
                    }
                    _ => {}
                }
            }

            let (host_part, custom_port) = match parse_nameserver_target(ns_str) {
                Ok(parsed) => parsed,
                Err(why) => {
                    eprintln!(
                        "Failed to resolve nameserver '{}': {}",
                        sanitize_for_terminal(ns_str),
                        sanitize_for_terminal(&why)
                    );
                    return exits::OPTIONS_ERROR;
                }
            };

            let is_tls = matches!(
                requests.inputs.transport_type,
                Some(TransportType::TLS | TransportType::HTTPS)
            );

            let (resolved_ips, tls_dns_name): (Vec<IpAddr>, Option<String>) = if let Ok(ip) =
                host_part.parse::<IpAddr>()
            {
                let sni = if is_tls {
                    Some(default_tls_server_name(ip))
                } else {
                    None
                };
                (vec![ip], sni)
            } else {
                // A host name is resolved by the operating system (getaddrinfo: the hosts file,
                // nsswitch, systemd-resolved, a VPN's split DNS), as the man page says, not by dog.
                // It was once a hickory resolver built from ResolverConfig::default(), which meant
                // Google in hickory 0.24 and became an empty server list in 0.26, so every host name
                // failed with "no connections available".
                let sni = if is_tls {
                    Some(host_part.clone())
                } else {
                    None
                };

                match tokio::net::lookup_host((host_part.as_str(), custom_port.unwrap_or(0))).await
                {
                    Ok(addrs) => {
                        let mut ips = Vec::new();
                        for addr in addrs {
                            if !ips.contains(&addr.ip()) {
                                ips.push(addr.ip());
                            }
                        }
                        if ips.is_empty() {
                            eprintln!(
                                "Failed to resolve nameserver '{}': No IP addresses found",
                                sanitize_for_terminal(ns_str)
                            );
                            return exits::OPTIONS_ERROR;
                        }
                        (ips, sni)
                    }
                    Err(e) => {
                        eprintln!(
                            "Failed to resolve nameserver '{}': {}",
                            sanitize_for_terminal(ns_str),
                            sanitize_for_terminal(&e.to_string())
                        );
                        return exits::OPTIONS_ERROR;
                    }
                }
            };

            for ip_addr in resolved_ips {
                let connections = build_connections(
                    requests.inputs.transport_type,
                    tls_dns_name.as_deref(),
                    ip_addr,
                    custom_port,
                );
                let ns_config = NameServerConfig::new(ip_addr, true, connections);
                config.add_name_server(ns_config);
            }
        }
        config
    };

    let local_host_hints = match hints::LocalHosts::load() {
        Ok(lh) => lh,
        Err(e) => {
            warn!("Error loading local host hints: {e}");
            hints::LocalHosts::default()
        }
    };

    for hostname_in_query in &requests.inputs.domains {
        if local_host_hints.contains(hostname_in_query) {
            eprintln!(
                "warning: domain '{}' also exists in hosts file",
                sanitize_for_terminal(hostname_in_query)
            );
        }
    }

    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.edns0 = requests.edns != EdnsMode::Disable;
    if let Some(payload_len) = requests.udp_payload_size {
        resolver_opts.edns_payload_len = payload_len;
    }

    let mut request_opts = DnsRequestOptions::default();
    request_opts.recursion_desired = resolver_opts.recursion_desired;
    request_opts.use_edns = resolver_opts.edns0;
    request_opts.edns_payload_len = resolver_opts.edns_payload_len;
    request_opts.edns_set_dnssec_ok = requests.dnssec;

    let tls_config = match TlsConfig::new() {
        Ok(cfg) => cfg,
        Err(e) => {
            format.print_error(&e);
            return exits::NETWORK_ERROR;
        }
    };
    let pool_context = Arc::new(PoolContext::new(resolver_opts.clone(), tls_config));
    let pool = NameServerPool::from_config(
        config.name_servers().to_vec(),
        pool_context,
        TokioRuntimeProvider::default(),
    );
    let retry_handle = RetryDnsHandle::new(pool, resolver_opts.attempts);
    let dog_handle = DogDnsHandle {
        inner: retry_handle,
        txid: requests.txid,
        authoritative: requests.authoritative,
        authentic_data: requests.authentic_data,
        checking_disabled: requests.checking_disabled,
    };
    let client_cache = CachingClient::new(
        resolver_opts.cache_size,
        dog_handle,
        resolver_opts.preserve_intermediates,
    );

    // Collect all lookup futures. When an explicit `--txid` is set, run queries
    // sequentially so two requests with the same 16-bit transaction ID are never
    // in flight simultaneously on a multiplexed connection.
    let serialize_txid = requests.txid.is_some();
    let mut futures = Vec::new();
    for domain in &requests.inputs.domains {
        for qclass in requests.inputs.classes.iter().copied() {
            for qtype in requests.inputs.record_types.iter().copied() {
                let client_clone = client_cache.clone();
                let domain_str = domain.clone();
                futures.push(async move {
                    if qtype == RecordType::ANY {
                        // Perform an exhaustive sweep of all record types
                        let mut fallback_futures = Vec::new();
                        for f_qtype in ANY_FALLBACK_TYPES.iter().copied() {
                            let f_client = client_clone.clone();
                            let f_domain_str = domain_str.clone();
                            fallback_futures.push(async move {
                                let f_timer = Instant::now();
                                let f_result = execute_single_lookup(
                                    &f_client,
                                    &f_domain_str,
                                    f_qtype,
                                    qclass,
                                    request_opts,
                                )
                                .await;
                                let f_elapsed = f_timer.elapsed();
                                (f_domain_str, qclass, f_qtype, f_result, f_elapsed)
                            });
                        }
                        if serialize_txid {
                            let mut out = Vec::with_capacity(fallback_futures.len());
                            for fut in fallback_futures {
                                out.push(fut.await);
                            }
                            out
                        } else {
                            join_all(fallback_futures).await
                        }
                    } else {
                        let query_timer = Instant::now();
                        let result = execute_single_lookup(
                            &client_clone,
                            &domain_str,
                            qtype,
                            qclass,
                            request_opts,
                        )
                        .await;
                        let elapsed = query_timer.elapsed();
                        vec![(domain_str, qclass, qtype, result, elapsed)]
                    }
                });
            }
        }
    }

    let query_results = if serialize_txid {
        let mut out = Vec::with_capacity(futures.len());
        for fut in futures {
            out.push(fut.await);
        }
        out
    } else {
        join_all(futures).await
    };

    // Sort results by domain, qclass, then qtype to maintain output order and blocks
    let mut sorted_results: Vec<_> = query_results.into_iter().flatten().collect();
    sorted_results.sort_by_key(|(domain, qclass, qtype, _, _)| (domain.clone(), *qclass, *qtype));

    let show_edns = requests.edns == EdnsMode::Show;

    // Process results in order
    for (domain, qclass, qtype, result, elapsed) in sorted_results {
        if verbose {
            let nameservers_set: HashSet<String> = config
                .name_servers()
                .iter()
                .map(|ns| ns.ip.to_string())
                .collect();
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
            let safe_domain = sanitize_for_terminal(&domain);
            stdout::emit_line(&format!("Query for {safe_domain} {qtype} on {nameserver_str} ({transport}) finished in {duration_ms:.2}ms"));
        }

        let family_key = (domain.clone(), qclass);
        match result {
            Ok(response) => {
                answered.insert(family_key);
                if verbose {
                    format.print_with_edns(vec![response], None, show_edns);
                } else {
                    responses.push(response);
                }
            }
            Err(e) => {
                if requests.inputs.any_query {
                    let err_str = e.to_string();
                    if e.is_no_records_found()
                        || err_str.contains("Not Implemented")
                        || err_str.contains("Form Error")
                    {
                        // Suppress this specific error for ANY queries
                    } else {
                        format.print_error(&e);
                        errored = true;
                    }
                } else if requests.inputs.default_address_query && e.is_no_records_found() {
                    empty_family.entry(family_key).or_insert(e);
                } else {
                    hard_errors.insert(family_key);
                    format.print_error(&e);
                    errored = true;
                }
            }
        }
    }

    if requests.inputs.default_address_query {
        let mut missed: Vec<_> = empty_family.into_iter().collect();
        missed.sort_by_key(|((domain, qclass), _)| (domain.clone(), *qclass));
        for (family_key, error) in missed {
            if answered.contains(&family_key) || hard_errors.contains(&family_key) {
                continue;
            }
            format.print_error(&error);
            errored = true;
        }
    }

    if verbose {
        let duration = timer.map(|t| t.elapsed());
        if let Some(duration) = duration {
            let duration_ms = duration.as_secs_f64() * 1000.0;
            stdout::emit_line(&format!("Ran in {duration_ms:.2}ms"));
        }

        if errored {
            exits::NETWORK_ERROR
        } else {
            exits::SUCCESS
        }
    } else {
        let duration = timer.map(|t| t.elapsed());
        if format.print_with_edns(responses, duration, show_edns) {
            if errored {
                exits::NETWORK_ERROR
            } else {
                exits::SUCCESS
            }
        } else {
            exits::NO_SHORT_RESULTS
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

#[cfg(test)]
mod test {
    use super::*;
    use hickory_resolver::config::ProtocolConfig;

    #[test]
    fn parse_nameserver_variants() {
        assert_eq!(
            parse_nameserver_target("8.8.8.8"),
            Ok(("8.8.8.8".to_string(), None))
        );
        assert_eq!(
            parse_nameserver_target("127.0.0.1:5353"),
            Ok(("127.0.0.1".to_string(), Some(5353)))
        );
        assert_eq!(
            parse_nameserver_target("2001:4860:4860::8888"),
            Ok(("2001:4860:4860::8888".to_string(), None))
        );
        assert_eq!(
            parse_nameserver_target("[2001:4860:4860::8888]"),
            Ok(("2001:4860:4860::8888".to_string(), None))
        );
        assert_eq!(
            parse_nameserver_target("[::1]:5353"),
            Ok(("::1".to_string(), Some(5353)))
        );
        assert_eq!(
            parse_nameserver_target("dns.google"),
            Ok(("dns.google".to_string(), None))
        );
        assert_eq!(
            parse_nameserver_target("dns.google:853"),
            Ok(("dns.google".to_string(), Some(853)))
        );
        assert!(parse_nameserver_target("127.0.0.1:0").is_err());
        assert!(parse_nameserver_target("dns.google:99999").is_err());
        assert!(parse_nameserver_target("[::1:5353").is_err());
    }

    #[test]
    fn tls_server_name_mapping() {
        assert_eq!(
            default_tls_server_name("8.8.8.8".parse().unwrap()),
            "dns.google"
        );
        assert_eq!(
            default_tls_server_name("2001:4860:4860:0:0:0:0:8844".parse().unwrap()),
            "dns.google"
        );
        assert_eq!(
            default_tls_server_name("1.1.1.1".parse().unwrap()),
            "cloudflare-dns.com"
        );
        assert_eq!(
            default_tls_server_name("9.9.9.9".parse().unwrap()),
            "dns.quad9.net"
        );
        assert_eq!(
            default_tls_server_name("2620:fe::fe".parse().unwrap()),
            "dns.quad9.net"
        );
        assert_eq!(
            default_tls_server_name("192.0.2.1".parse().unwrap()),
            "192.0.2.1"
        );
    }

    #[test]
    fn default_transport_includes_udp_and_tcp_fallback() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let default_conns = build_connections(None, None, ip, Some(5353));
        assert_eq!(default_conns.len(), 2);
        assert_eq!(default_conns[0].protocol, ProtocolConfig::Udp);
        assert_eq!(default_conns[0].port, 5353);
        assert_eq!(default_conns[1].protocol, ProtocolConfig::Tcp);
        assert_eq!(default_conns[1].port, 5353);

        let udp_only = build_connections(Some(TransportType::UDP), None, ip, None);
        assert_eq!(udp_only.len(), 1);
        assert_eq!(udp_only[0].protocol, ProtocolConfig::Udp);
        assert_eq!(udp_only[0].port, 53);

        let tcp_only = build_connections(Some(TransportType::TCP), None, ip, None);
        assert_eq!(tcp_only.len(), 1);
        assert_eq!(tcp_only[0].protocol, ProtocolConfig::Tcp);
        assert_eq!(tcp_only[0].port, 53);
    }
}
