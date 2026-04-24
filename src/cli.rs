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

use clap::{Arg, ArgAction, Command};

pub fn build_cli() -> Command {
    Command::new("dog")
        .no_binary_name(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .override_usage("dog [OPTIONS] [--] <arguments>")
        .after_help(
            "Shortcuts:
  Instead of using the -q, -t, and -n flags, you can provide the arguments directly:
  dog lookup.dog             Query a domain
  dog lookup.dog MX          Query a domain for a specific type
  dog lookup.dog @8.8.8.8    Query a domain using a specific nameserver
  dog 1.1.1.1                Perform a reverse lookup for an IP address",
        )
        .arg(Arg::new("free").action(ArgAction::Append).hide(true))
        .next_help_heading("Query options")
        .arg(
            Arg::new("query")
                .short('q')
                .long("query")
                .help("Host name or domain name to query")
                .value_name("HOST")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("type")
                .short('t')
                .long("type")
                .help("Type of the DNS record being queried")
                .value_name("TYPE")
                .action(ArgAction::Append)
                .ignore_case(true)
                .value_parser([
                    "A",
                    "AAAA",
                    "ANAME",
                    "ANY",
                    "AXFR",
                    "CAA",
                    "CNAME",
                    "DNSKEY",
                    "DS",
                    "HINFO",
                    "HTTPS",
                    "IXFR",
                    "MX",
                    "NAPTR",
                    "NS",
                    "NULL",
                    "OPENPGPKEY",
                    "OPT",
                    "PTR",
                    "SOA",
                    "SRV",
                    "SSHFP",
                    "SVCB",
                    "TLSA",
                    "TXT",
                    "RRSIG",
                    "NSEC",
                    "NSEC3",
                    "NSEC3PARAM",
                    "TSIG",
                    "CDS",
                    "CDNSKEY",
                    "CSYNC",
                    "KEY",
                    "SIG",
                ]),
        )
        .arg(
            Arg::new("nameserver")
                .short('n')
                .long("nameserver")
                .help("Address of the nameserver to send packets to")
                .value_name("ADDR")
                .action(ArgAction::Append),
        )
        .arg(
            Arg::new("class")
                .long("class")
                .help("Network class of the DNS record being queried (IN, CH, HS)")
                .value_name("CLASS")
                .action(ArgAction::Append),
        )
        .next_help_heading("Sending options")
        .arg(
            Arg::new("edns")
                .long("edns")
                .help("Whether to OPT in to EDNS (disable, hide, show)")
                .value_name("SETTING")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("txid")
                .long("txid")
                .help("Set the transaction ID to a specific value")
                .value_name("NUMBER")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("Z")
                .short('Z')
                .help("Set uncommon protocol tweaks")
                .value_name("TWEAKS")
                .action(ArgAction::Append),
        )
        .next_help_heading("Protocol options")
        .arg(
            Arg::new("udp")
                .short('U')
                .long("udp")
                .help("Use the DNS protocol over UDP")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("tcp")
                .short('T')
                .long("tcp")
                .help("Use the DNS protocol over TCP")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("tls")
                .short('S')
                .long("tls")
                .help("Use the DNS-over-TLS protocol")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("https")
                .short('H')
                .long("https")
                .help("Use the DNS-over-HTTPS protocol")
                .action(ArgAction::SetTrue),
        )
        .next_help_heading("Output options")
        .arg(
            Arg::new("color")
                .long("color")
                .help("When to use terminal colors")
                .value_name("WHEN")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("colour")
                .long("colour")
                .help("When to use terminal colours")
                .value_name("WHEN")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("json")
                .short('J')
                .long("json")
                .help("Display the output as JSON")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("seconds")
                .long("seconds")
                .help("Do not format durations, display them as seconds")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("short")
                .short('1')
                .long("short")
                .help("Short mode: display nothing but the first result")
                .action(ArgAction::SetTrue),
        )
        .next_help_heading("Meta options")
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .help("Print version information")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("help")
                .short('?')
                .long("help")
                .help("Print list of command-line options")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("list")
                .short('l')
                .long("list")
                .help("List known DNS record types")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Print verbose information")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("completions")
                .long("completions")
                .help("Generate shell completions")
                .value_name("SHELL")
                .action(ArgAction::Set),
        )
}
