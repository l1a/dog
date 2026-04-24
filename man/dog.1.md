% dog(1) 0.5.5

<!-- This is the dog(1) man page, written in Markdown. -->
<!-- To generate the roff version, run `just man`, -->
<!-- and the man page will appear in the ‘target’ directory. -->


NAME
====

dog — a command-line DNS client


SYNOPSIS
========

`dog [OPTIONS] [--] <arguments>`

**dog** is a command-line DNS client.
It has colourful output, supports the DNS-over-TLS and DNS-over-HTTPS protocols, and can emit JSON.


EXAMPLES
========

`dog example.net`
: Query the `A` record of a domain using default settings

`dog example.net MX`
: ...looking up `MX` records instead

`dog example.net MX @1.1.1.1`
: ...using a specific nameserver instead

`dog example.net MX @1.1.1.1 -T`
: ...using TCP rather than UDP

`dog -q example.net -t MX -n 1.1.1.1 -T`
: As above, but using explicit arguments


QUERY OPTIONS
=============

`-q`, `--query <HOST>`
: Host name or domain name to query.

`-t`, `--type <TYPE>`
: Type of the DNS record being queried.

`-n`, `--nameserver <ADDR>`
: Address of the nameserver to send packets to.

`--class <CLASS>`
: Network class of the DNS record being queried (`IN`, `CH`, `HS`)

By default, dog will request A records using the system default resolver. At least one domain name must be passed — dog will not automatically query the root nameservers.

Query options passed in using a command-line option, such as ‘`--query lookup.dog`’ or ‘`--type MX`’, or as plain arguments, such as ‘`lookup.dog`’ or ‘`MX`’. dog will make an intelligent guess as to what plain arguments mean (`MX` is quite clearly a type), which makes it easier to compose ad-hoc queries quickly. If precision is desired, use the long-form options.

If more than one domain, type, nameserver, or class is specified, dog will perform one query for each combination, and display the combined results in a table. For example, passing three type arguments and two domain name arguments will send six requests.

DNS traditionally uses port 53 for both TCP and UDP. To use a resolver with a different port, include the port number after a colon (`:`) in the nameserver address.


SENDING OPTIONS
===============

`--edns <SETTING>`
: Whether to OPT in to EDNS (disable, hide, show).

`--txid <NUMBER>`
: Set the transaction ID to a specific value.

`-Z <TWEAKS>`
: Set uncommon protocol tweaks.


PROTOCOL OPTIONS
================

`-U`, `--udp`
: Use the DNS protocol over UDP.

`-T`, `--tcp`
: Use the DNS protocol over TCP.

`-S`, `--tls`
: Use the DNS-over-TLS protocol.

`-H`, `--https`
: Use the DNS-over-HTTPS protocol.

By default, dog will use the UDP protocol, automatically re-sending the request using TCP if the response indicates that the message is too large for UDP. Passing `--udp` will only use UDP and will fail in this case; passing `--tcp` will use TCP by default.

The DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH) protocols are available with the `--tls` and `--https` options. Bear in mind that the system default resolver is unlikely to respond to requests using these protocols.

Note that if a hostname or domain name is given as a nameserver, rather than an IP address, the resolution of that host is performed by the operating system, _not_ by dog.

Unlike the others, the HTTPS transport type requires an entire URL, complete with protocol, domain name, and path.


OUTPUT OPTIONS
==============

`-1`, `--short`
: Short mode: display nothing but the first result.

`-J`, `--json`
: Display the output as JSON.

`--color`, `--colour <WHEN>`
: When to colourise the output. This can be ‘`always`’ or ‘`automatic`’, or ‘`never`’.

`--seconds`
: Do not format durations as hours and minutes; instead, display them as seconds.


META OPTIONS
============

`-V`, `--version`
: Displays the version of dog being invoked.

`-?`, `--help`
: Displays an overview of the command-line options.

`-l`, `--list`
: List known DNS record types.

`-v`, `--verbose`
: Print verbose information.

`--completions <SHELL>`
: Generate shell completions.


SHORTCUTS
=========

Instead of using the `-q`, `-t`, and `-n` flags, you can provide the arguments directly:

`dog lookup.dog`
: Query a domain

`dog lookup.dog MX`
: Query a domain for a specific type

`dog lookup.dog @8.8.8.8`
: Query a domain using a specific nameserver

`dog 1.1.1.1`
: Perform a reverse lookup for an IP address


RECORD TYPES
============

dog supports the following record types: `A`, `AAAA`, `ANAME`, `ANY`, `AXFR`, `CAA`, `CDNSKEY`, `CDS`, `CNAME`, `CSYNC`, `DNSKEY`, `DS`, `HINFO`, `HTTPS`, `IXFR`, `KEY`, `MX`, `NAPTR`, `NS`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `NULL`, `OPENPGPKEY`, `OPT`, `PTR`, `RRSIG`, `SIG`, `SOA`, `SRV`, `SSHFP`, `SVCB`, `TLSA`, `TSIG`, `TXT`.


ENVIRONMENT VARIABLES
=====================

dog responds to the following environment variables:

## `DOG_DEBUG`

Set this to any non-empty value to have dog emit debugging information to standard error. For more in-depth output, set this to the exact string ‘`trace`’.


EXIT STATUSES
=============

0
: If everything goes OK.

1
: If there was a network, I/O, or TLS error during operation.

2
: If there is no result from the server when running in short mode. This can be any received server error, not just NXDOMAIN.

3
: If there was a problem with the command-line arguments.


AUTHOR
======

dog was originally created by Benjamin ‘ogham’ Sago. This version is a fork maintained by l1a.

**Source code:** `https://github.com/l1a/dog` \
**Upstream:** `https://github.com/ogham/dog`
