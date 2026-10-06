<div align="center">
<h1>dog</h1>

**dog** is a command-line DNS client, like `dig` but friendlier.

*This is the maintained fork of [ogham/dog](https://github.com/ogham/dog), which is no longer maintained. It is built on [`hickory-resolver`](https://github.com/hickory-dns/hickory-dns).*

</div>

![A screenshot of dog making a DNS request](dog-screenshot.png)

---

dog takes its arguments the way you would say them: the name, the record type and the nameserver, in any order. It prints colourful, readable answers, speaks encrypted DNS, and gives scripts a JSON format and documented exit statuses.

```sh
dog example.com               # A records, from your system's nameserver
dog example.com MX            # a different record type
dog example.com MX @1.1.1.1   # ask a specific nameserver
dog 1.1.1.1                   # reverse lookup (PTR)
dog -S example.com @1.1.1.1   # DNS-over-TLS
dog -H example.com @1.1.1.1   # DNS-over-HTTPS
dog --json example.com TXT    # JSON, for scripts
dog -1 example.com            # short: just the answer data
```

```text
$ dog example.com @1.1.1.1
A example.com. 34s   104.20.23.154
A example.com. 34s   172.66.147.243

$ dog 1.1.1.1
PTR 1.1.1.1.in-addr.arpa. 9m50s   one.one.one.one.
```

## Features

- **Simple arguments.** `dog example.com MX @1.1.1.1`, in any order. Pass an IP address for a reverse lookup. The flags (`-q`, `-t`, `-n`) are there when you want to be explicit.
- **Encrypted DNS built in.** DNS over UDP, TCP, **TLS** (`-S`) and **HTTPS** (`-H`). The TLS stack is [`rustls`](https://github.com/rustls/rustls), so there is no OpenSSL to install or to link against.
- **Readable output.** Colour when writing to a terminal (`--color always|automatic|never`), and TTLs shown as `1m09s` rather than a raw number of seconds (`--seconds` for the raw number).
- **Made for scripts.** `--json` for a JSON document, `-1` for just the answer data, and [documented exit statuses](#using-dog-in-scripts).
- **35 record types**, including `HTTPS`, `SVCB`, `TLSA`, `SSHFP`, `CAA` and the DNSSEC types. `dog --list` prints each one with an example.
- **Shell completions** for bash, zsh, fish, PowerShell, elvish and nushell (`dog --completions <shell>`), and a man page.
- **Runs on Linux, macOS and Windows**, as a single binary.

## Using dog in scripts

`--json` prints one JSON document with the answers as strings, which `jq` can take apart:

```sh
$ dog --json example.com A @1.1.1.1
{"responses":[{"answers":["example.com. 218 IN A 172.66.147.243","example.com. 218 IN A 104.20.23.154"]}]}

$ dog --json example.com A @1.1.1.1 | jq -r '.responses[].answers[]'
example.com. 218 IN A 172.66.147.243
example.com. 218 IN A 104.20.23.154
```

`-1` (`--short`) prints only the data of each answer, one per line, and makes the exit status say whether there was an answer:

```sh
if dog -1 example.com @1.1.1.1 > /dev/null; then echo "resolves"; fi
```

| Exit status | Meaning |
|---|---|
| `0` | Everything went well. |
| `1` | A network, I/O or TLS error. |
| `2` | No result from the server **in short mode**. This is any server error, not only `NXDOMAIN`. |
| `3` | A problem with the command-line arguments. |

Set `DOG_DEBUG` to any non-empty value for debugging output on standard error, or to `trace` for more.

## Command-line options

`dog --help` lists everything, and `man dog` explains it. At a glance:

| Group | Options |
|---|---|
| **Query** | `-q`/`--query <HOST>`, `-t`/`--type <TYPE>`, `-n`/`--nameserver <ADDR>`, `--class <CLASS>` (`IN`, `CH`, `HS`) |
| **Protocol** | `-U`/`--udp`, `-T`/`--tcp`, `-S`/`--tls`, `-H`/`--https` |
| **Output** | `-J`/`--json`, `-1`/`--short`, `--color <WHEN>`, `--seconds` |
| **Sending** | `--edns <disable\|hide\|show>`, `--txid <NUMBER>`, `-Z <TWEAKS>` |
| **Meta** | `-V`/`--version`, `-?`/`--help`, `-l`/`--list`, `-v`/`--verbose`, `--completions <SHELL>` |

### Record types

dog supports the following record types: `A`, `AAAA`, `ANAME`, `ANY`, `AXFR`, `CAA`, `CDNSKEY`, `CDS`, `CNAME`, `CSYNC`, `DNSKEY`, `DS`, `HINFO`, `HTTPS`, `IXFR`, `KEY`, `MX`, `NAPTR`, `NS`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `NULL`, `OPENPGPKEY`, `OPT`, `PTR`, `RRSIG`, `SIG`, `SOA`, `SRV`, `SSHFP`, `SVCB`, `TLSA`, `TSIG`, `TXT`.

---

## Installation

You can install a package, download a pre-compiled binary, or compile dog from source. The installed command is always `dog`.

The package names differ because `dog` was already taken on some of these services. The package is `dogdns` on crates.io and the AUR, and `dog` on COPR and Homebrew.

### Packages

Packages are published with each release.

- **Fedora** ([COPR](https://copr.fedorainfracloud.org/coprs/kentobias/dog/), Fedora 43 and 44, x86_64 and aarch64):

      $ sudo dnf copr enable kentobias/dog
      $ sudo dnf install dog

- **Arch Linux** ([AUR](https://aur.archlinux.org/packages/dogdns)), using your AUR helper of choice:

      $ yay -S dogdns

  It conflicts with the official `dog` package, which ships the same `/usr/bin/dog`. That package is the unmaintained upstream tool.

- **Homebrew** (macOS and Linux), from this project's tap:

      $ brew install l1a/dog/dog

- **crates.io**, built from source (this installs the `dog` binary):

      $ cargo install dogdns

  The crate is `dogdns`. Do not run `cargo install dog`: that is an unrelated crate.


### Downloads

Binary downloads of dog are available from [the releases section on GitHub](https://github.com/l1a/dog/releases/) for Linux, macOS and Windows, on x86_64 and ARM64 (older releases have x86_64 only). Each archive contains the executable, the manual page, shell completions, and the licence, and every release has a `SHA256SUMS` file.


### Compilation

dog is written in [Rust](https://www.rust-lang.org).
You will need a recent stable Rust toolchain. The recommended way to install Rust for development is from the [official download page](https://www.rust-lang.org/tools/install), using rustup.

To build, download the source code and run:

    $ cargo build
    $ cargo test

- If you are compiling a copy for yourself, be sure to run `cargo build --release` to benefit from release-mode optimisations.
Copy the resulting binary, which will be in the `target/release` directory, into a folder in your `$PATH`.
`/usr/local/bin` is usually a good choice.

- To compile and install the manual pages, you will need [pandoc](https://pandoc.org/).
The `just man` command will compile the Markdown into manual pages, which it will place in the `target/man` directory.
To use them, copy them into a directory that `man` will read.
`/usr/local/share/man` is usually a good choice.

- Shell completions are generated by the binary itself: run `dog --completions <shell>` for `bash`, `zsh`, `fish`, `powershell`, `elvish` or `nushell`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the checks the project runs (`just`).


---

## See also

[`dig`](https://linux.die.net/man/1/dig), `host` and `nslookup` (the classic resolvers), [`kdig`](https://www.knot-dns.cz/docs/latest/html/man_kdig.html) and [`drill`](https://nlnetlabs.nl/projects/ldns/about/), and `resolvectl` (systemd-resolved). dog's `--json` output pairs well with [`jq`](https://jqlang.github.io/jq/).


## Licence

dog’s source code is licensed under the [GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/).
*(Original upstream code by Benjamin Sago licensed under EUPL-1.2).*
