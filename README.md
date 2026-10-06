<div align="center">
<h1>dog</h1>

**dog** is a command-line DNS client.

*This is the maintained fork of [ogham/dog](https://github.com/ogham/dog), which is no longer maintained. It is built on [`hickory-resolver`](https://github.com/hickory-dns/hickory-dns).*

</div>

![A screenshot of dog making a DNS request](dog-screenshot.png)

---

Dogs _can_ look up!

**dog** is a command-line DNS client, like `dig`.
It has colourful output, understands normal command-line argument syntax, supports the DNS-over-TLS and DNS-over-HTTPS protocols, and can emit JSON.

## Examples

    dog example.net                          Query a domain using default settings
    dog example.net MX                       ...looking up MX records instead
    dog example.net MX @1.1.1.1              ...using a specific nameserver instead
    dog example.net MX @1.1.1.1 -T           ...using TCP rather than UDP
    dog -q example.net -t MX -n 1.1.1.1 -T   As above, but using explicit arguments

---

## Command-line options

### Query options

    -q, --query <HOST>       Host name or domain name to query
    -t, --type <TYPE>        Type of the DNS record being queried [possible values: A, AAAA, ANAME, ANY, AXFR, CAA, CNAME, DNSKEY, DS, HINFO, HTTPS, IXFR, MX, NAPTR, NS, NULL, OPENPGPKEY, OPT, PTR, SOA, SRV, SSHFP, SVCB, TLSA, TXT, RRSIG, NSEC, NSEC3, NSEC3PARAM, TSIG, CDS, CDNSKEY, CSYNC, KEY, SIG]
    -n, --nameserver <ADDR>  Address of the nameserver to send packets to
        --class <CLASS>      Network class of the DNS record being queried (IN, CH, HS)

### Sending options

        --edns <SETTING>     Whether to OPT in to EDNS (disable, hide, show)
        --txid <NUMBER>      Set the transaction ID to a specific value
    -Z <TWEAKS>              Set uncommon protocol tweaks

### Protocol options

    -U, --udp                Use the DNS protocol over UDP
    -T, --tcp                Use the DNS protocol over TCP
    -S, --tls                Use the DNS-over-TLS protocol
    -H, --https              Use the DNS-over-HTTPS protocol

### Output options

        --color <WHEN>       When to use terminal colors
        --colour <WHEN>      When to use terminal colours
    -J, --json               Display the output as JSON
        --seconds            Do not format durations, display them as seconds
    -1, --short              Short mode: display nothing but the first result

### Meta options

    -V, --version            Print version information
    -?, --help               Print list of command-line options
    -l, --list               List known DNS record types
    -v, --verbose            Print verbose information
        --completions <SHELL> Generate shell completions

### Shortcuts

    Instead of using the -q, -t, and -n flags, you can provide the arguments directly:
    dog lookup.dog             Query a domain
    dog lookup.dog MX          Query a domain for a specific type
    dog lookup.dog @8.8.8.8    Query a domain using a specific nameserver
    dog 1.1.1.1                Perform a reverse lookup for an IP address


---

## Record Types

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

`mutt`, `tail`, `sleep`, `roff`


## Licence

dog’s source code is licensed under the [GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/).
*(Original upstream code by Benjamin Sago licensed under EUPL-1.2).*

<!-- fast-path test: this PR is closed unmerged -->
