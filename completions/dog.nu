# Nu shell completions for dog

# Query options completers
def "nu-complete dog types" [] {
  [
    "A"
    "AAAA"
    "ANAME"
    "ANY"
    "AXFR"
    "CAA"
    "CNAME"
    "DNSKEY"
    "DS"
    "HINFO"
    "HTTPS"
    "IXFR"
    "MX"
    "NAPTR"
    "NS"
    "NULL"
    "OPENPGPKEY"
    "OPT"
    "PTR"
    "SOA"
    "SRV"
    "SSHFP"
    "SVCB"
    "TLSA"
    "TXT"
    "RRSIG"
    "NSEC"
    "NSEC3"
    "NSEC3PARAM"
    "TSIG"
  ] | str upcase
}

def "nu-complete dog classes" [] {
  [
    "IN"
    "CH"
    "HS"
  ] | str upcase
}

def "nu-complete dog edns" [] {
  [
    "disable"
    "hide"
    "show"
  ]
}

def "nu-complete dog tweaks" [] {
  [
    "aa"
    "ad"
    "bufsize="
    "cd"
  ]
}

def "nu-complete dog colors" [] {
  [
    "always"
    "automatic"
    "never"
  ]
}

# Define the external command with completions
extern "dog" [
  --query(-q): string  # Host name or domain name to query
  --type(-t): string@"nu-complete dog types"  # Type of the DNS record being queried
  --nameserver(-n): string  # Address of the nameserver to send packets to
  --class: string@"nu-complete dog classes"  # Network class of the DNS record being queried
  --edns: string@"nu-complete dog edns"  # Whether to OPT in to EDNS
  --txid: string  # Set the transaction ID to a specific value
  -Z: string@"nu-complete dog tweaks"  # Set uncommon protocol tweaks
  --color: string@"nu-complete dog colors"  # When to use terminal colors
  --colour: string@"nu-complete dog colors"  # When to use terminal colours
  --udp(-U)  # Use the DNS protocol over UDP
  --tcp(-T)  # Use the DNS protocol over TCP
  --tls(-S)  # Use the DNS-over-TLS protocol
  --https(-H)  # Use the DNS-over-HTTPS protocol
  --short(-1)  # Short mode: display nothing but the first result
  --json(-J)  # Display the output as JSON
  --seconds  # Do not format durations, display them as seconds
  --version(-V)  # Print version information
  --help(-?)  # Print list of command-line options
  --list(-l)  # List known DNS record types
  --verbose(-v)  # Print verbose information
  ...domain: string  # The domain to query
]
