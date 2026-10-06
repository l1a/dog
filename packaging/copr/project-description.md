**dog** is a command-line DNS client, like `dig` but friendlier.

- **Simple arguments**: `dog example.com MX @1.1.1.1`, in any order, and `dog 1.1.1.1` for a reverse lookup.
- **Encrypted DNS built in**: UDP, TCP, **TLS** (`-S`) and **HTTPS** (`-H`), on rustls, so no OpenSSL.
- **Readable output**: colour on a terminal, and TTLs shown as `1m09s` rather than a raw number of seconds.
- **Made for scripts**: `--json`, `-1` for just the answer data, and documented exit statuses.
- **35 record types**, including `HTTPS`, `SVCB`, `TLSA`, `SSHFP`, `CAA` and the DNSSEC types.
- A man page and shell completions for bash, zsh and fish.

This is the maintained `l1a/dog` fork of `ogham/dog`, built on `hickory-resolver`. Source, documentation and issues: https://github.com/l1a/dog
