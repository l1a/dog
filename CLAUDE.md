# Dog - DNS client

A command-line DNS client (like dig, but more user-friendly).

## Build

The default build may require `libssl-dev` depending on the platform due to the use of TLS for DNS-over-TLS/HTTPS. Use the vendored feature to statically link if needed (if configured in `Cargo.toml`).

```sh
cargo build --release
```

## Project structure

The `l1a/dog` fork relies heavily on the [`hickory-resolver`](https://github.com/hickory-dns/hickory-dns) crate for all DNS parsing and networking. 

- `src/` - CLI binary source code
  - `main.rs` - Application entry point and `hickory-resolver` orchestration
  - `options.rs` - Command-line argument parsing
  - `output.rs` - Formatting DNS responses (JSON and Text)
  - `table.rs` - Pretty-printing tables for terminal output

## Testing

```sh
cargo test
```

The test suite covers:
- CLI argument parsing (`src/options.rs`)

*Note: The original `dog` integration test suite (`xtests/`) and `dns/` wire format parsing tests are no longer applicable as parsing is entirely delegated to `hickory-resolver`.*

## Known issues

- TLS configurations may require appropriate system libraries or cross-compilation toolchains depending on the target OS.
