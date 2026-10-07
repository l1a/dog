#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Smoke test: a built `dog` can send a real DNS query and parse and print the answer.
#
#   scripts/smoke_dns.sh                       # builds nothing; runs `cargo run --quiet --locked --`
#   DOG=target/debug/dog scripts/smoke_dns.sh  # or any other binary
#
# The unit tests are offline, so nothing else proves the resolver, the sockets and the output code
# work together on each OS and architecture CI covers. This asks a public resolver for google.com
# in three output modes and checks the SHAPE of the answers, not their content: addresses, TTLs and
# TXT strings change from one run to the next.
#
#   SMOKE_SERVER    resolver to ask            (default 8.8.8.8)
#   SMOKE_NAME      name to look up            (default google.com)
#   SMOKE_ATTEMPTS  tries before giving up     (default 3; a query times out after 15 s)
#
# (The checks use here-strings, not `echo | grep -q`: under `pipefail`, grep exiting at the first match can
# SIGPIPE the echo and report a failure that is not one.)
#
# A transient network failure is retried, a persistent one fails the job: a smoke test that cannot
# fail proves nothing. The overrides exist so the test of THIS script can make it fail on purpose.

set -euo pipefail

server=${SMOKE_SERVER:-8.8.8.8}
name=${SMOKE_NAME:-google.com}
attempts=${SMOKE_ATTEMPTS:-3}

if [ -n "${DOG:-}" ]; then dog=("$DOG"); else dog=(cargo run --quiet --locked --); fi

fail() { echo "smoke test FAILED: $*" >&2; exit 1; }

# retry <description> <command...>: run a command up to $attempts times, stopping at the first success.
retry() {
    local what=$1 try=1; shift
    until "$@"; do
        if [ "$try" -ge "$attempts" ]; then fail "$what, after $attempts attempt(s)"; fi
        echo "  attempt $try of $attempts failed ($what); retrying" >&2
        try=$((try + 1)); sleep 3
    done
}

# 1. Text output, every record type dog fans ANY out to. A name that has records has an NS or an SOA.
text_any() {
    local out
    out=$("${dog[@]}" --color never "$name" ANY "@$server") || return 1
    head -n 5 <<<"$out"
    grep -Eq "^(NS|SOA|A|AAAA|MX) +${name//./\\.}\\. " <<<"$out"
}

# 2. JSON output: valid shape, and at least one answer in it.
json_a() {
    local out
    out=$("${dog[@]}" --json "$name" A "@$server") || return 1
    echo "$out"
    grep -Eq '"answers":\["[^"]+' <<<"$out"
}

# 3. Short output: the data of each answer, one per line. NS data is a host name ending in a dot.
short_ns() {
    local out
    out=$("${dog[@]}" --short "$name" NS "@$server") || return 1
    head -n 3 <<<"$out"
    grep -Eq '^[A-Za-z0-9.-]+\.$' <<<"$out"
}

echo "dog DNS smoke test: $name via $server"
retry "text output of ANY had no record for $name" text_any
retry "JSON output of A had no answer" json_a
retry "short output of NS had no host name" short_ns
echo "smoke test passed"
