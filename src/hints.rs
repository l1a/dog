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

//! Hints to the user made before a query is sent, in case the answer that
//! comes back isn’t what they expect.

use std::collections::BTreeSet;
use std::fs::File;
use std::io;

use log::*;

/// The set of hostnames that are configured to point to a specific host in
/// the hosts file on the local machine. This gets queried before a request is
/// made: because the running OS will consult the hosts file before looking up
/// a hostname, but dog will not, it’s possible for dog to output one address
/// while the OS is using another. dog displays a warning when this is the
/// case, to prevent confusion.
#[derive(Default)]
pub struct LocalHosts {
    hostnames: BTreeSet<String>,
}

/// Maximum bytes read from the system hosts file (16 MiB).
const MAX_HOSTS_FILE_BYTES: u64 = 16 * 1024 * 1024;

impl LocalHosts {
    /// Loads the set of hostnames from the hosts file path on Unix.
    #[cfg(unix)]
    pub fn load() -> io::Result<Self> {
        debug!("Reading hints from /etc/hosts");
        Self::load_from_file(File::open("/etc/hosts")?)
    }

    /// Loads the set of hostnames from the hosts file path on Windows.
    #[cfg(windows)]
    pub fn load() -> io::Result<Self> {
        use std::env;
        use std::path::PathBuf;

        debug!("Reading hints from /etc/hosts equivalent");
        let root =
            env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
        let path = root.join(r"System32\drivers\etc\hosts");
        Self::load_from_file(File::open(path)?)
    }

    /// On other machines, load an empty set of hostnames that match nothing.
    #[cfg(all(not(windows), not(unix)))]
    pub fn load() -> io::Result<Self> {
        Ok(Self::default())
    }

    /// Reads hostnames from the given file and returns them as a `LocalHosts`
    /// struct, or an I/O error if one occurs. The file should be in the
    /// standard `/etc/hosts` format, with one entry per line, separated by
    /// whitespace, where the first field is the address and the remaining
    /// fields are hostname aliases, and `#` signifies a comment.
    fn load_from_file(file: File) -> io::Result<Self> {
        use std::io::{BufReader, Read};

        let reader = BufReader::new(file.take(MAX_HOSTS_FILE_BYTES));
        Self::load_from_reader(reader)
    }

    /// Reads hostnames from any buffered reader.
    fn load_from_reader<R: io::BufRead>(reader: R) -> io::Result<Self> {
        let mut hostnames = BTreeSet::new();
        for line in reader.lines() {
            let mut line = line?;

            if let Some(hash_index) = line.find('#') {
                line.truncate(hash_index);
            }

            for hostname in line.split_ascii_whitespace().skip(1) {
                let normalized = normalize_hostname(hostname);
                if !normalized.is_empty() {
                    hostnames.insert(normalized);
                }
            }
        }

        trace!("{} hostname hints loaded OK.", hostnames.len());
        Ok(Self { hostnames })
    }

    /// Queries this set of hostnames to see if the given name, which is about
    /// to be queried for, exists within the file.
    pub fn contains(&self, hostname_in_query: &str) -> bool {
        self.hostnames
            .contains(&normalize_hostname(hostname_in_query))
    }
}

fn normalize_hostname(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_hosts_and_strips_comments() {
        let sample = "\
# comment line
127.0.0.1   localhost localhost.localdomain # inline comment
::1         ip6-localhost ip6-loopback
10.0.0.5    Internal.Dev.Local.  alias-host
";
        let hosts = LocalHosts::load_from_reader(Cursor::new(sample)).unwrap();
        assert!(hosts.contains("localhost"));
        assert!(hosts.contains("LOCALHOST."));
        assert!(hosts.contains("internal.dev.local"));
        assert!(hosts.contains("alias-host"));
        assert!(!hosts.contains("127.0.0.1"));
        assert!(!hosts.contains("inline"));
        assert!(!hosts.contains("nonexistent.local"));
    }
}
