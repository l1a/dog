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

//! Text and JSON output.

use std::env;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::time::Duration;

use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::NetError as ResolveError;
use json::object;

use crate::colours::Colours;
use crate::table::{Section, Table};

/// How to format the output data.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum OutputFormat {
    /// Format the output as plain text, optionally adding ANSI colours.
    Text(UseColours, TextFormat),

    /// Format the output as one line of plain text.
    Short(TextFormat),

    /// Format the entries as JSON.
    JSON,
}

/// When to use colours in the output.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum UseColours {
    /// Always use colours.
    Always,

    /// Use colours if output is to a terminal; otherwise, do not.
    Automatic,

    /// Never use colours.
    Never,
}

/// Options that govern how text should be rendered in record summaries.
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct TextFormat {
    /// Whether to format TTLs as hours, minutes, and seconds.
    pub format_durations: bool,
}

impl UseColours {
    /// Whether we should use colours or not. This checks whether the user has
    /// overridden the colour setting, and if not, whether output is to a
    /// terminal.
    pub fn should_use_colours(self) -> bool {
        self == Self::Always
            || (io::stdout().is_terminal() && env::var("NO_COLOR").is_err() && self != Self::Never)
    }

    /// Creates a palette of colours depending on the user’s wishes or whether
    /// output is to a terminal.
    pub fn palette(self) -> Colours {
        if self.should_use_colours() {
            Colours::pretty()
        } else {
            Colours::plain()
        }
    }
}

impl OutputFormat {
    /// Prints the entirety of the output, formatted according to the
    /// settings. If the duration has been measured, it should also be
    /// printed. Returns `false` if there were no results to print, and `true`
    /// otherwise.
    pub fn print(self, responses: Vec<Lookup>, duration: Option<Duration>) -> bool {
        match self {
            Self::Short(_) => {
                let all_answers = responses
                    .into_iter()
                    .flat_map(|r| r.answers().to_vec())
                    .collect::<Vec<_>>();

                if all_answers.is_empty() {
                    eprintln!("No results");
                    return false;
                }

                for answer in all_answers {
                    println!("{}", TextFormat::record_payload_summary(&answer.data));
                }
            }
            Self::JSON => {
                let answers = responses
                    .iter()
                    .map(|response| {
                        response
                            .answers()
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                println!("{}", render_json(&answers, duration));
            }
            Self::Text(uc, tf) => {
                let total_records = responses
                    .iter()
                    .flat_map(hickory_resolver::lookup::Lookup::answers)
                    .count();
                if total_records > 100 {
                    let stdout = io::stdout();
                    let mut writer = BufWriter::new(stdout);
                    for response in responses {
                        let mut table = Table::new(uc.palette(), tf);
                        for a in response.answers() {
                            table.add_row(a, Section::Answer);
                        }
                        write!(&mut writer, "{}", table.render()).unwrap();
                    }
                    writer.flush().unwrap();
                } else {
                    for response in responses {
                        let mut table = Table::new(uc.palette(), tf);
                        for a in response.answers() {
                            table.add_row(a, Section::Answer);
                        }
                        print!("{}", table.render());
                    }
                }

                if let Some(duration) = duration {
                    println!("Ran in {}ms", duration.as_millis());
                }
            }
        }

        true
    }

    /// Print an error that’s ocurred while sending or receiving DNS packets
    /// to standard error.
    pub fn print_error(self, error: &ResolveError) {
        match self {
            Self::Short(..) | Self::Text(..) => {
                eprintln!("Error: {error}");
            }

            Self::JSON => {
                eprintln!("{}", render_error_json(&error.to_string()));
            }
        }
    }
}

/// Renders the `--json` output for a set of responses: each inner list is
/// the answers of one response, as text. The duration is included only if it
/// was measured.
fn render_json(responses: &[Vec<String>], duration: Option<Duration>) -> String {
    let rs = responses
        .iter()
        .map(|answers| object! { "answers": answers.clone() })
        .collect::<Vec<_>>();

    if let Some(duration) = duration {
        object! {
            "responses": rs,
            "duration": {
                "secs": duration.as_secs(),
                "millis": duration.subsec_millis(),
            },
        }
        .to_string()
    } else {
        object! {
            "responses": rs,
        }
        .to_string()
    }
}

/// Renders the `--json` form of an error, which is written to standard error.
fn render_error_json(message: &str) -> String {
    object! {
        "error": true,
        "error_message": message,
    }
    .to_string()
}

impl TextFormat {
    /// Formats a summary of a record in a received DNS response. Each record
    /// type contains wildly different data, so the format of the summary
    /// depends on what record it’s for.
    pub fn record_payload_summary(record: &hickory_resolver::proto::rr::RData) -> String {
        record.to_string()
    }

    /// Formats a duration depending on whether it should be displayed as
    /// seconds, or as computed units.
    pub fn format_duration(self, seconds: u32) -> String {
        if self.format_durations {
            format_duration_hms(seconds)
        } else {
            format!("{seconds}")
        }
    }
}

/// Formats a duration as days, hours, minutes, and seconds, skipping leading
/// zero units.
fn format_duration_hms(seconds: u32) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 60 * 60 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else if seconds < 60 * 60 * 24 {
        format!(
            "{}h{:02}m{:02}s",
            seconds / 3600,
            (seconds % 3600) / 60,
            seconds % 60
        )
    } else {
        format!(
            "{}d{}h{:02}m{:02}s",
            seconds / 86400,
            (seconds % 86400) / 3600,
            (seconds % 3600) / 60,
            seconds % 60
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration_hms(0), "0s");
        assert_eq!(format_duration_hms(59), "59s");
        assert_eq!(format_duration_hms(60), "1m00s");
        assert_eq!(format_duration_hms(3599), "59m59s");
        assert_eq!(format_duration_hms(3600), "1h00m00s");
        assert_eq!(format_duration_hms(86399), "23h59m59s");
        assert_eq!(format_duration_hms(86400), "1d0h00m00s");
    }

    // The `--json` output is a public interface, so these pin its exact bytes. The expected
    // strings were produced by the original `json` crate before it was replaced, and the
    // replacement had to reproduce them, including key order and which characters are escaped.

    #[test]
    fn json_no_responses() {
        assert_eq!(render_json(&[], None), r#"{"responses":[]}"#);
        assert_eq!(
            render_json(&[], Some(Duration::new(0, 0))),
            r#"{"responses":[],"duration":{"secs":0,"millis":0}}"#
        );
    }

    #[test]
    fn json_responses() {
        assert_eq!(
            render_json(&[vec!["a.example. 300 IN A 1.2.3.4".into()]], None),
            r#"{"responses":[{"answers":["a.example. 300 IN A 1.2.3.4"]}]}"#
        );
        assert_eq!(
            render_json(&[vec![]], None),
            r#"{"responses":[{"answers":[]}]}"#
        );
        assert_eq!(
            render_json(
                &[vec!["x".into(), "y".into()], vec![], vec!["z".into()]],
                Some(Duration::new(3, 45_678_912))
            ),
            r#"{"responses":[{"answers":["x","y"]},{"answers":[]},{"answers":["z"]}],"duration":{"secs":3,"millis":45}}"#
        );
    }

    #[test]
    fn json_escaping() {
        let answers = vec![
            "plain".to_string(),
            "quote\" backslash\\ slash/ tab\t nl\n cr\r bs\u{8} ff\u{c}".to_string(),
            "ctl\u{1} \u{1f} del\u{7f}".to_string(),
            "unicode é 日本 \u{1F415} ls\u{2028} ps\u{2029}".to_string(),
            String::new(),
        ];
        let expected = [
            r#"{"responses":[{"answers":["plain","quote\" backslash\\ slash/ tab\t nl\n cr\r bs\b ff\f","ctl\u0001 \u001f del"#,
            "\u{7f}",
            r#"","unicode é 日本 🐕 ls"#,
            "\u{2028}",
            " ps",
            "\u{2029}",
            r#"",""]}],"duration":{"secs":0,"millis":1}}"#,
        ]
        .concat();
        assert_eq!(
            render_json(&[answers], Some(Duration::from_millis(1))),
            expected
        );
    }

    #[test]
    fn json_errors() {
        assert_eq!(
            render_error_json("plain error"),
            r#"{"error":true,"error_message":"plain error"}"#
        );
        let expected = [
            r#"{"error":true,"error_message":"bad \"thing\"\n\u0001"#,
            "\u{2028}",
            r#" é"}"#,
        ]
        .concat();
        assert_eq!(
            render_error_json("bad \"thing\"\n\u{1}\u{2028} é"),
            expected
        );
    }
}
