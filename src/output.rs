//! Text and JSON output.

use std::time::Duration;
use std::env;
use std::io::{self, BufWriter, Write};

use hickory_resolver::lookup::Lookup;
use hickory_resolver::error::ResolveError;
use json::object;

use crate::colours::Colours;
use crate::table::{Table, Section};


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
        self == Self::Always || (atty::is(atty::Stream::Stdout) && env::var("NO_COLOR").is_err() && self != Self::Never)
    }

    /// Creates a palette of colours depending on the user’s wishes or whether
    /// output is to a terminal.
    pub fn palette(self) -> Colours {
        if self.should_use_colours() {
            Colours::pretty()
        }
        else {
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
            Self::Short(tf) => {
                let all_answers = responses.into_iter().flat_map(|r| r.into_iter()).collect::<Vec<_>>();

                if all_answers.is_empty() {
                    eprintln!("No results");
                    return false;
                }

                for answer in all_answers {
                    println!("{}", tf.record_payload_summary(&answer));
                }
            }
            Self::JSON => {
                let mut rs = Vec::new();

                for response in responses {
                    let json = object! {
                        "answers": response.record_iter().map(|r| r.to_string()).collect::<Vec<_>>(),
                    };

                    rs.push(json);
                }

                if let Some(duration) = duration {
                    let object = object! {
                        "responses": rs,
                        "duration": {
                            "secs": duration.as_secs(),
                            "millis": duration.subsec_millis(),
                        },
                    };

                    println!("{}", object);
                }
                else {
                    let object = object! {
                        "responses": rs,
                    };

                    println!("{}", object);
                }
            }
            Self::Text(uc, tf) => {
                let total_records = responses.iter().flat_map(|r| r.record_iter()).count();
                if total_records > 100 {
                    let stdout = io::stdout();
                    let mut writer = BufWriter::new(stdout);
                    for response in responses {
                        let mut table = Table::new(uc.palette(), tf);
                        for a in response.record_iter() {
                            table.add_row(a.clone(), Section::Answer);
                        }
                        write!(&mut writer, "{}", table.render()).unwrap();
                    }
                    writer.flush().unwrap();
                } else {
                    for response in responses {
                        let mut table = Table::new(uc.palette(), tf);
                        for a in response.record_iter() {
                            table.add_row(a.clone(), Section::Answer);
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
    pub fn print_error(self, error: ResolveError) {
        match self {
            Self::Short(..) | Self::Text(..) => {
                eprintln!("Error: {}", error);
            }

            Self::JSON => {
                let object = object! {
                    "error": true,
                    "error_message": error.to_string(),
                };

                eprintln!("{}", object);
            }
        }
    }
}

impl TextFormat {

    /// Formats a summary of a record in a received DNS response. Each record
    /// type contains wildly different data, so the format of the summary
    /// depends on what record it’s for.
    pub fn record_payload_summary(self, record: &hickory_resolver::proto::rr::RData) -> String {
        record.to_string()
    }

    /// Formats a duration depending on whether it should be displayed as
    /// seconds, or as computed units.
    pub fn format_duration(self, seconds: u32) -> String {
        if self.format_durations {
            format_duration_hms(seconds)
        }
        else {
            format!("{}", seconds)
        }
    }
}

/// Formats a duration as days, hours, minutes, and seconds, skipping leading
/// zero units.
fn format_duration_hms(seconds: u32) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    }
    else if seconds < 60 * 60 {
        format!("{}m{:02}s",
            seconds / 60,
            seconds % 60)
    }
    else if seconds < 60 * 60 * 24 {
        format!("{}h{:02}m{:02}s",
            seconds / 3600,
            (seconds % 3600) / 60,
            seconds % 60)
    }
    else {
        format!("{}d{}h{:02}m{:02}s",
            seconds / 86400,
            (seconds % 86400) / 3600,
            (seconds % 3600) / 60,
            seconds % 60)
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
}
