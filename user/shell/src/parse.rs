//! The command line: words separated by spaces, `"..."` or `'...'` keep spaces inside a word,
//! `|` between stages (outside quotes), `start` in front runs the whole line as a job.

use alloc::string::String;
use alloc::vec::Vec;

pub struct Line {
    /// `start ...`: a job; the prompt comes back at once.
    pub background: bool,
    /// The stages, each a list of words.
    pub stages: Vec<Vec<String>>,
}

/// Split a line. Err: what is wrong (an open quote, an empty stage).
pub fn parse(line: &str) -> Result<Line, String> {
    let mut stages: Vec<Vec<String>> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => word.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                in_word = true;
            }
            (None, ' ' | '\t') => {
                if in_word {
                    words.push(core::mem::take(&mut word));
                    in_word = false;
                }
            }
            (None, '|') => {
                if in_word {
                    words.push(core::mem::take(&mut word));
                    in_word = false;
                }
                if words.is_empty() {
                    return Err(String::from("nothing before '|'"));
                }
                stages.push(core::mem::take(&mut words));
            }
            (None, c) => {
                word.push(c);
                in_word = true;
            }
        }
    }
    if quote.is_some() {
        return Err(String::from("a quote is not closed"));
    }
    if in_word {
        words.push(word);
    }
    if words.is_empty() {
        if !stages.is_empty() {
            return Err(String::from("nothing after '|'"));
        }
    } else {
        stages.push(words);
    }
    let background = stages.first().and_then(|s| s.first()).is_some_and(|w| w == "start");
    if background {
        stages[0].remove(0);
        if stages[0].is_empty() {
            return Err(String::from("start what? (start <command>)"));
        }
    }
    Ok(Line { background, stages })
}

/// The word being typed at the end of `before` (for completion): (its start, the word).
pub fn last_word(before: &str) -> (usize, &str) {
    let start = before.rfind([' ', '|']).map_or(0, |p| p + 1);
    (start, &before[start..])
}

/// Is the word at `start` the first of its stage (a command name)?
pub fn is_command_position(before: &str, start: usize) -> bool {
    let head = before[..start].trim_end();
    head.is_empty() || head.ends_with('|') || head == "start"
}
