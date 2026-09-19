//! The compiled regex rules and the engine that runs them.

use crate::pcre::{PcreRegex, RegexOps};
use ::regex::Regex;

/// A compiled regex rule plus the text reported when it matches.
#[derive(Debug)]
pub struct RegexRule {
    pub pattern: Vec<u8>,
    engine: RegexEngine,
}

/// How the patterns of a rule are matched.
#[derive(Debug)]
enum RegexEngine {
    /// The PCRE of nginx, reached through the callbacks of the glue.  It
    /// understands the whole syntax a rule file can use.
    Pcre(PcreRegex),
    /// The `regex` crate, which accepts a subset of the PCRE syntax.  It is the
    /// engine of the unit tests and of a build of the core outside nginx; the
    /// module itself always has the callbacks of the glue.
    Native(Regex),
}

/// The engine refused the pattern; the caller reports the file and the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegexError;

impl RegexRule {
    /// Compile `line` with the engine of the glue, or with the `regex` crate
    /// when there is no glue (see [`RegexOps`]).
    pub fn compile(line: &[u8], ops: Option<&RegexOps>) -> Result<Self, RegexError> {
        let engine = match ops.filter(|ops| ops.usable()) {
            Some(ops) => match PcreRegex::compile(line, ops) {
                Some(regex) => RegexEngine::Pcre(regex),
                None => return Err(RegexError),
            },
            None => match Regex::new(&String::from_utf8_lossy(line)) {
                Ok(regex) => RegexEngine::Native(regex),
                Err(_) => return Err(RegexError),
            },
        };

        Ok(RegexRule {
            pattern: line.to_vec(),
            engine,
        })
    }

    /// Whether `value` matches the rule.
    pub fn is_match(&self, value: &[u8]) -> bool {
        match &self.engine {
            RegexEngine::Pcre(regex) => regex.is_match(value),
            RegexEngine::Native(regex) => regex.is_match(&String::from_utf8_lossy(value)),
        }
    }
}
