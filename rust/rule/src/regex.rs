//! The regular expression seam of the engine.

use std::str;

/// One compiled regular expression.
///
/// The trait is object safe and `Send + Sync`, so a [`crate::RuleSet`] can be
/// shared between the workers of nginx once the module integrates the engine.
pub trait CompiledRegex: Send + Sync {
    /// Whether the expression matches `value`.
    fn is_match(&self, value: &[u8]) -> bool;
}

/// The compiler of the regular expressions of a rule file.
///
/// [`RustRegexEngine`] is the default; the nginx integration can implement the
/// trait on top of its PCRE callbacks so that a `~=` rule keeps the syntax the
/// module already accepts in `waf_rule_path`.
pub trait RegexEngine {
    /// Compile `pattern`, or explain why the engine refused it.
    fn compile(&self, pattern: &[u8]) -> Result<Box<dyn CompiledRegex>, String>;
}

/// The engine of the `regex` crate.
#[derive(Clone, Copy, Debug, Default)]
pub struct RustRegexEngine;

struct NativeRegex(regex::bytes::Regex);

impl CompiledRegex for NativeRegex {
    fn is_match(&self, value: &[u8]) -> bool {
        self.0.is_match(value)
    }
}

impl RegexEngine for RustRegexEngine {
    fn compile(&self, pattern: &[u8]) -> Result<Box<dyn CompiledRegex>, String> {
        let pattern = str::from_utf8(pattern)
            .map_err(|_| "the pattern is not a valid UTF-8 string".to_string())?;
        let regex = regex::bytes::Regex::new(pattern).map_err(|error| error.to_string())?;
        Ok(Box::new(NativeRegex(regex)))
    }
}
