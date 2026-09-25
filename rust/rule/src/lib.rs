//! The next generation rule engine of `ngx_waf`.
//!
//! The engine compiles the rules of the [`Rule "condition" actions;`] syntax
//! described in the project discussion #129 into a [`RuleSet`], and evaluates
//! it against a [`Request`].  It is a plain Rust library: the nginx glue, the
//! FFI header and the `waf_rule_path` loader do not know about it yet.
//!
//! ```no_run
//! use ngx_waf_rule::{compile, Header, Request, Verdict};
//!
//! let rules = compile("Rule \"$URL == '/etc/passwd'\" deny,log;\n")?;
//! let headers = [Header { name: b"User-Agent", value: b"curl/8" }];
//! let request = Request::new(
//!     b"/etc/passwd",
//!     b"",
//!     b"GET",
//!     443,
//!     "127.0.0.1".parse().unwrap(),
//!     &headers,
//! );
//! assert_eq!(rules.evaluate(&request).verdict, Verdict::Deny { line: 1 });
//! # Ok::<(), ngx_waf_rule::Errors>(())
//! ```
//!
//! [`Rule "condition" actions;`]: https://github.com/ADD-SP/ngx_waf/discussions/129

#![warn(missing_docs)]

mod ast;
mod compile;
mod error;
mod eval;
mod parser;
mod regex;
mod request;

pub use crate::compile::RuleSet;
pub use crate::error::{Error, Errors};
pub use crate::eval::{
    Evaluation, EvaluationState, LogEntry, RuleTrace, TracedEvaluation, UserVariables, Verdict,
};
pub use crate::regex::{CompiledRegex, RegexEngine, RustRegexEngine};
pub use crate::request::{Header, Request};

/// Compile `source` with the [`RustRegexEngine`] of the `regex` crate.
///
/// The returned rules are independent of the source string and can be shared
/// between threads.
pub fn compile(source: &str) -> Result<RuleSet, Errors> {
    compile_with(source, &RustRegexEngine)
}

/// Compile `source` with the given regular expression engine.
///
/// The engine is the seam for the nginx integration: the module can hand over
/// its PCRE callbacks instead of the `regex` crate, and the compiled rules
/// keep the very same syntax and semantics.
pub fn compile_with(source: &str, regex: &dyn RegexEngine) -> Result<RuleSet, Errors> {
    let rules = parser::parse(source)?;
    compile::compile(&rules, source, regex)
}
