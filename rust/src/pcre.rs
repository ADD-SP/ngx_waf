//! Rule matching through the regular expression engine of nginx.
//!
//! Every rule of `waf_rule_path` is compiled with `ngx_regex_compile()` and
//! matched with `ngx_regex_exec()`, so a rule file may use the whole PCRE
//! syntax: look around asserts, back references, atomic groups, `\K`, ...
//! The glue hands the core a table of two callbacks and the rules run with the
//! very engine nginx was linked with (PCRE1 or PCRE2).
//!
//! Without that table — the unit tests of this crate, or a build of
//! `libngx_waf_core.a` outside nginx — the rules fall back to the `regex`
//! crate, which accepts a subset of that syntax (see [`super::rules`]).

use std::os::raw::c_void;

/// The engine of the glue, `ngx_waf_regex_ops_t` in the generated header.
///
/// * `compile(ctx, pattern, len)` returns an opaque handle for the pattern, or
///   null when the engine refused it.
/// * `exec(handle, value, len)` returns 1 when the value matches, 0 when it
///   does not, and -1 when the engine failed.
///
/// Both callbacks are provided by `src/ngx_http_waf_module.c`, and `ctx` is the
/// configuration pool the compiled patterns live in.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RegexOps {
    pub compile: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> *mut c_void>,
    pub exec: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> isize>,
    pub ctx: *mut c_void,
}

impl RegexOps {
    /// Whether the table can compile and run a pattern.
    pub fn usable(&self) -> bool {
        self.compile.is_some() && self.exec.is_some()
    }
}

impl std::fmt::Debug for RegexOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegexOps")
            .field("compile", &self.compile.is_some())
            .field("exec", &self.exec.is_some())
            .finish()
    }
}

/// One pattern compiled by the engine of the glue.
///
/// The handle belongs to the configuration pool of the cycle that compiled it;
/// it is never freed here, the pool takes it back when the configuration goes
/// away.
#[derive(Debug)]
pub struct PcreRegex {
    exec: unsafe extern "C" fn(*mut c_void, *const u8, usize) -> isize,
    handle: *mut c_void,
}

impl PcreRegex {
    /// Compile `pattern`, or return `None` when the engine refused it.
    pub fn compile(pattern: &[u8], ops: &RegexOps) -> Option<Self> {
        let compile = ops.compile?;
        let exec = ops.exec?;

        // SAFETY: the glue owns both callbacks; `ctx` is the configuration pool
        // that outlives every handle compiled with it, and the pattern is
        // readable for `pattern.len()` bytes.
        let handle = unsafe { compile(ops.ctx, pattern.as_ptr(), pattern.len()) };
        if handle.is_null() {
            return None;
        }

        Some(PcreRegex { exec, handle })
    }

    /// Whether `value` matches the pattern.
    pub fn is_match(&self, value: &[u8]) -> bool {
        // SAFETY: `handle` comes from the compile callback of the same table
        // and lives as long as the configuration; `value` is readable for
        // `value.len()` bytes and a match never keeps a pointer to it.
        unsafe { (self.exec)(self.handle, value.as_ptr(), value.len()) > 0 }
    }
}

// SAFETY: a compiled pattern is immutable; the engine allocates its match
// state per call (`ngx_regex_exec()` creates a new `pcre2_match_data`), so the
// handle can be shared between workers and threads.
unsafe impl Send for PcreRegex {}
// SAFETY: see above.
unsafe impl Sync for PcreRegex {}
