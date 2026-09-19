//! The Rust core of the ngx_waf nginx module.
//!
//! The C side keeps the module/directive registration, the request data
//! packing, the asynchronous parts of the nginx event loop and the response
//! plumbing.  Everything else lives here and is reached through the C ABI in
//! [`ffi`], which is described by `include/ngx_http_waf_ffi.h`.

// Unsafe code is confined to the boundaries the README lists; every block
// carries the safety argument that makes it sound, and an operation inside an
// `unsafe fn` needs its own block (and argument) like any other.
#![warn(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]

// The crate is only reachable through the C ABI of `ffi`, everything else is
// internal.
mod abi;
mod cache;
mod cc;
mod check;
mod config;
mod data;
mod ffi;
mod flags;
mod http;
mod modsec;
mod pcre;
mod rules;
mod util;
