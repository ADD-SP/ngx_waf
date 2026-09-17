//! The Rust core of the ngx_waf nginx module.
//!
//! The C side keeps the module/directive registration, the request data
//! packing, the asynchronous parts of the nginx event loop and the response
//! plumbing.  Everything else lives here and is reached through the C ABI in
//! [`ffi`], which is described by `include/ngx_http_waf_ffi.h`.

// The crate is only reachable through the C ABI of `ffi`, everything else is
// internal.
mod cache;
mod cc;
mod check;
mod config;
mod ffi;
mod flags;
mod ip_trie;
mod modsec;
mod pcre;
mod rules;
mod types;
mod util;
