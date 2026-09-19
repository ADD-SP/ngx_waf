## Unreleased

* The module logic is being rewritten in Rust: the C part is now only the nginx
  glue (module and directive registration, request packing, response and
  variable plumbing), everything else lives in `rust/`.
* Bazel has been replaced by the nginx `config` script, cargo and mise tasks.
* The FFI header `include/ngx_http_waf_ffi.h` is generated with cbindgen and
  checked in.
* The build entry points moved from the root `Makefile` to mise tasks
  (`.mise/tasks/`, `mise run <task>`).  `mise.toml` also declares the pinned
  cbindgen and the Debian/Ubuntu system packages; the Rust toolchain still
  comes from rustup and `rust-toolchain.toml`.
* The C ABI only carries the vocabulary of the boundary: typed enums for the
  step, the events, the methods and the protocol, opaque handles for the
  configurations and the inspection, and semantic queries for the
  configuration.  The constants and the types of the implementation no longer
  cross it.
* Every inspection is ported, including the asynchronous ones: the captcha and
  the friendly crawler verification use reverse DNS through the nginx resolver
  and a non blocking request to the captcha provider.  The response phases of
  ModSecurity are not ported.  The HTTP framing of the provider answer is
  parsed by the core: the glue only reads the bytes and hands them over.  The
  differences to the C implementation are listed in `rust/README.md`.

See [https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/changes/overview.md](https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/changes/overview.md).
