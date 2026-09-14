## Unreleased

* The module logic is being rewritten in Rust: the C part is now only the nginx
  glue (module and directive registration, request packing, response and
  variable plumbing), everything else lives in `rust/`.
* Bazel has been replaced by the nginx `config` script, cargo and a `Makefile`.
* The FFI header `include/ngx_http_waf_ffi.h` is generated with cbindgen and
  checked in.
* The captcha and the friendly crawler verification are ported, including the
  asynchronous parts: reverse DNS through the nginx resolver and a non blocking
  provider request.  The five seconds shield and ModSecurity are still accepted
  by the configuration, reported with a warning and do nothing for now.

See [https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/changes/overview.md](https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/changes/overview.md).
