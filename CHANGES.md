## Unreleased

* The module logic is being rewritten in Rust: the C part is now only the nginx
  glue (module and directive registration, request packing, response and
  variable plumbing), everything else lives in `rust/`.
* Bazel has been replaced by the nginx `config` script, cargo and a `Makefile`.
* The FFI header `include/ngx_http_waf_ffi.h` is generated with cbindgen and
  checked in.
* Every inspection is ported, including the asynchronous ones: the captcha and
  the friendly crawler verification use reverse DNS through the nginx resolver
  and a non blocking request to the captcha provider.  The response phases of
  ModSecurity are not ported.  The differences to the C implementation are
  listed in `rust/README.md`.

See [https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/changes/overview.md](https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/changes/overview.md).
