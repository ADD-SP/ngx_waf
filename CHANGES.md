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
* The coverage of the core is one command: `mise run coverage` reports the
  unit tests per module, `mise run coverage-e2e` adds an instrumented nginx
  running the end to end and `Test::Nginx` suites.
* The SSL context of the captcha endpoint (`waf_captcha api=https://...`) is
  released with the configuration: every configuration load leaked it before.
* `mise run test-valgrind` runs the `Test::Nginx` templates and the end to end
  checks under valgrind, and CI runs it for the static module of the stable
  nginx branch.
* The shared memory of the core is only reached through a guard that holds the
  zone lock: the glue no longer offers an allocation that takes the lock
  itself, and an operation that leaves early (or panics) cannot keep the zone
  locked.  Three of those early returns were fixed.
* A counter table does not scan itself any more: the probe of an address walks
  at most 64 slots, a forgotten or expired entry is recycled by the next
  address whose walk passes it, and a table that reached three quarters of its
  slots drops one of the entries the walk passed.  A zone keeps remembering the
  same number of addresses, its tables take a third more of the segment
  (~12.5% instead of ~9.4%), and the first reload after the upgrade rebuilds
  the zone once.
* The structures of a shared memory zone are checked before they are used:
  every pointer the core follows has to lie inside the segment, a table header
  has to describe slots that fit in it, and a directory entry (or a directory
  chain) that fails the check is dropped, so a zone that a bug, a crash or
  another process wrote over is rebuilt instead of being read as a slice that
  reaches out of the zone.

See [https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/changes/overview.md](https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/changes/overview.md).
