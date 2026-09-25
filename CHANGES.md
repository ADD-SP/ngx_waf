## Unreleased

* The next generation rule engine of discussion #129 landed under `rust/rule/`
  together with the `ngx-waf-rule` command line tool (`rust/rule-cli/`).  It
  compiles the `Rule "condition" actions;` syntax, evaluates it against a
  synthetic request and keeps the score/user variable semantics of the
  examples; the tool has the `check` and `test` subcommands.  `rust/Cargo.toml`
  is now a virtual workspace whose members are `src/` (the `ngx-waf-core` core
  crate, whose manifest lives next to `lib.rs`), `rule/` and `rule-cli/`.  The
  engine is not wired into `waf_rule_path` or the nginx module yet, that
  integration and its FFI entry points are the next change.
* The rule engine has a criterion benchmark of `RuleSet::evaluate`
  (`mise run bench`): the individual operators, header scans and 0/3/10/100/1000
  rule sets.  `mise run bench-check` compiles the harness and runs criterion's
  test mode in CI; the benchmark is not a performance gate.
* The rule engine has a reusable `EvaluationState` and `evaluate_fast` hot
  path: the owned `evaluate`/`evaluate_traced` API stays compatible, a worker
  can reuse one state per request, and a rule set without `log` actions or user
  variables does not allocate on the fast path.  The criterion suite compares
  the owned and fast paths.
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
* The memory safety of the core is checked by sanitizers and a fuzzer now:
  `mise run test-asan` runs the unit tests under AddressSanitizer,
  `mise run test-miri` runs the shared memory tables under Miri, `mise run
  fuzz` fuzzes the table state machine with cargo-fuzz, and
  `mise run test-sanitize-nginx` runs the end to end checks against an nginx
  built with AddressSanitizer.  CI runs all four.
* A table of a shared memory zone is refused unless the header and the slot
  array it describes lie in the segment: a capacity that fit the size of the
  segment but not the room behind its header (a table a bug, a crash or
  another process wrote over) was turned into a slice that reached out of the
  zone.
* The resolver context of a failed crawler or captcha provider lookup is not
  released twice any more: `ngx_resolve_name()`/`ngx_resolve_addr()` release
  the context when they report the failure, the module no longer calls
  `ngx_resolve_*_done()` on that path.
* The chunked framing of a captcha provider answer whose chunk size leaves no
  room for the CRLF of its chunk in the address space is refused instead of
  overflowing the addition that sizes the framing (a debug build panicked on
  the sum, a release build on the slice that followed it).
* `$waf_spend` never copies more bytes than the buffer that formats the number
  holds: `snprintf()` reports the length it would have written, and the copy
  used that length to read from the stack buffer it was given.
* A context whose `waf_captcha` names more than one `api=https://...` keeps one
  pool cleanup for the SSL context of its endpoint: the module releases the
  context a repeated directive replaces and registers the cleanup once instead
  of freeing the same `SSL_CTX` twice when the configuration goes away.
* `waf_captcha` supports Cloudflare Turnstile (`prov=Turnstile`): the default
  endpoint is Turnstile's siteverify API, the answer only has to carry
  `success`, the native `cf-turnstile-response` and the compatibility mode's
  `g-recaptcha-response` fields are both accepted, and the module ships a
  Turnstile page (issue #153).
* `waf_captcha max_fails=N` honours the configured value: the C implementation
  used a floor of 20 (`max(N, 20)`), so a smaller `N` behaved like 20.  The
  failure after the configured number now answers 429 (issue #152).
* `waf_action modsecurity=FOLLOW` serves the configured `waf_block_page` with
  the status of the ModSecurity rule; the C implementation returned the bare
  status and left the response to the nginx error page (issue #114).
* The cookies of the captcha and of the under attack page are parsed with the
  `cookie` crate, so the "Cookie" parsing change of nginx 1.29.6 (issue #154)
  does not affect them.  The C implementation looked the cookies up with
  `ngx_http_parse_multi_header_lines()`, which stopped treating `;` as a
  separator and challenged every visitor again.

See [https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/changes/overview.md](https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/changes/overview.md).
