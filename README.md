# ngx_waf

<p align="center">
    <img src="https://cdn.jsdelivr.net/gh/ADD-SP/ngx_waf@master/assets/logo.png" width=200 height=200/>
</p>

[![test](https://github.com/ADD-SP/ngx_waf/workflows/test/badge.svg)](https://github.com/ADD-SP/ngx_waf/actions?query=workflow%3Atest)
[![docs](https://github.com/ADD-SP/ngx_waf-docs/actions/workflows/docs.yml/badge.svg)](https://add-sp.github.io/ngx_waf-docs/)

[![Notification](https://img.shields.io/badge/Notification-Telegram%20Channel-blue)](https://t.me/ngx_waf)
[![Discussion EN](https://img.shields.io/badge/Discussion%20EN-Telegram%20Group-blue)](https://t.me/group_ngx_waf)
[![Discussion CN](https://img.shields.io/badge/Discussion%20CN-Telegram%20Group-blue)](https://t.me/group_ngx_waf_cn)

English | [简体中文](README-ZH-CN.md)

Handy, High performance Nginx firewall module.

## Why ngx_waf

* Basic protection: such as black and white list of IPs or IP range, uri black and white list, and request body black list, etc.
* Easy to use: configuration files and rule files are easy to write and readable.
* High performance: Efficient algorithms and caching.
* Advanced protection: [ModSecurity](https://github.com/SpiderLabs/ModSecurity) compatible, you can use [OWASP(Open Web Application Security Project®) ModSecurity Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/).
* Friendly crawler verification: Supports verifying Google, Bing, Baidu and Yandex crawlers and allowing them automatically to avoid false positives.
* Captcha: Supports three kinds of captchas: hCaptcha, reCAPTCHAv2 and reCAPTCHAv3.

## Features

* [ModSecurity](https://github.com/SpiderLabs/ModSecurity) compatible.
* IPV4 and IPV6 support.
* Support for enabling CAPTCHAs, including [hCaptcha](https://www.hcaptcha.com/), [reCAPTCHAv2](https://developers.google.com/recaptcha) and [reCAPTCHAv3](https://developers.google.com/recaptcha).
* Support authentication-friendly crawlers (based on user agent and IP identification) to avoid blocking of these crawlers (e.g. GoogleBot).
* CC protection, if the request rate exceeds the limit, the IP will be automatically banned for a period of time, or use CAPTCHA to do human identification and allow it if successful.
* Exceptional allow on specific IP address.
* Block the specified IP address.
* Block the specified request body.
* Exceptional allow on specific URL.
* Block the specified URL.
* Block the specified query string.
* Block the specified UserAgent.
* Block the specified Cookie.
* Exceptional allow on specific Referer.
* Block the specified Referer.

## Docs

* Recommended link: [https://add-sp.github.io/ngx_waf-docs/](https://add-sp.github.io/ngx_waf-docs/)
* Alternate link: [https://ngx-waf-docs.pages.dev/](https://ngx-waf-docs.pages.dev/)

## Building from source

The module is a small nginx glue written in C plus a Rust core that holds the
logic (see [`rust/README.md`](rust/README.md)); Bazel is not used anymore.

The tasks and the Debian/Ubuntu system packages are declared in
[`mise.toml`](mise.toml) and run with [mise](https://mise.jdx.dev).  The Rust
toolchain is not managed by mise: rustup and `rust-toolchain.toml` pin it, so
install rustup first.

```sh
mise trust         # let mise read mise.toml
mise bootstrap -y  # install the system packages and the pinned cbindgen
mise run build     # build nginx with the static module in test/nginx-<version>
mise run test      # the Rust unit tests and the nginx integration tests
mise run test-e2e  # the end to end checks, with one worker and with four
```

`mise run doctor` checks that cargo, rustc and cbindgen are on PATH.  A stable
Rust toolchain (with cargo) and the development files of libmodsecurity 3 (for
example the `libmodsecurity-dev` package, or `LIB_MODSECURITY` pointing at a
prefix) are required, and nginx has to be built with SSL support
(`--with-http_ssl_module`): the client that reaches a captcha provider uses the
TLS machinery of nginx itself.  `[bootstrap.packages]` only names
Debian/Ubuntu packages; on another distribution install the equivalents (a C
toolchain, zlib, PCRE2, OpenSSL, libmodsecurity 3, perl) with its package
manager.  `NGINX_SRC` selects the nginx source tree to copy, `NGINX_VERSION` the
version to download when it is missing, and `mise run build-dynamic` builds the
dynamic module instead.  The known differences to the C implementation are
listed in [`rust/README.md`](rust/README.md).

## Contact

* Telegram Channel: [https://t.me/ngx_waf](https://t.me/ngx_waf)
* Telegram Group (English): [https://t.me/group_ngx_waf](https://t.me/group_ngx_waf)
* Telegram Group (Chinese): [https://t.me/group_ngx_waf_cn](https://t.me/group_ngx_waf_cn)

## Sponsor

Hope you can help promote this project. The more stars got, the better this project is. :)

## Test Suite

This module comes with a Perl-driven test suite. The test cases are declarative too.
Thanks to the [Test::Nginx](https://metacpan.org/pod/Test::Nginx) module in the Perl world.

Install the prerequisites once per machine, build the tree the suite runs
against, then run every template:

```shell
# The system packages include cpanminus; the second line installs Test::Nginx.
mise bootstrap -y
mise run test-nginx-deps

mise run build           # or: mise run build-dynamic

mise run test-nginx
```

`mise run test-nginx` runs every template; pass one or more test files to run
only those:

```shell
mise run test-nginx t/modsecurity.t
```

Export `MODULE_PATH=/path/to/ngx_http_waf_module.so` when the module is built
dynamically, and `TEST_NGINX_BINARY=/path/to/nginx` to test a binary other than
the one `mise run build` produced.

Some templates reach the real captcha providers, so the suite needs network
access.

## License

[BSD 3-Clause License](LICENSE)

## Thanks

* [ModSecurity](https://github.com/SpiderLabs/ModSecurity): An open source, cross platform web application firewall (WAF) engine.
* [uthash](https://github.com/troydhanson/uthash): C macros for hash tables and more.
* [libcurl](https://curl.se/libcurl/): The multiprotocol file transfer library .
* [cJSON](https://github.com/DaveGamble/cJSON): Ultralightweight JSON parser in ANSI C.
* [libinjection](https://github.com/libinjection/libinjection): SQL / SQLI tokenizer parser analyzer.
* [libsodium](https://github.com/jedisct1/libsodium): A modern, portable, easy to use crypto library.
* [test-nginx](https://github.com/openresty/test-nginx): Data-driven test scaffold for Nginx C module and OpenResty Lua library development.
* [lastversion](https://github.com/dvershinin/lastversion): A command line tool that helps you download or install a specific version of a project.
* [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf): A web application firewall based on the lua-nginx-module (openresty).
* [nginx-book](https://github.com/taobao/nginx-book): The Chinese language development guide for nginx.
* [nginx-development-guide](https://github.com/baishancloud/nginx-development-guide): The Chinese language development guide for nginx.
