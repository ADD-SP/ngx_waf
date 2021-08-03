---
title: 2.x.x
lang: en
---

# Change Log (2.x.x)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

::: tip What is a breaking change?

* The original configuration file may not work, for example, if a directive item is removed or renamed.
* It may be necessary to update the build environment, such as installing new dependencies.

:::

## [2.1.1] - 2020-12.10

### Added

### Changed

### Fixed

* Fixed a module startup failure error. The error message for this error is `nginx: [alert] could not open error log file: open() "ngx_waf: /logs/error.log" failed (2: No such file or directory)` ([0dfc46f](https://github.com/ADD-SP/ngx_waf/commit/0dfc46f2dfc7ed91977b501c868abf961966d4e1)).

***

## [2.1.0] - 2020-12-09

### Added

* Compatible with the mainline version of NGINX ([f31f906](https://github.com/ADD-SP/ngx_waf/commit/f31f906b11fb00f54bfea504ca7c8c147a0be1d8) & [65277d1](https://github.com/ADD-SP/ngx_waf/commit/7b4f897a4a332b43bf94de874f8ba8c3098aaee4)).

### Changed

### Fixed

***

## [2.0.2] - 2020-12-07

### Added

### Changed

### Fixed

* Fix for Anti Challenge Collapsar failing when `waf_mult_mount` is disabled ([048fe5c](https://github.com/ADD-SP/ngx_waf/commit/048fe5c15863d9a3106387225774305aa5564726)).

* Fixed compile error caused by incorrect `#include` ([3fa298c](https://github.com/ADD-SP/ngx_waf/commit/3fa298c6184618ea0cd6336783a4d7a2ed27469c)).

***

## [2.0.1] - 2020-12-03

### Added

### Changed

* Instead of downloading the uthash dependency manually, you can install the system library with `yum install uthash-devel` or `apt-get install uthash-dev` ([7cfc94b](https://github.com/ADD-SP/ngx_waf/commit/7cfc94bc64fa4f2c29bdf3b24e21aeb1ba412054)).

### Fixed

* Fixed a bug that failed to compile under CentOS/RHEL 6 or 7 that was caused by not properly preventing macro redefinitions ([28e1c8a](https://github.com/ADD-SP/ngx_waf/commit/28e1c8aca03375089c75df21c5db3c38013edde7) & [566ae4a](https://github.com/ADD-SP/ngx_waf/commit/566ae4a50f855674b256db84305a24e1b2a6bc6d)).

***

## [2.0.0] - 2020-09-29

### Added

* We can compile the module with `--add-dynamic-module`. Thanks for [dvershinin](https://github.com/dvershinin)'s work([https://github.com/ADD-SP/ngx_waf/pull/4](https://github.com/ADD-SP/ngx_waf/pull/4))。

### Changed

* Remove a default User-Agent rule that is `(?i)(? :Sogou web spider)`, as it will block non-malicious web spider([827d4e5](https://github.com/ADD-SP/ngx_waf/commit/827d4e5bc48894ff9147e49799d3a9656fe7dd8a)).

* Merge directives ([ba92cfd](https://github.com/ADD-SP/ngx_waf/commit/ba92cfd53ce78da8ff4ed22d2bc71a47de4cbe25)). These directives will be merged: `waf_check_ipv4`, `waf_check_url`, `waf_check_args`, `waf_check_ua`, `waf_check_referer`, `waf_check_cookie`, `waf_check_post`, `waf_check_cookie`, `waf_cc_deny`. The merged new directive is `waf_mode`, see [README](README-EN.md).

### Fixed

* The blank lines in the rules can now be read correctly ([955cf2d](https://github.com/ADD-SP/ngx_waf/commit/955cf2d240c4d66f815890e3ee9b88ccf906cf1d)).
