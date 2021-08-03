---
title: 5.x.x
lang: en
---

# Change Log (5.x.x)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

::: tip What is a breaking change?

* The original configuration file may not work, for example, if a directive item is removed or renamed.
* It may be necessary to update the build environment, such as installing new dependencies.

:::

## [5.5.1] - 2021-07-16 UTC+0800

### Fixed

* Segmentation fault.

* Memory leak.

***

## [5.5.0] - 2021-06-25 UTC+0800

### Changed

* Because of high false positives, [libinjection](https://github.com/libinjection/libinjection)-based XSS attack detection has been disabled in working modes `STD` and `DYNAMIC`.

***

## [5.4.2] - 2021-06-15 UTC+0800

### Fixed

* When POST inspection is enabled, POST requests are not logged in the access log.

***

## [5.4.1] - 2021-06-09 UTC+0800

### Fixed

* The value of built-in variables may be wrong when the directive `error_page` is used.

***

## [5.4.0] - 2021-06-03 UTC+0800

### **NOTE**

**The clone link for `libinjection` has been replaced in this release. The new link is [https://github.com/libinjection/libinjection.git](https://github.com/libinjection/libinjection.git).**

### Added

* Anti XSS (powered by [libinjection](https://github.com/libinjection/libinjection)).

### Changed

* Add debug log related to built-in variable calculation.

### Fixed

* POST inspection is not working.

***

## [5.3.2] - 2021-05-28 UTC+0800

### Fixed

* Memory corruption.

***

## [5.3.1] - 2021-05-26 GMT+0800

### Fixed

* Sometimes the module does not compile even if the dependencies are installed correctly.

***


## [5.3.0] - 2021-05-16 GMT+0800

### Added

* New directive: `waf_under_attack`, which can be used when the site is under attack.

* New directive: `waf_http_status`, which sets the HTTP status code returned when a request is blocked.

* New built-in variable: `$waf_blocking_log`, not an empty string when the request is blocked for its value.

### Changed

* Update default rules.

### Fixed

* CC protection sometimes not work.

* Cookie inspection sometimes not work.

***


## [5.1.2] - 2021-04-30 GMT+0800

### Added

* Support for detecting SQL injection (powered by [libinjection](https://github.com/libinjection/libinjection)). This feature can be enabled by enabling the mode `LIB-INJECTION`, see the documentation for details.

***

## [5.1.1] - 2021-04-23 GMT+0800

### Fixed

* URL and Referer whitelist are not working.

***

## [5.1.0] - 2021-04-20 GMT+0800

### Added

* New built-in variable `waf_log`, which is not an empty string when this module has performed a inspection, but an empty string otherwise, mainly used in the directive `access_log`.

* New built-in variable `waf_spend`, which records the time (in milliseconds) taken by this module to perform the inspection.

***

## [5.0.0] - 2021-04-07 GMT+0800

### **WARNING**

**This version contains breaking changes.**

### Added

* A new mode `CACHE` has been added, enabling this mode will cache the results of each inspection to improve performance.

* New configuration `waf_cache` has been added to set parameters related to cache.

* Added directive `waf_cc_deny` to set CC protection related parameters.

* New directive `waf_priority` has been added to set the priority of all checks except for POST checks.

* The [Retry-Afte](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After) response header is appended when the CC protection returns a 503 status code.

### Removed

* The directive `waf_cc_deny_limit` is deprecated and replaced with the new directive `waf_cc_deny`.

### Changed

* Swaps the default priority of CC protection and IP whitelist inspection.

### Fixed

* Fixed a segmentation fault when the number of worker processes is greater than one.

* Fixed a bug where CC protection statistics were sometimes inaccurate.
