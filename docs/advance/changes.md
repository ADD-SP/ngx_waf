---
title: Changes
lang: en
---

# Change Log

## [Unreleased]

### **WARNING**

**This version contains breaking changes.**

### Added

* A new mode `CACHE` has been added, enabling this mode will cache the results of each inspection to improve performance.

* New configuration `waf_cache` has been added to set parameters related to cache.

* Added directive `waf_cc_deny` to set CC protection related parameters.

* New directive `waf_priority` has been added to set the priority of all checks except for POST checks.

### Removed

* The directive `waf_cc_deny_limit` is deprecated and replaced with the new directive `waf_cc_deny`.

### Changed

* Swaps the default priority of CC protection and IP whitelist inspection.

### Fixed

* Fixed a segmentation fault when the number of worker processes is greater than one.

* Fixed a bug where CC protection statistics were sometimes inaccurate.

***

## [4.0.0] - 2021-03-22 GMT+0800

### **WARNING**

**This version contains breaking changes.**

### Added

* Added some parameters to `waf_mode` and `waf_cc_deny_limit` ([368db2b](https://github.com/ADD-SP/ngx_waf/commit/368db2b26e9d2a910c06e77f892740cefe9556d3)).

### Removed

* Abort directive: `waf_mult_mount`. The function of this directive has been merged into the directive `waf_mode`.

### Changed 

* Adds some parameters to the directive `waf_mode`.

### Fixed

* Fixed an error in the name of the built-in variable `waf_rule_details`, 
which was set to `waf_rule_deatails` in a previous version of the code.

* No more superfluous inspections.

* Completely resolve compatibility issues with the `ngx_http_rewrite_module`.

***

## [3.1.6] - 2021-03-07

### Fixed

* Correcting the order in which rules take effect ([51c7824](https://github.com/ADD-SP/ngx_waf/commit/51c7824786c060f4b0dcffe77a4a1e04b775e04b)).

## [3.1.5] - 2021-03-03

### Fixed

* Fixed a bug in the `config` script that caused dependencies to not be checked correctly ([075a27e](https://github.com/ADD-SP/ngx_waf/commit/075a27e4f7aaf7e78c45eac0c78c9634863be476#diff-b79606fb3afea5bd1609ed40b622142f1c98125abcfe89a76a661b0e8e343910)).

***

## [3.1.4] - 2021-03-02

### Changed

* Use safer string handling functions to avoid buffer overflows when conditions allow ([177ae68](https://github.com/ADD-SP/ngx_waf/commit/177ae68cb019f47096e6065ec34aa0ef9be07567)).

***

## [3.1.3] - 2021-02-23

### Fixed

* Order of effectiveness of correction rules ([857ec84](https://github.com/ADD-SP/ngx_waf/commit/857ec84c6519d88d1c1a5560a244dceffd413f3f)).

***

## [3.1.2] - 2021-01-18

### Fixed

* Fixed a bug that caused module initialization to fail when the rule file was not writable ([20acd27](https://github.com/ADD-SP/ngx_waf/commit/20acd27815d1f266d89c1557e93848c96117b8ff)).

***

## [3.1.1] - 2021-01-18

### Fixed

* Compatible with lower versions of gcc ([becbbe0](https://github.com/ADD-SP/ngx_waf/commit/becbbe022b9f6efa606e720d7cbcd6c5d6f22c33)).

***

## [3.1.0] - 2021-01-17

### Note

* `v3.0.3` was skipped because a backward compatibility feature was added during the `v3.0.3` test.

### Added

* Add debug log for easy troubleshooting ([bac1d02](https://github.com/ADD-SP/ngx_waf/commit/bac1d026e9e902d9a49881e899cba4965f3388a4)).

### Fixed

* Fixed a segmentation fault ([57d7719](https://github.com/ADD-SP/ngx_waf/commit/57d7719654caddc40ee655c797f0984f42c25495))。

* More accurate visit frequency statistics ([53d3b14](https://github.com/ADD-SP/ngx_waf/commit/53d3b149a524252dbb9b8170e31f4b1f4895a6b7)).

***

## [3.0.2] - 2021-01-10

### Note

* Because of hotfixes performed on `v3.0.1`, all beta versions of `v3.0.2` are voided, please do not use these beta versions.

### Fixed

* Fixed a build error on `Alpine Linux` ([e989aa3](https://github.com/ADD-SP/ngx_waf/commit/e989aa34370da73f03627601188ca33844372c4f)).

***

## [3.0.1] - 2020-12-28

### Fixed

* Fixed a segmentation fault when inspecting cookies ([8dc2b56](https://github.com/ADD-SP/ngx_waf/commit/8dc2b56e9a8ae7c22cc5309ac0a060b0358f545b)).


***

## [3.0.0] - 2020-12-25

### Added

* Anti Challenge Collapsar now supports IPV6 ([00fbc1c](https://github.com/ADD-SP/ngx_waf/commit/00fbc1c20ec964f6cd3bb992d756737e95b6c7ed)).

* IP black and white lists support IPV6, and can recognize IPV6 strings such as `fe80::/10` ([8519b26](https://github.com/ADD-SP/ngx_waf/commit/8519b26f5fb9491ac60ae084247a0957c0931d0c)).

### Changed

* Delete some meaningless logs ([bd279e7](https://github.com/ADD-SP/ngx_waf/commit/bd279e7be872621fa75337722a9fae30b2ea6812)).

* Friendly error alerts ([d1185b2](https://github.com/ADD-SP/ngx_waf/commit/d1185b26a413e45dcf5ef479b0078aa57a4b5962) & [f2b617d](https://github.com/ADD-SP/ngx_waf/commit/f2b617d5174eb1bc6982113415ddcb1f798ef703)). Warnings or error reporting when IP addresses in the rule file are invalid or IP address blocks overlap (does not detect all overlaps).

* Faster IP matching ([2b9e774](https://github.com/ADD-SP/ngx_waf/commit/2b9e77404826666df301c3d6b3ce07a6968de266)).

### Fixed

* Fixed a bug that caused the cookie inspection not work ([87beed1](https://github.com/ADD-SP/ngx_waf/commit/87beed183e404c70411a2d35ea68ebbccccf5ff6)).

* Modify the `config` file to ensure that the latest module code is compiled when executing `make` or `make modules` ([25f97f5](https://github.com/ADD-SP/ngx_waf/commit/25f97f5e7f3792b131ab0ebb1bfe4b7fe5e330ae)). Before the fix, if only the files under `inc/` changed, the latest code would not be compiled because the files under `inc/` were not checked for changes.

* Fixed a bug with incorrect IPV4 segment identification ([73a22eb](https://github.com/ADD-SP/ngx_waf/commit/73a22eb3538a24e9714bf8331946a5654df20cc1)). This bug could cause the subnet mask not to be generated correctly when a rule like `192.168.0.0/10`, i.e. the suffix is not a multiple of 8, appears in the rule.

***

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
