---
title: 4.x.x
lang: en
---

# Change Log (4.x.x)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

::: tip What is a breaking change?

* The original configuration file may not work, for example, if a directive item is removed or renamed.
* It may be necessary to update the build environment, such as installing new dependencies.

:::

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