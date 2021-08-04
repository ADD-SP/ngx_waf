---
title: Current
lang: en
---

# Change Log (Current)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

::: tip What is a breaking change?

* The original configuration file may not work, for example, if a directive item is removed or renamed.
* It may be necessary to update the build environment, such as installing new dependencies.

:::

## [Unreleased]

### Added
 

### Removed


### Changed


### Fixed


***

## [7.0.0] - 2021-08-04 UTC+0800

### Changed

* Changed the way Under Attack Mode is implemented. It is no longer implemented using redirects, but by modifying the response body.

* Removed directive `uri` from configuration item `waf_under_attack`, see documentation for details.

* Added a directive `file` to the configuration item `waf_under_attack` whose value should be the absolute path to an HTML file, see the documentation for details.

* The directive `waf_cc_deny` is not allowed at the context `http`。