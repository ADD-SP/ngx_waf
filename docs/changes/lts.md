---
title: Long-term Support (LTS)
lang: en
---

# Change Log (LTS)

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

## [6.1.0] - 2021-08-03 UTC+0800

### Added

* Added three options to the directive `waf_mode`.
    * ADV: Enable the  advanced rules.
    * CMN-METH: Equivalent to `head get post`.
    * ALL-METH: Any http request method will start checking.