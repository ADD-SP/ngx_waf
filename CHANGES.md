# Change Log

## [Unreleased]

### Added

### Changed

+ Instead of downloading the uthash dependency manually, you can install the system library with `yum install uthash-devel` or `apt-get install uthash-dev`([7cfc94b](https://github.com/ADD-SP/ngx_waf/commit/7cfc94bc64fa4f2c29bdf3b24e21aeb1ba412054)).

### Fixed


## [2.0.0] - 2020-09-29

### Added

+ We can compile the module with `--add-dynamic-module`. Thanks for [dvershinin](https://github.com/dvershinin)'s work([https://github.com/ADD-SP/ngx_waf/pull/4](https://github.com/ADD-SP/ngx_waf/pull/4))。

### Changed

+ Remove a default User-Agent rule that is `(?i)(? :Sogou web spider)`, as it will block non-malicious web spider([827d4e5](https://github.com/ADD-SP/ngx_waf/commit/827d4e5bc48894ff9147e49799d3a9656fe7dd8a)).
+ Merge directives([ba92cfd](https://github.com/ADD-SP/ngx_waf/commit/ba92cfd53ce78da8ff4ed22d2bc71a47de4cbe25)). These directives will be merged: `waf_check_ipv4`, `waf_check_url`, `waf_check_args`, `waf_check_ua`, `waf_check_referer`, `waf_check_cookie`, `waf_check_post`, `waf_check_cookie`, `waf_cc_deny`. The merged new directive is `waf_mode`, see [README](README-EN.md).

### Fixed

+ The blank lines in the rules can now be read correctly([955cf2d](https://github.com/ADD-SP/ngx_waf/commit/955cf2d240c4d66f815890e3ee9b88ccf906cf1d)).
