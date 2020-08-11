# Change Log

## [Unreleased]

### Added

+ 新配置项`ngx_waf_mult_mount`用于增加拦截面（[e1b500d](https://github.com/ADD-SP/ngx_waf/commit/e1b500de349e017b67f334878342bdd6a34d22b8)），典型的应用场景是存在`rewrite`的情况下重写前后均会对 URL 进行一次检测。
+ 支持 CC 防御功能（[3a93e19](https://github.com/ADD-SP/ngx_waf/commit/3a93e190b8cb78fcd7a0197f76298c010169d113)）。

### Changed

+ 修改规则优先级（[3c388c8](https://github.com/ADD-SP/ngx_waf/commit/3c388c85e30528b66306ca780524c7d663277f07)）（[248958d](https://github.com/ADD-SP/ngx_waf/commit/248958d3a0ef27dd14acc63a503e97931841f18a)），现在的优先级为（靠上的优先生效）：
    1. IP 白名单
    2. IP 黑名单
    3. CC 防御
    4. URL 白名单
    5. URL 黑名单
    6. 参数黑名单
    7. UserAgent 黑名单
    8. Referer 白名单
    9. Referer 黑名单

### Fixed

+ IPV4 黑白名单功能失效（[231f94a](https://github.com/ADD-SP/ngx_waf/commit/231f94aa5383fe8f6cdc0fbc3cd2dcadb7606881)）。
+ 当 User-agent 为空时会触发 segmentation fault（[bf33b36](https://github.com/ADD-SP/ngx_waf/commit/bf33b366232b7f5e05379d5e10ab006696189ea6)）。
+ 启用 CC 防御后会有内存泄漏（[be58d18](https://github.com/ADD-SP/ngx_waf/commit/be58d189b4c95be066623604124b02a9bf174e7f)）。

