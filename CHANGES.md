# Change Log

## [Unreleased]

### Added

+ 支持 CC 防御功能。
+ 新配置项`ngx_waf_mult_mount`用于增加拦截面，典型的应用场景是存在`rewrite`的情况下重写前后均会对 URL 进行一次检测。

### Changed

+ 修改规则优先级，现在的优先级为（靠上的优先生效）：
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
+ 启用 CC 防御后会有内存泄漏。
+ 当 User-agent 为空时会触发 segmentation fault。

