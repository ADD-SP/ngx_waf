# Change Log

## [Unreleased]

### Added

+ 支持 CC 防御功能。

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

