---
title: 3.x.x
lang: zh-CN
---

# 更新日志（3.x.x）

本文件的格式基于[如何维护更新日志](https://keepachangelog.com/zh-CN/1.0.0)，
并且本项目遵守[语义化版本](https://semver.org/lang/zh-CN/spec/v2.0.0.html)。

::: tip 何为「不兼容的修改」？

* 原有的配置文件可能无法使用，比如删除或者重命名了某个配置项。
* 可能需要更新编译环境，比如安装新的依赖。

:::

## [3.1.6] - 2021-03-07

### 修复

* 更正规则的生效顺序（[51c7824](https://github.com/ADD-SP/ngx_waf/commit/51c7824786c060f4b0dcffe77a4a1e04b775e04b)）。

***

## [3.1.5] - 2021-03-03

### 修复

* 修复了 `config` 脚本的一个错误，这个错误会导致不能正确地检查依赖项（[075a27e](https://github.com/ADD-SP/ngx_waf/commit/075a27e4f7aaf7e78c45eac0c78c9634863be476#diff-b79606fb3afea5bd1609ed40b622142f1c98125abcfe89a76a661b0e8e343910)）。

***

## [3.1.4] - 2021-03-02

### 改动

* 条件允许的情况下使用更安全的字符串处理函数以避免缓冲区溢出（[177ae68](https://github.com/ADD-SP/ngx_waf/commit/177ae68cb019f47096e6065ec34aa0ef9be07567)）。

***

## [3.1.3] - 2021-02-23

### 修复

* 改正规则的生效顺序（[857ec84](https://github.com/ADD-SP/ngx_waf/commit/857ec84c6519d88d1c1a5560a244dceffd413f3f)）。

***

## [3.1.2] - 2021-02-17

### 修复

* 修复了一个 bug，这个 bug 会导致当规则文件不具有可写权限时初始化失败（[20acd27](https://github.com/ADD-SP/ngx_waf/commit/20acd27815d1f266d89c1557e93848c96117b8ff)）。

***

## [3.1.1] - 2021-01-18

### 修复

* 兼容较低版本的 GCC（[becbbe0](https://github.com/ADD-SP/ngx_waf/commit/becbbe022b9f6efa606e720d7cbcd6c5d6f22c33)）。

***

## [3.1.0] - 2021-01-17

### 注意

* 因为在 `v3.0.3` 测试过程中新增了向下兼容的功能，所以 `v3.0.3` 被跳过。

### 新增

* 增加调试日志便于排障（[bac1d02](https://github.com/ADD-SP/ngx_waf/commit/bac1d026e9e902d9a49881e899cba4965f3388a4)）。

### 修复

* 修复了一个段错误（[57d7719](https://github.com/ADD-SP/ngx_waf/commit/57d7719654caddc40ee655c797f0984f42c25495)）。

* 更精确的访问频次统计（[53d3b14](https://github.com/ADD-SP/ngx_waf/commit/53d3b149a524252dbb9b8170e31f4b1f4895a6b7)）。

***

## [3.0.2] - 2021-01-10

### 注意

* 因为在 `v3.0.1`上有热修复，所以 `v3.0.2` 的一切测试版本作废，请不要使用这些测试版。

### 修复

* 修复一个了在 `Alpine Linux` 下的编译错误（[e989aa3](https://github.com/ADD-SP/ngx_waf/commit/e989aa34370da73f03627601188ca33844372c4f)）。

***

## [3.0.1] - 2020-12-28

### 修复

* 修复了一个在检查 Cookie 时的段错误（[8dc2b56](https://github.com/ADD-SP/ngx_waf/commit/8dc2b56e9a8ae7c22cc5309ac0a060b0358f545b)）。

***

## [3.0.0] - 2020-12-25

### 新增

* CC 防御现在也支持了 IPV6（[00fbc1c](https://github.com/ADD-SP/ngx_waf/commit/00fbc1c20ec964f6cd3bb992d756737e95b6c7ed)）。

* IP 黑白名单支持了 IPV6。可以识别形如 `fe80::/10` 的 IPV6 字符串（[8519b26](https://github.com/ADD-SP/ngx_waf/commit/8519b26f5fb9491ac60ae084247a0957c0931d0c)）。

### 改动

* 删除了一些无用的日志（[bd279e7](https://github.com/ADD-SP/ngx_waf/commit/bd279e7be872621fa75337722a9fae30b2ea6812)）。

* 友好的错误提示（[d1185b2](https://github.com/ADD-SP/ngx_waf/commit/d1185b26a413e45dcf5ef479b0078aa57a4b5962) & [f2b617d](https://github.com/ADD-SP/ngx_waf/commit/f2b617d5174eb1bc6982113415ddcb1f798ef703)）。当规则文件中 IP 地址无效或者 IP 地址块重叠的时候警告或者报错（并不能检测所有的重叠情况）。

* 更快的 IP 地址检查速度（[2b9e774](https://github.com/ADD-SP/ngx_waf/commit/2b9e77404826666df301c3d6b3ce07a6968de266)）。改用前缀树检查 IP，现在在常数时间内即可完成 IP 的匹配，之前是一个一个地匹配，是线性时间。

### 修复

* 修复了 Cookie 检查的失效的 bug（[87beed1](https://github.com/ADD-SP/ngx_waf/commit/87beed183e404c70411a2d35ea68ebbccccf5ff6)）。

* 修改 `config` 文件以确保执行 `make` 或 `make modules` 时最新的模块代码能够被编译（[25f97f5](https://github.com/ADD-SP/ngx_waf/commit/25f97f5e7f3792b131ab0ebb1bfe4b7fe5e330ae)）。在修复之前，如果仅仅 `inc/` 下的文件发生变化，编译时不会将最新的代码编译进去，因为没有检查 `inc/` 下的文件是否发生变化。

* 修复了 IPV4 网段识别错误的 bug（[73a22eb](https://github.com/ADD-SP/ngx_waf/commit/73a22eb3538a24e9714bf8331946a5654df20cc1)）。这个 bug 可能会导致当规则中出现类似 `192.168.0.0/10`，即后缀不是 8 的倍数的时候无法正确生成子网掩码。