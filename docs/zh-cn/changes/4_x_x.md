---
title: 4.x.x
lang: zh-CN
---

# 更新日志（4.x.x）

本文件的格式基于[如何维护更新日志](https://keepachangelog.com/zh-CN/1.0.0)，
并且本项目遵守[语义化版本](https://semver.org/lang/zh-CN/spec/v2.0.0.html)。

::: tip 何为「不兼容的修改」？

* 原有的配置文件可能无法使用，比如删除或者重命名了某个配置项。
* 可能需要更新编译环境，比如安装新的依赖。

:::

## [4.0.0] - 2021-03-22 GMT+0800

### **警告**

**此版本包含不兼容的更新（breaking changes）。**

### 新增

* 为 `waf_mode` 和 `waf_cc_deny_limit` 增加了一些参数（[368db2b](https://github.com/ADD-SP/ngx_waf/commit/368db2b26e9d2a910c06e77f892740cefe9556d3)）。

### 移除

* 废弃配置项 `waf_mult_mount`，该配置的功能已经合并到了配置项 `waf_mode` 中。

### 变动

* 给 `waf_mode` 增加了一些参数。

### 修复

* 更正了内置变量 `waf_rule_details` 的名称错误，该变量的名称在之前的版本代码中被设置为 `waf_rule_deatails`。

* 不再进行冗余的检测。

* 彻底解决了与 `ngx_http_rewrite_module` 的兼容性问题。