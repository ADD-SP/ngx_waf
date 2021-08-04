---
title: 最新版（Current）
lang: zh-CN
---

# 更新日志（Current）

本文件的格式基于[如何维护更新日志](https://keepachangelog.com/zh-CN/1.0.0)，
并且本项目遵守[语义化版本](https://semver.org/lang/zh-CN/spec/v2.0.0.html)。

::: tip 何为「不兼容的修改」？

* 原有的配置文件可能无法使用，比如删除或者重命名了某个配置项。
* 可能需要更新编译环境，比如安装新的依赖。

:::


## [未发布]


### 新增


### 移除


### 变动


### 修复


***

## [7.0.0] - 2021-08-04 UTC+0800

### 变动

* 改变了 Under Attack Mode 的实现方式。不再使用重定向实现，而是通过修改响应体实现。

* 删除了配置项 `waf_under_attack` 的参数 `uri`，详情见文档。

* 为配置项 `waf_under_attack` 增加了一个参数 `file`，该参数的值应该是一个 HTML 文件的绝对路径，详情见文档。

* 不允许在 `http` 这一级中使用配置项 `waf_cc_deny`。
