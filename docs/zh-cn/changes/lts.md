---
title: 长期维护版（LTS）
lang: zh-CN
---

# 更新日志（LTS）

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

## [6.1.0] - 2021-08-03 UTC+0800

### 新增

* 为配置项 `waf_mode` 增加了三个选项。
    * ADV：控制开关高级规则。
    * CMN-METH：等价于 `HEAD GET POST`。
    * ALL-METH：任意的 HTTP 请求方法都会启动检查。

