---
title: 5.x.x
lang: zh-CN
---

# 更新日志（5.x.x）

本文件的格式基于[如何维护更新日志](https://keepachangelog.com/zh-CN/1.0.0)，
并且本项目遵守[语义化版本](https://semver.org/lang/zh-CN/spec/v2.0.0.html)。

::: tip 何为「不兼容的修改」？

* 原有的配置文件可能无法使用，比如删除或者重命名了某个配置项。
* 可能需要更新编译环境，比如安装新的依赖。

:::

## [5.5.1] - 2021-07-16 UTC+0800

### 修复

* 段错误。

* 内存泄漏。

***

## [5.5.0] - 2021-06-25 UTC+0800

### 变动

* 在工作模式 `STD` 和 `DYNAMIC` 中禁用了基于 `libinjection` 的 XSS 攻击检测，因为有用户反映误报比较高。

***

## [5.4.2] - 2021-06-15 UTC+0800

### 修复

* 如果启用了 POST 检测，则访问日志（access_log）中不会记录 POST 请求，即丢失所有的 POST 请求的日志。

***


## [5.4.1] - 2021-06-09 UTC+0800

### 修复

* 当使用了 `error_page` 配置时，内置变量的值可能会出错。

***

## [5.4.0] - 2021-06-03 UTC+0800

### **注意**

**本次更新更换了 libinjection 的 clone 链接，新的链接为 [https://github.com/libinjection/libinjection.git](https://github.com/libinjection/libinjection.git)。**

### 新增

* XSS 攻击防御（Powered By [libinjection](https://github.com/libinjection/libinjection)）。

### 变动

* 增加内置变量计算相关的调试日志。

### 修复

* POST 检测失效。

***

## [5.3.2] - 2021-05-28 UTC+0800

### 修复

* 内存损坏。

***

## [5.3.1] - 2021-05-26 GMT+0800

### 修复

* 有时即使正确安装了依赖也不能编译模块。


***

## [5.3.0] - 2021-05-16 GMT+0800

### 新增

* 新的配置：`waf_under_attack`，当网站受到攻击时可以使用。

* 新的配置：`waf_http_status`，用于设置请求被拦截后返回的 HTTP 状态码。

* 新的内置变量：`$waf_blocking_log`，当请求被拦截其值时不为空字符串。

### 变动

* 更新了默认规则。

### 修复

* CC 防护有时会失效。

* Cookie 防护有时会失效。


***

## [5.1.2] - 2021-04-30 GMT+0800

### 新增

* 支持检测 SQL 注入（Powered By [libinjection](https://github.com/libinjection/libinjection)）。你可以通过启用 `LIB-INJECTION` 模式开启该功能，详见使用文档。

***

## [5.1.1] - 2021-04-23 GMT+0800

### 修复

* URL 和 Referer 白名单规则失效。

***

## [5.1.0] - 2021-04-20 GMT+0800

### 新增

* 新的内置变量 `waf_log`，当本模块进行了检查时不为空字符串，反之则为空字符串，主要用于 `access_log` 指令。

* 新的内置变量 `waf_spend`，记录本模块执行检查花费的时间（毫秒）。

***


## [5.0.0] - 2021-04-07 GMT+0800

### **警告**

**此版本包含不兼容的更新（breaking changes）。**

### 新增

* 新增了模式 `CACHE`，启用此模式后会缓存每次检查的结果，提高性能。

* 新增了配置 `waf_cache` 用于设置缓存相关的参数。

* 新增了配置 `waf_cc_deny`，用于设置 CC 防护相关的参数。

* 新增了配置 `waf_priority`，用来设置除了 POST 检查以外所有的检查项目的优先级。

* 当 CC 防护返回 503 状态码时会附上 [Retry-After](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Retry-After) 响应头。

### 移除

* 废弃了配置 `waf_cc_deny_limit`，使用新的配置 `waf_cc_deny` 替代。

### 变动

* 互换了 CC 防护和 IP 白名单检查的默认优先级。

### 修复

* 修复了当 worker 进程数量大于一时的段错误。

* 修复了 CC 防护统计有时不准的错误。