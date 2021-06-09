---
title: 内置变量
lang: zh-CN
---

# 内置变量

在书写 nginx.conf 文件的时候不可避免地需要用到一些变量，如`$remote_addr`可以用来获取客户端 IP 地址。

本模块增加了多个可用的变量。

## `$waf_log`

如果本次请求中防火墙进行了检查则不为空字符串，反之为空字符串。本变量主要用于 `access_log` 指令，详见 [自定义日志格式](log.md#自定义日志格式)。

## `$waf_blocking_log`

如果本次请求本被模块拦截则不为空字符串，反之则为空字符串。本变量主要用于 `access_log` 指令，详见 [自定义日志格式](log.md#自定义日志格式)。

## `$waf_blocked`

表示本次请求是否被本模块拦截，如果拦截了则其的值为`'true'`,反之则为`'false'`。

## `$waf_spend`

表示本次检查花费了多少时间（毫秒），保留 5 位小数，舍入规则取决于具体 C 标准库的实现。

## `$waf_rule_type`

如果本次请求命中黑白名单规则，则其值为触发的规则类型。下面是可能的取值。若没有命中黑白名单规则则其值为`''`。

+ `'CC-DENY'`
+ `'WHITE-IPV4'`
+ `'WHITE-IPV6'`
+ `'BLACK-IPV4'`
+ `'BLACK-IPV6'`
+ `'WHITE-URL'`
+ `'BLACK-URL'`
+ `'BLACK-ARGS'`
+ `'BLACK-USER-AGENT'`
+ `'WHITE-REFERER'`
+ `'BLACK-REFERER'`
+ `'BLACK-COOKIE'`
+ `'BLACK-POST'`
+ `'UNDER-ATTACK'`

## `$waf_rule_details`

如果本次请求被本模块拦截，则其值为触发的具体的规则的内容。若没有生效则其值为`''`。