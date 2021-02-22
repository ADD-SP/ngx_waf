---
title: 内置变量
lang: zh-CN
---

# 内置变量

在书写 nginx.conf 文件的时候不可避免地需要用到一些变量，如`$remote_addr`可以用来获取客户端 IP 地址。

本模块增加了三个可用的变量。

## `waf_blocked`

表示本次请求是否被本模块拦截，如果拦截了则其的值为`'true'`,反之则为`'false'`。

## `waf_rule_type`

如果本次请求被本模块拦截，则其值为触发的规则类型。下面是可能的取值。若没有生效则其值为`'null'`。

+ `'BLACK-IPV4'`
+ `'BLACK-IPV6'`
+ `'BLACK-URL'`
+ `'BLACK-ARGS'`
+ `'BLACK-USER-AGENT'`
+ `'BLACK-REFERER'`
+ `'BLACK-COOKIE'`
+ `'BLACK-POST'`

## `waf_rule_details`

如果本次请求被本模块拦截，则其值为触发的具体的规则的内容。若没有生效则其值为`'null'`。