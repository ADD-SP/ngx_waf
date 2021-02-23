---
title: 配置语法
lang: zh-CN
---

# 配置语法

## `waf`

+ 配置语法: `waf [ on | off ];`
+ 默认值：`off`
+ 配置段: server

是否启用本模块。

## `waf_rule_path`

+ 配置语法: `waf_rule_path dir;`
+ 默认值：无
+ 配置段: server

规则文件所在目录，且必须以`/`结尾。


## `waf_mult_mount`

+ 配置语法: `waf_mult_mount [ on | off ];`
+ 默认值：`off`
+ 配置段: server

进行多阶段检查，当`nginx.conf`存在地址重写的情况下（如`rewrite`配置）建议启用，反之建议关闭。

本配置用于兼容 [ngx_http_rewrite_module](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html) 
模块，详见[模块兼容性](/zh-cn/guide/compatibility.md#ngx_http_rewrite_module)。

::: warning 警告

并不保证此配置可以完全解决兼容性问题，建议启用后进行测试。

:::


## `waf_mode`

+ 配置语法: `waf_mode mode_type ...;`
+ 默认值: 无
+ 配置段: server

指定防火墙的工作模式，至少指定一个模式，最多指定八个模式。

`mode_type`具有下列取值（不区分大小写）:
+ GET: 当`Http.Method=GET`时启动检查。
+ HEAD: 当`Http.Method=HEAD`时启动检查。
+ POST: 当`Http.Method=POST`时启动检查。
+ PUT: 当`Http.Method=PUT`时启动检查。
+ DELETE: 当`Http.Method=DELETE`时启动检查。
+ MKCOL: 当`Http.Method=MKCOL`时启动检查。
+ COPY: 当`Http.Method=COPY`时启动检查。
+ MOVE: 当`Http.Method=MOVE`时启动检查。
+ OPTIONS: 当`Http.Method=OPTIONS`时启动检查。
+ PROPFIN: 当`Http.Method=PROPFIN`时启动检查。
+ PROPPATCH: 当`Http.Method=PROPPATCH`时启动检查。
+ LOCK: 当`Http.Method=LOCK`时启动检查。
+ UNLOCK: 当`Http.Method=UNLOCK`时启动检查。
+ PATCH: 当`Http.Method=PATCH`时启动检查。
+ TRAC: 当`Http.Method=TRAC`时启动检查。
+ IP: 启用 IP 地址的检查规则。
+ URL: 启用 url 的检查规则。
+ RBODY: 启用请求体的检查规则。
+ ARGS: 启用 args 的检查规则。
+ UA: 启用 user-agent 的检查规则。
+ COOKIE: 启用 cookie 的检查规则。
+ REFERER: 启用 referer 的检查规则。
+ CC: 启用 CC 防御。
+ STD: 等价于 `GET POST CC IP URL ARGS RBODY UA`。
+ FULL: 任何情况下都会启动检查并启用所有的检查规则。

> 注意: `CC`是独立于其它模式的模式，其生效与否不受到其它模式的影响。典型情况如`URL`模式会受到`GET`模式的影响，因为如果不使用`GET`模式，那么在收到`GET`请求时就不会启动检查，自然也就不会检查 URL，但是`CC`模式不会受到类似的影响。

## `waf_cc_deny_limit`

+ 配置语法: `waf_cc_deny_limit rate duration;`
+ 默认值：无
+ 配置段: server

包含两个参数，第一个参数`rate`表示每分钟的最多请求次数（大于零的整数），第二个参数`duration`表示超出第一个参数`rate`的限制后拉黑 IP 多少分钟（大于零的整数）。
