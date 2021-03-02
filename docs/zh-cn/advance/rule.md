---
title: 规则说明
lang: zh-CN
---

# 规则说明

本模块使用下列几种配置文件，所有的配置文件必须在同一目录下并保证 nginx 对其有读取权限。

* IP 白名单，文件名为 `white-ipv4` 和 `white-ipv6`。
* IP 黑名单，文件名为 `ipv4` 和 `ipv6`。
* Url 白名单，文件名为 `white-url`。
* Url 黑名单，文件名为 `url`。
* Get 参数黑名单，文件名为 `args`。
* Post 请求体黑名单，文件名为 `post`。
* UserAgent 黑名单，文件名为 `user-agent`。
* Cookie 黑名单，文件名为 `cookie`。
* Referer 白名单，文件名为 `white-referer`。
* Referer 黑名单，文件名为 `referer`。

::: tip 注意

有些规则文件需要书写正则表达式，书写时每行一个正则表达式，
正则表达式遵循 [PCRE 标准](http://www.pcre.org/current/doc/html/pcre2syntax.html)。

:::

## ip白名单

ip 白名单包括下面两个文件。

* ipv4 白名单，文件名为 `white-ipv4`。
* ipv6 白名单，文件名为 `white-ipv6`。

书写时一行指定一个 IP 地址或者 IP 地址块。ipv4 地址必须使用「点分十进制表示法」，
ipv6 地址必须使用 「冒号十六进制表示法」。下面举一些例子。

指定单个 ipv4 地址。

```
192.168.2.1
```

指定一个 ipv4 地址块。

```
192.168.2.0/24
```

指定单个 ipv6 地址。

```
FE80::1000
```

指定一个 ipv6 地址块。

```
FE80::/10
```

## IP黑名单

IP 黑名单包括下面两个文件。

* ipv4 黑名单，文件名为 `ipv4`。
* ipv6 黑名单，文件名为 `ipv6`。

写法同 [ip 白名单](#ip白名单)。

## url白名单

Url 白名单的文件名为 `white-url`，书写规则时每行指定一个正则表达式，
Url 被任何一个正则表达式匹配到就会直接放行，不进行后续的检查。

## url黑名单

Url 黑名单的文件名为 `url`，书写规则时每行指定一个正则表达式，
Url 被任何一个正则表达式匹配到就会被拦截，返回 403 状态码。

## get参数黑名单

Get 参数黑名单的文件名为 `args`，书写规则时每行指定一个正则表达式，
Get 参数被任何一个正则表达式匹配到就会被拦截，返回 403 状态码。

## post请求体黑名单

Post 请求体黑名单的文件名为 `post`，书写规则时每行指定一个正则表达式，
Post 请求体内的内容被任何一个正则表达式匹配到就会被拦截，返回 403 状态码。

::: warning 警告

有时本模块不会执行 Post 请求体检查，详见[常见问题与解答](/zh-cn/guide/faq.md#post检测失效)。

:::

## user-agent黑名单

UserAgent 黑名单的文件名为 `user-agent`，书写规则时每行指定一个正则表达式，
UserAgent 被任何一个正则表达式匹配到就会被拦截，返回 403 状态码。

## cookie黑名单

Cookie 黑名单的文件名为 `cookie`，书写规则时每行指定一个正则表达式，
Cookie 被任何一个正则表达式匹配到就会被拦截，返回 403 状态码。

## referer白名单

Referer 白名单的文件名为 `white-referer`，书写规则时每行指定一个正则表达式，
Referer 被任何一个正则表达式匹配到就会直接放行，不进行后续的检查。

## referer黑名单

Referer 黑名单的文件名为 `referer`，书写规则时每行指定一个正则表达式，
Referer 被任何一个正则表达式匹配到就会被拦截，返回 403 状态码。