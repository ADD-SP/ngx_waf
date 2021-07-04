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
* 高级规则，文件名为 `advaced`。

::: tip 注意

有些规则文件需要书写正则表达式，书写时每行一个正则表达式，
正则表达式遵循 [PCRE 标准](http://www.pcre.org/current/doc/html/pcre2syntax.html)。

:::


::: tip 注意

高级规则仅在开发版中可用。

:::

## 基础规则

### ip白名单

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

### IP黑名单

IP 黑名单包括下面两个文件。

* ipv4 黑名单，文件名为 `ipv4`。
* ipv6 黑名单，文件名为 `ipv6`。

写法同 [ip 白名单](#ip白名单)。

### url白名单

Url 白名单的文件名为 `white-url`，书写规则时每行指定一个正则表达式，
Url 被任何一个正则表达式匹配到就会直接放行，不进行后续的检查。

### url黑名单

Url 黑名单的文件名为 `url`，书写规则时每行指定一个正则表达式，
Url 被任何一个正则表达式匹配到就会被拦截，返回 403 状态码。

### get参数黑名单

Get 参数黑名单的文件名为 `args`，书写规则时每行指定一个正则表达式，
Get 参数被任何一个正则表达式匹配到就会被拦截，返回 403 状态码。

### post请求体黑名单

Post 请求体黑名单的文件名为 `post`，书写规则时每行指定一个正则表达式，
Post 请求体内的内容被任何一个正则表达式匹配到就会被拦截，返回 403 状态码。

::: warning 警告

有时本模块不会执行 Post 请求体检查，详见[常见问题与解答](/zh-cn/guide/faq.md#post检测失效)。

:::

### user-agent黑名单

UserAgent 黑名单的文件名为 `user-agent`，书写规则时每行指定一个正则表达式，
UserAgent 被任何一个正则表达式匹配到就会被拦截，返回 403 状态码。

### cookie黑名单

Cookie 黑名单的文件名为 `cookie`，书写规则时每行指定一个正则表达式，
Cookie 被任何一个正则表达式匹配到就会被拦截，返回 403 状态码。

### referer白名单

Referer 白名单的文件名为 `white-referer`，书写规则时每行指定一个正则表达式，
Referer 被任何一个正则表达式匹配到就会直接放行，不进行后续的检查。

### referer黑名单

Referer 黑名单的文件名为 `referer`，书写规则时每行指定一个正则表达式，
Referer 被任何一个正则表达式匹配到就会被拦截，返回 403 状态码。

## 高级规则

### 概述

高级规则是一种将条件表达式和动作组合起来的规则，只有满足指定的条件时才会执行对应的动作。高级规则更加灵活，但是也更加消耗性能。


::: tip 注意

高级规则的性能较慢，因为其原理是将规则编译成一系列指令，然后由虚拟机执行。

:::

### 示例

下面的例子表示如果 `url` 中包含 `/install` 则返回 HTTP 403 状态码。

```
id: example
if: url contains '/install'
do: return(403)
```

***

下面的例子表示如果 `user-agent` 中不包含 `secret` 则返回 HTTP 403 状态码。

```
id: example
if: user-agent not equals 'secret'
do: return(403)
```

***

下面的例子表示如果 `url` 能够正则表达式 `^/admin` 所匹配，或者 `user-agent` 等于 `secret` 则停止后续的所有检测并放行本次请求。

```
id: example
if: url matches '^/admin' or user-agent equals 'secret'
do: allow
```

***

下面的例子表示如果查询字符串中的参数 `user_id` 的内容被检测出 SQL 注入则返回 HTTP 403 状态码。

```
id: example
if: sqli_detn(query_string[user_id])
do: return(403)
```

***

下面的例子表示如果客户端发送的请求头中 `X-Passwod` 的值不等于 `password` 则返回 HTTP 403 状态码。

```
id: example
if: header_in[X-Passwod] not equals 'password'
do: return(403)
```

### 语法

```
id: example
if: condition
do: action

id: example
if: condition
do: action
```

多条规则之间必须间隔一行，并且只能间隔一行。
最后一条规则的末尾不能有任何字符。

* id：每条规则都有一个唯一的 ID，这个 ID 会在规则生效时记录在日志中。每条规则只能有一个 ID，不同规则可以有相同的 ID。
* if：如果 `condition` 为真则执行 `action`。
* do：当 `condition` 为真则时执行 `action`。


::: tip 注意

所有的关键字均大小写不敏感。

:::

### Condition

`condition`是一系列条件表达式的组合，条件表达式由运算符符和运算数组成。

* 字符串运算符
    * equals
        * 格式：`left equals right`。
        * 功能：如果左右两个字符串相等则为真，反之为假。
    * contains
        * 格式：`left contains right`。
        * 功能：如果 `right` 是 `left` 的一个子串则为真，反之为假。
    * matches
        * 格式：`str matches regexp`。
        * 功能：如果 `str` 能被正则表达式 `regexp` 所匹配则为真，反之为假。
        * 注意：如果 `regexp` 不是合法的正则表达式则为假。
    * sqli_detn
        * 格式：`sqli_detn(str)`。
        * 功能：如果 `str` 中是否存在 SQL 注入则为真，反之为假。
    * xss_detn
        * 格式：`xss_detn(str)`。
        * 功能：如果 `str` 中存在 XSS 攻击则为真，反之为假。

::: tip 注意

* `detn` 是 `detection` 的缩写。
* `sqli` 是 `SQL injection` 的缩写。

:::

* IP 运算符：
    * equals
        * 格式：`client_ip equals str`。
        * 功能：如果 `str` 所表示的 IP 与 `client_ip` 相同则为真，反之为假。
        * 注意
            * `str` 是一个点分十进制或冒号十六进制表示的 IP 字符串，如果格式错误则为假。
            * 当左右两个运算数的 IP 类型不一致时为假。
            * `client_ip` 是关键字，表示客户端的 IP 地址。
    * belong_to
        * 格式：`client_ip belong_to str`。
        * 功能：如果 `str` 所表示的 IP 地址块包含 `client_ip` 则为真，反之为假。
        * 注意
            * `str` 是一个点分十进制或冒号十六进制表示的 IP 字符串，如果格式错误则为假。
            * 当左右两个运算数的 IP 类型不一致时为假。
            * `client_ip` 是关键字，表示客户端的 IP 地址。

* 逻辑运算符
    * and
        * 格式：`condition and condition`。
        * 功能：逻辑与。
    * or
        * 格式：`condition or condition`。
        * 功能：逻辑或。
    * not
        * 格式
            * `not operator`。
            * `not (condition)`。
        * 功能：逻辑非。
        * 示例
            * `not equals`。
            * `not belong_to`。

* 其它运算符
    * ()
        * 格式：`(condition)`
        * 功能：括号运算符，用来改变优先级，功能类似数学中的括号。

### Action

`Action` 是在 `if` 条件满足后执行的动作。

* return
    * 格式：`return(http_status)`。
    * 功能：立即停止所有的检测并返回指定的 HTTP 状态码。
    * 示例：`return(403)`。
* allow
    * 格式：`allow`
    * 功能：立即停止所有的检测并放行本次请求。


### 其它关键字

#### 字符串类型

* url：如果用户请求 `http(s)://localhost/index.html?smth=smth`，则值为`index.html`。
* query_string\[*key*\]：如果用户请求 `http(s)://localhost/index.html?key=one&ex=two` ，则值为 `one`。
* user-agent: 你知道的，就是 `user-agent`。
* referer：你知道的，就是 `referer`。
* cookie\[*key*\]：如果 Cookie 为 `key=one&ex=two` 则值为 `one`。
* header_in\[*key*\]：表示请求头中对应字段的值。

#### IP 类型

* client_ip：表示客户端的 IP 地址。

