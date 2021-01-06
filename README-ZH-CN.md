# ngx_waf

![ngx_waf](https://socialify.git.ci/ADD-SP/ngx_waf/image?description=1&descriptionEditable=%E7%94%A8%E4%BA%8E%20nginx%20%E7%9A%84%E6%B2%A1%E6%9C%89%E5%A4%8D%E6%9D%82%E9%85%8D%E7%BD%AE%E7%9A%84%20Web%20%E5%BA%94%E7%94%A8%E9%98%B2%E7%81%AB%E5%A2%99%E6%A8%A1%E5%9D%97%E3%80%82&language=1&owner=1&pattern=Brick%20Wall&theme=Light)

[![test](https://github.com/ADD-SP/ngx_waf/workflows/test/badge.svg)](https://github.com/ADD-SP/ngx_waf/actions?query=workflow%3Atest)
[![](https://img.shields.io/badge/nginx-%3E%3D1.18.0-important)](http://nginx.org/en/download.html)
[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/ADD-SP/ngx_waf?include_prereleases)](https://github.com/ADD-SP/ngx_waf/releases)
![GitHub](https://img.shields.io/github/license/ADD-SP/ngx_waf?color=blue)
[![讨论](https://img.shields.io/badge/%E8%AE%A8%E8%AE%BA-open-success)](https://github.com/ADD-SP/ngx_waf/discussions)
[![语义化版本 2.0.0](https://img.shields.io/badge/%E8%AF%AD%E4%B9%89%E5%8C%96%E7%89%88%E6%9C%AC-2.0.0-blue)](https://semver.org/lang/zh-CN/)

[English](README.md) | 简体中文

一个用于 nginx 的没有复杂配置的 Web 应用防火墙模块。

[开发进度](https://github.com/ADD-SP/ngx_waf/projects/2) & [更新日志](CHANGES-ZH-CN.md)

## 快捷跳转

+ [功能](#功能)
+ [安装](#安装)
+ [使用](#使用)
+ [规则文件](#规则文件)
+ [变量](#变量)
+ [开发文档](#开发文档)
+ [拦截日志](#日志)
+ [常见问题与解答](https://github.com/ADD-SP/ngx_waf/discussions/15)
+ [已知问题](https://github.com/ADD-SP/ngx_waf/discussions/16)


## 功能

+ 支持 IPV4 和 IPV6。
+ CC 防御，超出限制后自动拉黑对应 IP 一段时间。
+ IP 黑白名单，同时支持类似 `192.168.0.0/16` 和 `fe80::/10`，即支持点分十进制和冒号十六进制表示法和网段划分。
+ POST 黑名单。
+ URL 黑白名单
+ GET 参数黑名单
+ UserAgent 黑名单。
+ Cookie 黑名单。
+ Referer 黑白名单。

## 安装

On Unix Like

### 下载 nginx 源码

nginx 添加新的模块必须要重新编译，所以先[下载 nginx 源码](http://nginx.org/en/download.html)。

```bash
cd /usr/local/src
wget http://nginx.org/download/nginx-version.tar.gz
tar -zxf nginx-version.tar.gz
```

> 推荐使用 nginx-1.18.0 的源码，若使用低版本的 nginx 源码则不保证本模块可以正常使用。本模块对 Mainline 版本的 nginx 做了兼容性处理，但考虑到 Mainline 版本仍在开发中，所以不保证一直可以兼容。如果遇到了兼容性问题请提 issue。

### 下载 ngx-waf 源码

```bash
cd /usr/local/src
git clone https://github.com/ADD-SP/ngx_waf.git
cd ngx_waf
```

### 编译和安装模块

从 nginx-1.9.11 开始，nginx 开始支持动态模块。

静态模块将所有模块编译进一个二进制文件中，所以增删改模块都需要重新编译 nginx 并替换。

动态模块则动态加载 `.so` 文件，无需重新编译整个 nginx。只需要将模块编译成 `.so` 文件然后修改`nginx.conf`即可加载对应的模块。

***

**使用静态模块**

```bash
cd /usr/local/src/nginx-version
./configure xxxxxx --add-module=/usr/local/src/ngx_waf
make
```
> xxxxxx 为其它的编译参数，一般来说是将 xxxxxx 替换为`nginx -V`显示的编译参数。

如果您已经安装了 nginx 则可以直接替换二进制文件（假设原有的二进制文件的全路径为`/usr/local/nginx/sbin/nginx`）

```bash
nginx -s stop
mv /usr/local/nginx/sbin/nginx /usr/local/nginx/sbin/nginx.old
cp objs/nginx /usr/local/nginx/sbin/nginx
nginx
```

> 如果不想中断 nginx 服务则可以通过热部署的方式来实现升级，热部署方法见[官方文档](https://nginx.org/en/docs/control.html)。

如果您之前没有安装则直接执行下列命令
```bash
make install
```

***

**使用动态模块**

```bash
cd /usr/local/src/nginx-version
./configure xxxxxx --add-dynamic-module=/usr/local/src/ngx_waf
make modules
```
> xxxxxx 为其它的编译参数，一般来说是将 xxxxxx 替换为`nginx -V`显示的编译参数。

此时你需要找到一个目录用来存放模块的 .so 文件，本文假设存储在`/usr/local/nginx/modules`下

```bash
cp objs/ngx_http_waf_module.so /usr/local/nginx/modules/ngx_http_waf_module.so
```

然后修改`nginx.conf`，在最顶部添加一行。
```text
load_module "/usr/local/nginx/modules/ngx_http_waf_module.so";
```

## 使用

在需要启用模块的 server 块添加下列配置，例如

```text
http {
    ...
    server {
        ...
        waf on;
        waf_rule_path /usr/local/src/ngx_waf/rules/;
        waf_mode STD;
        waf_cc_deny_limit 1000 60;
        ...
    }
    ...
}

```
### `waf`

+ 配置语法: `waf [ on | off ];`
+ 默认值：`off`
+ 配置段: server

是否启用本模块。

### `waf_rule_path`

+ 配置语法: `waf_rule_path dir;`
+ 默认值：无
+ 配置段: server

规则文件所在目录，且必须以`/`结尾。


### `waf_mult_mount`

+ 配置语法: `waf_mult_mount [ on | off ];`
+ 默认值：`off`
+ 配置段: server

进行多阶段检查，当`nginx.conf`存在地址重写的情况下（如`rewrite`配置）建议启用，反之建议关闭。


### `waf_mode`

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

### `waf_cc_deny_limit`

+ 配置语法: `waf_cc_deny_limit rate duration;`
+ 默认值：无
+ 配置段: server

包含两个参数，第一个参数`rate`表示每分钟的最多请求次数（大于零的整数），第二个参数`duration`表示超出第一个参数`rate`的限制后拉黑 IP 多少分钟（大于零的整数）。

### 测试

```text
https://example.com/www.bak
```

如果返回 403 则表示安装成功。

## 规则文件

规则中的正则表达式均遵循[PCRE 标准](http://www.pcre.org/current/doc/html/pcre2syntax.html)。


+ rules/ipv4：IPV4 黑名单，每条规则独占一行。每行只能是一个由点分十进制表示的 IPV4 地址，允许通过类似 `192.168.0.0/16` 的方式划分网段。拦截匹配到的 IP 并返回 403。
+ rules/ipv6：IPV6 黑名单，每条规则独占一行。每行只能是一个由冒号十六进制表示的 IPV6 地址，通过类似 `fe80::/10` 的方式划分网段。拦截匹配到的 IP 并返回 403。
+ rules/url：URL 黑名单，每条规则独占一行。每行一个正则表达式，当 URL 被任意一个规则匹配到就返回 403。
+ rules/args：GET 参数黑名单，每条规则独占一行。每行一个正则表达式，当 GET 参数（如test=0&test1=）被任意一个规则匹配到就返回 403。
+ rules/referer：Referer 黑名单，每条规则独占一行。每行一个正则表达式，当 referer 被任意一个规则匹配到就返回 403。
+ rules/user-agent：UserAgent 黑名单，每条规则独占一行。每行一个正则表达式，当 user-agent 被任意一个规则匹配到就返回 403。
+ rules/cookie：Cookie 黑名单，每条规则独占一行。每行一个正则表达式，当 Cookie 中的内容被任意一个规则匹配到就返回 403。
+ rules/post：POST 黑名单，每条规则独占一行。每行一个正则表达式，当请求体中的内容被任意一个规则匹配到就返回 403。
+ rules/white-ipv4：IPV4 白名单，写法同`rules/ipv4`。
+ rules/white-ipv6：IPV6 白名单，写法同`rules/ipv6`。
+ rules/white-url：URL 白名单。写法同`rules/url`。
+ rules/white-referer：Referer 白名单。写法同`rules/referer`。



## 变量

在书写 nginx.conf 文件的时候不可避免地需要用到一些变量，如`$remote_addr`可以用来获取客户端 IP 地址。

本模块增加了三个可用的变量。

+ `$waf_blocked`: 本次请求是否被本模块拦截，如果拦截了则其的值为`'true'`,反之则为`'false'`。
+ `$waf_rule_type`：如果本次请求被本模块拦截，则其值为触发的规则类型。下面是可能的取值。若没有生效则其值为`'null'`。
    + `'BLACK-IPV4'`
    + `'BLACK-URL'`
    + `'BLACK-ARGS'`
    + `'BLACK-USER-AGENT'`
    + `'BLACK-REFERER'`
    + `'BLACK-COOKIE'`
    + `'BLACK-POST'`
+ `'$waf_rule_details'`：如果本次请求被本模块拦截，则其值为触发的具体的规则的内容。若没有生效则其值为`'null'`。

## 日志

拦截日志日志存储在 error.log 中。拦截记录的日志等级为 ALERT。基本格式为`xxxxx, ngx_waf: [拦截类型][对应规则], xxxxx`，具体可看下面的例子。

```text
2020/01/20 22:56:30 [alert] 24289#0: *30 ngx_waf: [BLACK-URL][(?i)(?:/\.env$)], client: 192.168.1.1, server: example.com, request: "GET /v1/.env HTTP/1.1", host: "example.com", referrer: "http:/example.com/v1/.env"

2020/01/20 22:58:40 [alert] 24678#0: *11 ngx_waf: [BLACK-POST][(?i)(?:select.+(?:from|limit))], client: 192.168.1.1, server: example.com, request: "POST /xmlrpc.php HTTP/1.1", host: "example.com", referrer: "https://example.com/"
```

## 开发文档

### 安装依赖

请确保已经安装 `doxygen` 和 `graphviz`，且 `doxygen` 的版本至少要为 1.8.17。

### 生成文档

```bash
./mkdocs.sh
```

在 `docs/ZH-CN/html` 目录下会生成开发文档。你可以直接用浏览器打开 `docs/ZH-CN/html/index.html` 文件来浏览文档。

## 开源许可证

[BSD 3-Clause License](LICENSE)

## 其它

+ 本项目遵循 [语义化版本 2.0.0](https://semver.org/lang/zh-CN/)
+ [常见问题与解答](https://github.com/ADD-SP/ngx_waf/discussions/15)
+ [已知问题](https://github.com/ADD-SP/ngx_waf/discussions/16)
+ [开发总结](https://www.addesp.com/archives/2876)

## 感谢

+ [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf): 本模块的默认规则大多来自于此。
+ [nginx-book](https://github.com/taobao/nginx-book): 感谢作者提供的教程。
+ [nginx-development-guide](https://github.com/baishancloud/nginx-development-guide): 感谢作者提供的教程。
