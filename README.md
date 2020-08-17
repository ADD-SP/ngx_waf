# ngx_waf

用于 nginx 的防火墙模块。

**本模块目前还在测试，稳定性可能不佳。**

## 功能

+ CC 防御，超出限制后自动拉黑一段时间。
+ IPV4 黑白名单，支持 CIDR 表示法。
+ POST 黑名单。
+ URL 黑白名单
+ GET 参数黑名单
+ UserAgent 黑名单。
+ Cookie 黑名单。
+ Referer 黑白名单。

[更新日志](CHANGES.md)

## 安装

### On Unix Like

#### 下载 nginx 源码

nginx 添加新的模块必须要重新编译，所以先[下载 nginx 源码](http://nginx.org/en/download.html)。

> 推荐 1.18.0 版本的 nginx 源码，若使用低版本的 nginx 源码则不保证本模块可以正常使用。

#### 下载 ngx-waf 源码

```bash
cd /usr/local/src
git clone https://github.com/ADD-SP/ngx_waf.git
cd ngx_waf
git clone -b v2.1.0 https://github.com/troydhanson/uthash.git inc/uthash
```

#### 编译 nginx

进入 nginx 源代码目录

```bash
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

#### 修改 nginx.conf

在需要启用模块的 server 块添加两行，例如

```text
http {
    ngx_waf_mult_mount off;
    ...
    server {
        ...
        ngx_waf on;
        ngx_waf_rule_path /usr/local/src/ngx_waf/rules/;
        ngx_waf_cc_deny on;
        ngx_waf_cc_deny_limit 1000 60;
        ...
    }
    ...
}

```

> ngx_waf_mult_mount 当`nginx.conf`存在地址重写的情况下（如`rewrite`配置）建议启用，反之建议关闭。

> ngx_waf 表示是否启用模块。

> ngx_waf_rule_path 表示规则文件所在的文件夹，且必须以`/`结尾。

> ngx_waf_cc_deny 表示是否启用 CC 防御。

> ngx_waf_cc_deny_limit 包含两个参数，第一个参数表示每分钟的最多请求次数（大于零的整数），第二个参数表示超出第一个参数的限制后拉黑 IP 多少分钟（大于零的整数）。

#### 测试

```text
https://example.com/www.bak
```

如果返回 403 则表示安装成功。

## 规则文件

规则中的正则表达式均遵循[PCRE 标准](http://www.pcre.org/current/doc/html/pcre2syntax.html)。

规则生效顺序（靠上的优先生效）

1. IP 白名单
2. IP 黑名单
3. CC 防御
4. URL 白名单
5. URL 黑名单
6. Args 黑名单
7. UserAgent 黑名单
8. Referer 白名单
9. Referer 黑名单
10. Cookie 黑名单
11. POST 黑名单


+ rules/ipv4：IPV4 黑名单，每条规则独占一行。每行只能是一个 IPV4 地址或者一个 CIDR 地址块。拦截匹配到的 IP 并返回 403。
+ rules/url：URL 黑名单，每条规则独占一行。每行一个正则表达式，当 URL 被任意一个规则匹配到就返回 403。
+ rules/args：GET 参数黑名单，每条规则独占一行。每行一个正则表达式，当 GET 参数（如test=0&test1=）被任意一个规则匹配到就返回 403。
+ rules/referer：Referer 黑名单，每条规则独占一行。每行一个正则表达式，当 referer 被任意一个规则匹配到就返回 403。
+ rules/user-agent：UserAgent 黑名单，每条规则独占一行。每行一个正则表达式，当 user-agent 被任意一个规则匹配到就返回 403。
+ rules/post：POST 黑名单，每条规则独占一行。每行一个正则表达式，当请求体中的内容被任意一个规则匹配到就返回 403。
+ rules/white-ipv4：IPV4 白名单，写法同`rules/ipv4`。
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

## 常见问题

### 为什么有一段时间请求速度会变慢

可能是因为开启了 CC 防御功能，详情见[性能-内存管理](#性能-内存管理)。

### 为什么 POST 过滤失效？

本模块出于性能原因在检查请求体内容的之前会检测其是否在内存中，如果在则正常检查，反之跳过检查。可以尝试修改`nginx.conf`

```text
http {
    ...
    # 当请求体不大于这个数值时会将其写入内存，反之则写入临时文件。
    client_body_buffer_size: 10M;
    # 是否总是将请求体保存在临时文件中
    client_body_in_file_only: off;
    ...
}
```

### fork() failed while spawning "worker process" (12: Cannot allocate memory)

可能是过多地使用`nginx -s reload`导致的，本模块会在读取配置的时候申请一些内存，但是不知为何`nginx -s reload`之后这些内存不会立即释放，所以短时间内频繁`nginx -s reload`就极可能导致这个错误。

## 性能

### 内存管理
<span id='性能-内存管理'></span>
本模块在启用了 CC 防御功能时会周期性地释放一次内存和申请一次内存，但是并不会一次性全部释放，而是逐步释放，每次请求释放一小部分，逐渐地完成释放，期间会小幅度拖慢处理时间。

## 感谢

+ [uthash](https://github.com/troydhanson/uthash): 本项目使用了版本为 v2.1.0 的 uthash 的源代码。uthash 源代码以及开源许可位于`inc/uthash/`。
+ [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf): 本模块的默认规则大多来自于此。
+ [nginx-book](https://github.com/taobao/nginx-book): 感谢作者提供的教程。
+ [nginx-development-guide](https://github.com/baishancloud/nginx-development-guide): 感谢作者提供的教程。
