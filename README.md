# ngx_waf

![ngx_waf](https://socialify.git.ci/ADD-SP/ngx_waf/image?description=1&descriptionEditable=A%20web%20application%20firewall%20module%20for%20nginx%20without%20complex%20configuration.&language=1&owner=1&pattern=Brick%20Wall&theme=Light)

[![test](https://github.com/ADD-SP/ngx_waf/workflows/test/badge.svg)](https://github.com/ADD-SP/ngx_waf/actions?query=workflow%3Atest)
[![](https://img.shields.io/badge/nginx-%3E%3D1.18.0-important)](http://nginx.org/en/download.html)
[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/ADD-SP/ngx_waf?include_prereleases)](https://github.com/ADD-SP/ngx_waf/releases)
![GitHub](https://img.shields.io/github/license/ADD-SP/ngx_waf?color=blue)
[![Semantic Versioning 2.0.0](https://img.shields.io/badge/Semantic%20Versioning-2.0.0-blue)](https://semver.org/)

English | [简体中文](README-ZH-CN.md)

A web application firewall module for nginx without complex configuration.

[Progress](https://github.com/ADD-SP/ngx_waf/projects/2) & [Change Log](CHANGES.md)

## Function

+ IPV4 and IPV6 support.
+ Anti Challenge Collapsar, it can automatically block malicious IP.
+ Exceptional allow on specific IP address.
+ Block the specified IP address.
+ Block the specified request body.
+ Exceptional allow on specific URL.
+ Block the specified URL.
+ Block the specified request args.
+ Block the specified UserAgent.
+ Block the specified Cookie.
+ Exceptional allow on specific Referer.
+ Block the specified Referer.

## Install

On Unix Like

### download the source code of nginx

If you want to add a new nginx module, you'll need the nginx source code

```bash
cd /usr/local/src
wget http://nginx.org/download/nginx-1.18.0.tar.gz
tar -zxf nginx-1.18.0.tar.gz
```
> The nginx-1.18.0 source code is recommended, but using a lower version of the nginx source code does not guarantee that this module will work. This module is compatible with the Mainline version of nginx, but since the Mainline version is still under development, there is no guarantee that it will always work. If you encounter compatibility issues, please create an issue.

### download the source code of ngx_waf

```bash
cd /usr/local/src
git clone https://github.com/ADD-SP/ngx_waf.git
cd ngx_waf
```

### compile and install

Starting from nginx-1.9.11, nginx began to support dynamic modules.

Using static modules requires all modules to be compiled into binary files, so adding, deleting and updating modules requires recompiling nginx and replacing the old binary files.

Using dynamic modules only needs to load the `.so` at runtime, without recompiling the entire nginx. Just compile the module into a `.so`, and then edit `nginx.conf` to load the corresponding module.

***

**use static modules**

```bash
cd /usr/local/src/nginx-1.18.0
./configure xxx --add-module=/usr/local/src/ngx_waf
make
```
> If you have already installed nginx, it is recommended to run `nginx -V` to get the compilation parameters, and then replace `xxx` with it.

```bash
nginx -s stop
mv /usr/local/nginx/sbin/nginx /usr/local/nginx/sbin/nginx.old
cp objs/nginx /usr/local/nginx/sbin/nginx
nginx
```

> If you don’t want to stop the nginx service, you can upgrade through hot deployment, see [Official Document](https://nginx.org/en/docs/control.html) for hot deployment method.


If nginx is not installed.

```bash
make install
```

***

**use dynamic modules**

```bash
cd /usr/local/src/nginx-1.18.0
./configure xxx --add-dynamic-module=/usr/local/src/ngx_waf
make modules
```
> If you have already installed nginx, it is recommended to run `nginx -V` to get the compilation parameters, and then replace `xxx` with it.

Now you need to find a directory to store the `.so` file of the module, this doc assumes it is stored under `/usr/local/nginx/modules`

```bash
cp objs/ngx_http_waf_module.so /usr/local/nginx/modules/ngx_http_waf_module.so
```

Then edit `nginx.conf` and add a line at the top.

```text
load_module "/usr/local/nginx/modules/ngx_http_waf_module.so";
```


## How to use?

You should edit nginx.conf as follow.

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

+ syntax: `waf [ on | off ];`
+ default: `off`
+ context: server

Whether to enable this module.

### `waf_rule_path`

+ syntax: `waf_rule_path dir;`
+ default: —
+ context: server

The directory where the rule file is located, must end with `/`.


### `waf_mult_mount`

+ syntax: `waf_mult_mount [ on | off ];`
+ default: `off`
+ context: server

Multi-stage inspection. When address rewriting exists in `nginx.conf` (such as `rewrite`), it is recommended to enable it, otherwise it is recommended to disable it.

### `waf_mode`

+ syntax: `waf_mode mode_type ...;`
+ default: —
+ context: server

Set the working mode of the firewall. Specify at least one mode and specify at most eight modes.

`mode_type` has the following values (not case sensitive):
+ GET: Start the inspection process when `Http.Method=GET`.
+ HEAD: Start the inspection process when `Http.Method=HEAD`.
+ POST: Start the inspection process when `Http.Method=POST`.
+ PUT: Start the inspection process when `Http.Method=PUT`.
+ DELETE: Start the inspection process when `Http.Method=DELETE`.
+ MKCOL: Start the check process when `Http.Method=MKCOL`.
+ COPY: Start the inspection process when `Http.Method=COPY`.
+ MOVE: Start the inspection process when `Http.Method=MOVE`.
+ OPTIONS: Start the inspection process when `Http.Method=OPTIONS`.
+ PROPFIN: Start the inspection process when `Http.Method=PROPFIN`.
+ PROPPATCH: Start the inspection process when `Http.Method=PROPPATCH`.
+ LOCK: Start the inspection process when `Http.Method=LOCK`.
+ UNLOCK: Start the inspection process when `Http.Method=UNLOCK`.
+ PATCH: Start the inspection process when `Http.Method=PATCH`.
+ TRAC: Start the inspection process when `Http.Method=TRAC`.
+ IP: Enable IP address inspecting rules.
+ URL: Enable URL inspecting rules.
+ RBODY: Enable request body inspecting rules.
+ ARGS: Enable ARGS inspecting rules.
+ UA: Enable UA inspecting rules.
+ COOKIE: Enable COOKIE inspecting rules.
+ REFERER: Enable REFERER inspecting rules.
+ CC: Enable 'Anti Challenge Collapsar'.
+ STD: Equivalent to `GET POST CC IP URL ARGS RBODY UA`.
+ FULL: In any case, the inspection process will be started and all inspection rules will be enabled.

> Note: The mode of `CC` is independent of other modes, and whether it takes effect or not is not affected by other modes. A typical situation such as the `URL` mode will be affected by the `GET` mode, because if the `GET` mode is not used, the check will not be started when `Http.Method=GET`, and the URL will naturally not be inspected, but ` CC` mode will not be similarly affected.

### `waf_cc_deny_limit`

+ syntax: `waf_cc_deny_limit rate duration;`
+ default: —
+ context: server

Declare the maximum request rate of the same IP and the blocking time after the rate is exceeded.

`rate`: The maximum number of requests per minute for the same IP.
`duration`: The number of minutes to block after exceeding the `rate`.


### test

```text
https://example.com/www.bak
```

If the http status code is 403, it means this module is working normally.

### Rule file

All regular expressions follow the [PCRE Standard](http://www.pcre.org/current/doc/html/pcre2syntax.html).

+ rules/white-ipv4：IPV4 whitelist, each rule has its own row.Each line can be only one IPV4 address or one CIDR address block. Matching IPV4 addresses are not blocked.
+ rules/ipv4：IPV4 blacklist, each rule has its own line. Each line can only be an IPV4 address or a CIDR address block. Matched IPV4 addresses are blocked and 403 is returned.
+ rules/white-ipv6：IPV6 whitelist, each rule has its own line. Each line can only be an IPV6 address or a string like `fe80::/10`. Matching IPV6 addresses are not blocked.
+ rules/ipv6：IPV6 blacklist, each rule has its own row. Each line can only be an IPV6 address or a string like `fe80::/10`. Matched IPV6 addresses are blocked and 403 is returned.
+ rules/white-url：URL whitelist, each rule has its own line. One regular expression per line, when the URL is matched by any rule, it will be allowed.
+ rules/url：URL blacklist, each rule has its own line. There is a regular expression per line, and 403 is returned when the URL is matched by any rule.
+ rules/args：Request args blacklist, each rule has its own line. There is one regular expression per line, and 403 is returned when the request args is matched by any rule.
+ rules/user-agent：UserAgent blacklist, each rule has its own line. There is one regular expression per line, and 403 is returned when the user-agent is matched by any rule.
+ rules/white-referer：Referer whitelist, each rule has its own line. One regular expression per line, when the referer is matched by any rule, it will be allowed.
+ rules/referer：Referer blacklist, each rule has its own line. There is a regular expression per line, and 403 is returned when the referer is matched by any rule.
+ rules/cookie：Cookie blacklist, each rule has its own line. There is a regular expression per line, and 403 is returned when the cookie is matched by any rule.
+ rules/post：Request body blacklist, each rule has its own line. There is a regular expression per line, and 403 is returned when the request body is matched by any rule.


### Variable

When writing `nginx.conf`, some variables are inevitably needed. For example, `$remote_addr` can be used to get the client IP address.

This module adds three available variables.

+ `$waf_blocked`: Whether this request is intercepted by this module, if intercepted, its value is `'true'`, otherwise it is `'false'`.
+ `$waf_rule_type`：If current request was blocked by this module, this variable is set to the triggered rule type, otherwise `'null'`. The following are possible values.
    + `'BLACK-IPV4'`
    + `'BLACK-URL'`
    + `'BLACK-ARGS'`
    + `'BLACK-USER-AGENT'`
    + `'BLACK-REFERER'`
    + `'BLACK-COOKIE'`
    + `'BLACK-POST'`
+ `'$waf_rule_details'`：If this request is blocked by this module, its value is the content of the specific rule triggered. If it is not blocked, its value is `'null'`.

## Log

The block log is stored in `error.log`. The log level of the block record is ALERT. The basic format is `xxxxx, ngx_waf: [Type][Rule], xxxxx`, see the following example for details.

```text
2020/01/20 22:56:30 [alert] 24289#0: *30 ngx_waf: [BLACK-URL][(?i)(?:/\.env$)], client: 192.168.1.1, server: example.com, request: "GET /v1/.env HTTP/1.1", host: "example.com", referrer: "http:/example.com/v1/.env"

2020/01/20 22:58:40 [alert] 24678#0: *11 ngx_waf: [BLACK-POST][(?i)(?:select.+(?:from|limit))], client: 192.168.1.1, server: example.com, request: "POST /xmlrpc.php HTTP/1.1", host: "example.com", referrer: "https://example.com/"
```

## License

[BSD 3-Clause License](LICENSE)

## Other

+ This project follows [Semantic Versioning 2.0.0](https://semver.org/).
+ [FAQ](https://github.com/ADD-SP/ngx_waf/issues/14)
+ [Known issues](https://github.com/ADD-SP/ngx_waf/issues/1)

## Thanks

+ [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf): Most of the default rules of this module come from this.
+ [nginx-book](https://github.com/taobao/nginx-book): Thanks for the tutorial provided by the author.
+ [nginx-development-guide](https://github.com/baishancloud/nginx-development-guide): Thanks for the tutorial provided by the author.
