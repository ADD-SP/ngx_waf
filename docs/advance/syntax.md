---
title: Configuration syntax
lang: en
---

# Configuration syntax

## `waf`

+ syntax: `waf [ on | off ];`
+ default: `off`
+ context: server

Whether to enable this module.

## `waf_rule_path`

+ syntax: `waf_rule_path dir;`
+ default: —
+ context: server

The absolute path to the directory where the rule file is located, and must end with `/`.


## `waf_mult_mount`

+ syntax: `waf_mult_mount [ on | off ];`
+ default`off`
+ context: server

Perform a multi-stage check, when `nginx.conf` exists address rewriting (such as `rewrite` directive) is recommended to enable, and vice versa is recommended to disable.


This configuration is used for compatibility with the 
[ngx_http_rewrite_module](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html) 
module, see [module compatibility](guide/compatibility#ngx_http_rewrite_module) for details.

::: warning WARNING

There is no guarantee that this configuration will completely resolve compatibility issues, 
and it is recommended to test it after enabling it.

:::


## `waf_mode`

+ syntax: `waf_mode mode_type ...;`
+ default: —
+ context: server

Specify the working mode of the firewall, specifying at least one mode and up to eight modes.

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

## `waf_cc_deny_limit`

+ syntax: `waf_cc_deny_limit rate duration;`
+ default: —
+ context: server

Declare the maximum request rate of the same IP and the blocking time after the rate is exceeded.

`rate`: The maximum number of requests per minute for the same IP.
`duration`: The number of minutes to block after exceeding the `rate`.