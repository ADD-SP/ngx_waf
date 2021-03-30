---
title: Configuration syntax
lang: en
---

# Configuration syntax

## `waf`

* syntax: `waf <on|off>;`
* default: `waf off;`
* context: server

Whether to enable this module.

## `waf_rule_path`

* syntax: `waf_rule_path <dir>;`
* default: —
* context: server

The absolute path to the directory where the rule file is located, and must end with `/`.

## `waf_mode`

* syntax: `waf_mode <mode_type> ...;`
* default: —
* context: server

Specify the working mode of the firewall, specifying at least one mode and up to eight modes.

`mode_type` has the following values (not case sensitive):
* GET: Start the inspection process when `Http.Method=GET`.
* HEAD: Start the inspection process when `Http.Method=HEAD`.
* POST: Start the inspection process when `Http.Method=POST`.
* PUT: Start the inspection process when `Http.Method=PUT`.
* DELETE: Start the inspection process when `Http.Method=DELETE`.
* MKCOL: Start the check process when `Http.Method=MKCOL`.
* COPY: Start the inspection process when `Http.Method=COPY`.
* MOVE: Start the inspection process when `Http.Method=MOVE`.
* OPTIONS: Start the inspection process when `Http.Method=OPTIONS`.
* PROPFIN: Start the inspection process when `Http.Method=PROPFIN`.
* PROPPATCH: Start the inspection process when `Http.Method=PROPPATCH`.
* LOCK: Start the inspection process when `Http.Method=LOCK`.
* UNLOCK: Start the inspection process when `Http.Method=UNLOCK`.
* PATCH: Start the inspection process when `Http.Method=PATCH`.
* TRAC: Start the inspection process when `Http.Method=TRAC`.
* IP: Enable IP address inspecting rules.
* URL: Enable URL inspecting rules.
* RBODY: Enable request body inspecting rules.
* ARGS: Enable ARGS inspecting rules.
* UA: Enable UA inspecting rules.
* COOKIE: Enable COOKIE inspecting rules.
* REFERER: Enable REFERER inspecting rules.
* CC: Enable 'Anti Challenge Collapsar'.
* COMPAT: compatibility mode, used to enable compatibility options with other modules or environments, currently used for compatibility with the ngx_http_rewrite_module, see [compatibility statement](/guide/compatibility.md).
* STRICT: Strict mode, which sacrifices some performance for more checks, currently only works when `COMPAT` mode is enabled, and performs a full round of inspections before and after the ngx_http_rewrite_module takes effect.
* STATIC: working mode for static sites, equivalent to `HEAD GET IP URL UA CC`.
* DYNAMIC: working mode for dynamic sites, equivalent to `HEAD GET POST IP URL ARGS UA RB COOKIE CC`.
* STD: Equivalent to `IP URL RB ARGS UA HEAD GET POST CC COMPAT`.
* FULL: In any case, the inspection process will be started and all inspection rules will be enabled.

You can turn off a mode by prefixing a `mode_type` with `! ` prefix to a `mode_type` to turn it off. 
The following is an example of using the standard working mode, but without inspecting the User-Agent.

```nginx
waf_mode STD !UA;
```

::: tip NOTE

The mode of `CC` is independent of other modes, and whether it takes effect or not is not affected by other modes. A typical situation such as the `URL` mode will be affected by the `GET` mode, because if the `GET` mode is not used, the check will not be started when `Http.Method=GET`, and the URL will naturally not be inspected, but ` CC` mode will not be similarly affected.

:::


## `waf_cc_deny_limit`

* syntax: `waf_cc_deny_limit <rate> <duration> [buffer_size]`;
* default: `waf_cc_deny_limit 10000000 1 10m;`
* context: server

Set the parameters related to CC protection.

* `rate`:Indicates the maximum number of requests per minute (an integer greater than zero).
* `duration`:Indicates how many minutes (an integer greater than zero) to pull the IP after exceeding the limit of the first parameter `rate`.
* `buffer_size`: used to set the size of the memory for recording IP accesses, such as `10m`, `10240k`, must not be less than `10m`, if not specified then the default is `10m`.


