---
title: Directive
lang: en
---

# Directive

## `waf`

* syntax: waf \<*on* | *off*\>
* default: waf *off*
* context: http, server, location

Whether to enable this module.

## `waf_rule_path`

* syntax: waf_rule_path \<*dir*\>
* default: —
* context: http, server, location

The absolute path to the directory where the rule file is located, and must end with `/`.

## `waf_mode`

* syntax: waf_mode \<*mode_type*\> ...
* default: —
* context: http, server, location

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
* CMN-METH: Equivalent to `HEAD GET POST`.
* ALL-METH: Any HTTP request method will start the inspection process.
* IP: Enable IP address inspecting rules.
* URL: Enable URL inspecting rules.
* RBODY: Enable POST request body inspecting rules.
* ARGS: Enable ARGS inspecting rules.
* UA: Enable UA inspecting rules.
* COOKIE: Enable COOKIE inspecting rules.
* REFERER: Enable REFERER inspecting rules.
* CC: Enable 'Anti Challenge Collapsar'. **When you enable this mode, you must set [waf_cc_deny](#waf-cc-deny)**.
* ADV: Enable the advanced rules.
* LIB-INJECTION-SQLI: Use [libinjection](https://github.com/libinjection/libinjection) to detect SQL injection.
* LIB-INJECTION-XSS: Use [libinjection](https://github.com/libinjection/libinjection) to detect XSS attacks.
* LIB-INJECTION: Equivalent to `LIB-INJECTION-SQLI LIB-INJECTION-XSS`.
* CACHE: Enable caching. Enabling this mode will cache the result of the inspection, so that the next time the same target is inspected, there is no need to repeat the inspection. However, the results of the POST body inspection are not cached. For example, if a URL is not in the blacklist after inspection, the next time the same URL is inspected, the cache can be read directly. **When you enable this mode, you must set [waf_cache](#waf-cache)**.
* STD: Standard working mode, equivalent to `HEAD GET POST IP URL RBODY ARGS UA CC CACHE LIB-INJECTION-SQLI`.
* STATIC: working mode for static sites, equivalent to `HEAD GET IP URL UA CC CACHE`.
* DYNAMIC: working mode for dynamic sites, equivalent to `HEAD GET POST IP URL ARGS UA RBODY COOKIE CC CACHE LIB-INJECTION-SQLI`.
* FULL: Enable all modes.

You can turn off a mode by prefixing `mode_type` with the prefix `!` to turn off a mode.
The following is an example of using the standard working mode, but without inspecting the User-Agent.

```nginx
waf_mode STD !UA;
```

::: warning NOTE

If two or more conflicting modes are enabled at the same time, the mode to the right will override the mode to its left. The following example means inspecting the User-Agent.

```nginx
waf_mode !UA STD;
```

:::

::: tip NOTE

The mode of `CC` is independent of other modes, and whether it takes effect or not is not affected by other modes. A typical situation such as the `URL` mode will be affected by the `GET` mode, because if the `GET` mode is not used, the check will not be started when `Http.Method=GET`, and the URL will naturally not be inspected, but ` CC` mode will not be similarly affected.

:::

## `waf_cc_deny`

* syntax: waf_cc_deny \<rate=*n*r/m\> \[duration=*1h*\] \[size=*20m*\]
* default: —
* context: http, server, location

Set the parameters related to CC protection.

* `rate`: Indicates the maximum number of requests per minute, e.g. `60r/m` means the maximum number of requests per minute is 60. Exceeding the limit returns a [503 status code](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/503) with a [Retry-After](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After) response header.
* `duration`: Indicates the time to block IP after exceeding the limit of the first parameter `rate`, such as `60s`, `60m`, `60h` and `60d`, if not specified, the default is `1h`.
* `size`: Used to set the size of the memory for recording IP accesses, such as `20m`, `2048k`, must not be less than `20m`, if not specified, the default is `20m`. When this memory is exhausted, the program will automatically reset this memory to recount the IP accesses.


::: tip CHANGES IN 'Current' VERSION

It is not allowed to use this directive in the context `http`.

:::


## `waf_cache`

* syntax: waf_cache \<capacity=*n*\>
* default: —
* context: http, server, location

Set the parameters related to cache rule inspection results.

* `capacity`: For some inspection items with caching mechanism enabled, the maximum number of inspection results per inspection item to be cached for each inspection target.


::: tip Cache-enabled inspections

Cache-enabled inspections refer to all inspections except CC protection, I
P black and white list inspection, and POST inspection.

:::


::: tip Performance optimization suggestions

Too small a `capacity` will result in frequent cache cleanups, 
increasing memory fragmentation and reducing performance. 
So please set it reasonably according to your actual needs.

:::


## `waf_under_attack`

* syntax: waf_under_attack \<*on* | *off*\> \[uri=*str*\]
* default: waf_under_attack off
* context: http, server, location

If your site is under attack you can try using this directive.
Turning it on forces a five-second delay on each user's first visit and automatically jumps to the page pointed to by `uri`.

* `uri`: can be a full URL or a path. For example, `https://example.com/attack.html` or `/attack.html`.

::: tip Tips

The page pointed to by `uri` should automatically jump to the page the user wants to visit after five seconds, the URL of the page can be obtained by querying a string with the parameter `target`.

`assets/under-attack.html` is a sample page, you should copy this file to your web directory and configure `uri` correctly.

Naturally, you can also write your own html file and point to it with `uri`.

:::


::: tip CHANGES IN 'Current' VERSION

In the LTS version we implemented this feature through redirects, but many reasons (such as caching and CDN) would cause the redirects to fail or not validate the cookie properly.
So we changed the implementation so that we return the specified page by changing the response body in a way that does not cause the URI to change.

We also added the response header `Cache-Control: no-store` to avoid the impact of caching.

* Removed the parameter `uri`.
* Added parameter `file`, the value of which should be the absolute path to an HTML file, e.g. `file=/path/to/under-attack.html`. This HTML has only one function, i.e. it refreshes automatically after five seconds.

:::


## `waf_priority`

* syntax: waf_priority "*str*"
* default: waf_priority "W-IP IP CC UNDER-ATTACK W-URL URL ARGS UA W-REFERER REFERER COOKIE ADV"
* context: http, server, location

Set the priority of each inspection process, except for POST detection, which always has the lowest priority.

* `UNDER-ATTACK`: Directive `waf_under_attack`.
* `W-IP`: IP whitelist inspection
* `IP`: IP Blacklist inspection
* `CC`: CC protection
* `W-URL`: URL whitelist inspection
* `URL`: URL blacklist inspection
* `ARGS`: URL parameter (query string) blacklist inspection
* `UA`: User-Agent blacklist inspection
* `W-REFERER`: Referer whitelist inspection
* `REFERER`: Referer blacklist inspection
* `COOKIE`: Cookie blacklist inspection
* `ADV`: Advanced rules.

::: warning WARNING

`str` must be wrapped in single or double quotes, and `str` must contain all of the inspection process.

:::


## `waf_http_status`

* syntax: waf_http_status \[general=*http_status_code*\] \[cc_deny=*http_status_code*]
* default: waf_http_status general=403 cc_deny=503
* context: http, server, location

This directive is used to set the HTTP status code returned when a request is blocked.

* `general`: Indicates the HTTP status code returned when all blacklist-based inpection are triggered.
* `cc_dney`: Indicates the HTTP status code returned when CC protection is triggered.


