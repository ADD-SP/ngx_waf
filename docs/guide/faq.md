---
title: FAQ
lang: en
---

# FAQ

## How does this module perform?

IP inspection and CC defense take constant time, other inspections take `O(nm)`, where `n` is the number of relevant rules and `m` is the time complexity to perform regular matching, but the results of this inspection are automatically cached after each inspection, so that the next time the same target is inspected, the cache can be used instead of checking all the rules. The result of the POST request body check is not cached.

## Cache Policy

LRU

## ngx_http_access_module

When this module is used with `ngx_http_access_module`, `ngx_http_access_module` will run before this module.

## Post Inspection Failure

For performance reasons, this module will inspect whether it is in the memory before inspecting the request body. If it is, it will inspect normally, otherwise skip the inspection. You can try to edit nginx.conf.

```nginx
http {
    ...
    client_body_buffer_size 10M;
    client_body_in_file_only off;
    ...
}
```
[client_body_buffer_size](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_buffer_size) 
and [client_body_in_file_only](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_in_file_only).

## fork() failed while spawning "worker process" (12: Cannot allocate memory)

It may be caused by excessive use of `nginx -s reload`. The module requests some memory when reading the configuration, but somehow the memory is not released immediately after `nginx -s reload`, so frequent `nginx -s reload` in a short period of time will most likely cause this error.

## Can I change the rules at runtime?

No, this module will only read the rules when nginx reads the configuration. 
nginx will read the configuration on startup and reload.

## Is IP inspection affected by CDN?

If you use the [ngx_http_realip_module](https://nginx.org/en/docs/http/ngx_http_realip_module.html) module to get the real IP, then this module will use the real IP for inspection.

## Regular expression Denial of Service (ReDoS)

> The regular expression denial of service (ReDoS) is an algorithmic complexity attack that produces a denial-of-service by providing a regular expression that takes a very long time to evaluate. <br><br>
> [ReDoS - Wikipedia](https://en.wikipedia.org/wiki/ReDoS)

* This module uses the PCRE library to execute regular expressions. The PCRE library can specify the upper limit of the main loop counter at compile time and stop automatically when the upper limit is exceeded. The default limit is 500000. You can also adjust it manually at compile time, see the [pcre2 build man page](https://www.pcre.org/current/doc/html/pcre2build.html#SEC11).

* This module caches all regular inspections (except POST inspections), so that the next time you encounter a string for an attack, you do not need to execute the regular expression again without triggering the cache cleanup process.
