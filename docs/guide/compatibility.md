---
title: Compatibility Statement
lang: en
---


# Compatibility Statement

## Platform Compatibility

This module does not provide compatibility support for Windows platforms.

## Nginx Compatibility

This module currently supports `nginx-1.18.0` or newer.

::: tip NOTE

`nginx-1.19.x` is the mainline version, 
i.e. the development. Therefore, 
this module may not be compatible with the mainline version when it is updated.
If you encounter compatibility errors when using the mainline version of nginx, 
you can create [issue](https://github.com/ADD-SP/ngx_waf/issues).

:::

## Module Compatibility

### ngx_http_rewrite_module

There is a compatibility issue between ngx_waf and 
[ngx_http_rewrite_module](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html). 
The ngx_waf inspection process may be skipped when the `return` or `rewrite` directives are used.

See [waf_mode](/advance/syntax.md#waf-mode) for the solution.

