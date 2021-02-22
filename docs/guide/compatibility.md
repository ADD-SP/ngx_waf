---
title: Compatibility Statement
lang: en
---


# Compatibility Statement

## Platform Compatibility

This module does not provide compatibility support for Windows platforms.

## Nginx Compatibility

This module currently supports `nginx-1.18.0` and `nginx-1.19.6` versions.

::: tip NOTE

`nginx-1.19.x` is the mainline version, 
i.e. the development. Therefore, 
this module may not be compatible with the mainline version when it is updated.
If you encounter compatibility errors when using the mainline version of nginx, 
you can raise [issue](https://github.com/ADD-SP/ngx_waf/issues).

:::

## Module Compatibility

### ngx_http_rewrite_module

This module is compatible with 
[ngx_http_rewrite_module](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html) 
There is a compatibility issue. 
When the `return` or `rewrite` directives are used, the detection process of this module may be skipped.

See [waf_mult_mount](/advance/syntax#waf-mult-mount) for the imperfect solution.

