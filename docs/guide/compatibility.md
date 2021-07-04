---
title: Compatibility Statement
lang: en
---


# Compatibility Statement

## OS Compatibility

Compatibility with operating systems other than Linux is not guaranteed.

## Nginx Compatibility

This module only guarantees compatibility with `nginx-1.18.0` or newer versions.

## Module Compatibility

### ngx_http_rewrite_module

There is a compatibility issue between ngx_waf and 
[ngx_http_rewrite_module](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html). 
The ngx_waf inspection process may be skipped when the `return` or `rewrite` directives are used.

See [waf_mode](/advance/directive.md#waf-mode) for the solution.

