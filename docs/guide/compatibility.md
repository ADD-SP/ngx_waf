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

* The module does not take effect if the request directive `return` takes effect.
* The module does not take effect if the request directive `rewrite` results in a return (e.g., a 302 redirect).

::: tip Replace `rewrite` with `try_files`.

You may have the following configuration.

``nginx
if (! -e $request_filename) {
    rewrite (. *) /index.php
}
```

You can replace it with the following configuration.

``nginx
try_files $uri $uri/ /index.php;
```

See [rewrite](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#rewrite) and [try_files](https://nginx.org/en/docs/http/ngx_) for details http_core_module.html#try_files).

:::

