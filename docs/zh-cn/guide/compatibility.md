---
title: 兼容性说明
lang: zh-CN
---


# 兼容性说明

## 操作系统兼容性

不保证与Linux以外的操作系统的兼容性。

## nginx 兼容性

本模块只保证对 `nginx-1.18.0` 或更新的版本的兼容性。

## 模块兼容性

### ngx_http_rewrite_module

本模块与 [ngx_http_rewrite_module](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html) 
存在兼容性问题。

* 当 `return` 指令生效时模块不会生效。
* 当 `rewrite` 指令造成了返回（如 302 重定向）时模块不会生效。

::: tip 使用 `try_files` 代替 `rewrite`

你可能会有下列的配置。

```nginx
if (!-e $request_filename) {
    rewrite (.*) /index.php
}
```

你可以用下面的配置来替换。

```nginx
try_files $uri $uri/ /index.php;
```

详情见 [rewrite](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#rewrite) 和 [try_files](https://nginx.org/en/docs/http/ngx_http_core_module.html#try_files)。

:::

