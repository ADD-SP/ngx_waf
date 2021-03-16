---
title: 兼容性说明
lang: zh-CN
---


# 兼容性说明

## 平台兼容性

本模块不向 Windows 平台提供兼容性支持。

## nginx 兼容性

本模块目前支持 `nginx-1.18.0` 或更新的版本。

::: tip 注意

`nginx-1.19.x` 为主线版本，即开发版。所以当主线版本发生更新时本模块可能无法兼容。
如果您使用主线版本的 nginx 时遇到了兼容性错误可以提 [issue](https://github.com/ADD-SP/ngx_waf/issues)。

:::

## 模块兼容性

### ngx_http_rewrite_module

本模块与 [ngx_http_rewrite_module](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html) 
存在兼容性问题。当使用了 `return` 或 `rewrite` 指令时可能会导致本模块的检测流程被跳过。

缓解方式见 [waf_mult_mount](/zh-cn/advance/syntax.md#waf-mult-mount)。

