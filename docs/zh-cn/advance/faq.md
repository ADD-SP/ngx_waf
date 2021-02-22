---
title: 常见问题与解答
lang: zh-CN
---

# 常见问题与解答

## 本模块的性能如何？

IP 检查和 CC 防御花费常数时间，其它的检查花费 O(nm) 的时间，其中 n 是相关规则的条数，m 为执行正则匹配的时间复杂度。

## post检测失效

本模块出于性能考虑只会在 Post 请求体在内存中时检查，若不在内存中则跳过检查。
您可以通过修改配置文件来解决这个问题。

```nginx
http {
    ...
    # 设置 Post 请求体缓冲区大小
    client_body_buffer_size: 10M;

    # 永远将请求体存放在内存中
    client_body_in_file_only: off;
    ...
}
```
[client_body_buffer_size 的说明](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_buffer_size) 
和 [client_body_in_file_only 的说明](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_in_file_only)。

## fork() failed while spawning "worker process" (12: Cannot allocate memory)

可能是过多地使用 `nginx -s reload` 导致的，本模块会在读取配置的时候申请一些内存，但是不知为何 `nginx -s reload` 之后这些内存不会立即释放，所以短时间内频繁 `nginx -s reload` 就极可能导致这个错误。
