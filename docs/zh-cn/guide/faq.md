---
title: 常见问题与解答
lang: zh-CN
---

# 常见问题与解答

## 本模块的性能如何？

IP 检查和 CC 防御花费常数时间，其它的检查花费 `O(nm)` 的时间，其中 `n` 是相关规则的条数，`m` 为执行正则匹配的时间复杂度，但是每次检查过后会自动缓存本次检查的结果，下次检查相同的目标时就可以使用缓存而不是检查全部的规则。不会缓存 POST 请求体的检查结果。

## 缓存策略

LRU

## ngx_http_access_module

当本模块与 `ngx_http_access_module` 一起使用时，`ngx_http_access_module` 会先于本模块运行。

## post检测失效

本模块出于性能考虑只会在 Post 请求体在内存中时检查，若不在内存中则跳过检查。
您可以通过修改配置文件来解决这个问题。

```nginx
http {
    ...
    client_body_buffer_size 10M;
    client_body_in_file_only off;
    ...
}
```
[client_body_buffer_size 的说明](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_buffer_size) 
和 [client_body_in_file_only 的说明](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_in_file_only)。

## fork() failed while spawning "worker process" (12: Cannot allocate memory)

可能是过多地使用 `nginx -s reload` 导致的，本模块会在读取配置的时候申请一些内存，但是不知为何 `nginx -s reload` 之后这些内存不会立即释放，所以短时间内频繁 `nginx -s reload` 就极可能导致这个错误。

## 可以在运行时修改规则么？

不可以，本模块只会在 nginx 读取配置时读取规则。nginx 会在启动和 reload 时读取配置。

## CDN 对 IP 检查的影响

如果你使用 [ngx_http_realip_module](https://nginx.org/en/docs/http/ngx_http_realip_module.html) 获取真实 IP 的话，则本模块在检查 IP 时就会使用真实的 IP。

## 正则表达式拒绝服务攻击（ReDoS）

ReDoS 是指使用的正则表达式存在缺陷时，攻击者可以使用一个精心构造的字符串来大量地消耗服务器的资源，比如导致正则引擎的灾难性的回溯。

本模块有两种措施可以用来缓解此类攻击。

* 本模块使用的 PCRE 库执行正则表达式，PCRE 在编译时即可指定主循环的计数器上限，超出上限自动停止。默认上限为 500000。你也可以在编译时手动调整，详见 [pcre2 build man page](https://www.pcre.org/current/doc/html/pcre2build.html#SEC11)。

* 本模块会缓存所有正则的检查结果（POST 检查除外），这样在不触发缓存淘汰流程的情况下，下次遇到用于攻击的字符串也无需再次执行正则表达式。
