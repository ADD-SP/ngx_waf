---
title: 日志
lang: zh-CN
---

# 日志

## 拦截日志

拦截日志日志存储在 error.log 中。拦截记录的日志等级为 ALERT。
格式为 `ngx_waf: [规则类型][触发的具体规则]`。

您可以使用下列命令快速查看拦截日志。

```sh
cat /path/to/error.log | grep ngx_waf
```

下面是两个例子。

```
2020/01/20 22:56:30 [alert] 6666#0: *30 ngx_waf: [BLACK-URL][(?i)(?:/\.env$)], client: 192.168.1.1, server: example.com, request: "GET /v1/.env HTTP/1.1", host: "example.com", referrer: "http:/example.com/v1/.env"

2020/01/20 22:58:40 [alert] 6667#0: *11 ngx_waf: [BLACK-POST][(?i)(?:select.+(?:from|limit))], client: 192.168.1.1, server: example.com, request: "POST /xmlrpc.php HTTP/1.1", host: "example.com", referrer: "https://example.com/"
```

## 调试日志

当您在 nginx 的配置文件中将错误日志的等级调整为 `debug` 时，会在 error.log 中输出调试日志，
用以排障。格式为 `ngx_waf_debug: 调试信息`。

您可以使用下列命令快速查看调试日志。

```sh
cat /path/to/error.log | grep ngx_waf_debug
```

下面是一段典型的调式日志，指示了一次 CC 防御检测的流程。

```
2021/02/21 20:35:33 [debug] 6666#0: *1 ngx_waf_debug: Start the CC inspection process.
2021/02/21 20:35:33 [debug] 6666#0: *1 ngx_waf_debug: The module context has been obtained.
2021/02/21 20:35:33 [debug] 6666#0: *1 ngx_waf_debug: The configuration of the module has been obtained.
2021/02/21 20:35:33 [debug] 6666#0: *1 ngx_waf_debug: Detection has begun.
2021/02/21 20:35:33 [debug] 6666#0: *1 ngx_waf_debug: Shared memory is locked.
2021/02/21 20:35:33 [debug] 6666#0: *1 ngx_waf_debug: Shared memory is unlocked.
2021/02/21 20:35:33 [debug] 6666#0: *1 ngx_waf_debug: Detection is over.
2021/02/21 20:35:33 [debug] 6666#0: *1 ngx_waf_debug: The CC detection process is fully completed.
```