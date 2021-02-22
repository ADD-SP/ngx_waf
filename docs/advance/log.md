---
title: Log
lang: en
---

# Log

## Blocking Log


The blocking log is stored in `error.log`. The log level of the blocking log is `ALERT`.
The format is `ngx_waf: [rule type][specific rule triggered]`.

You can use the following command to quickly view the blocking log.

```sh
cat /path/to/error.log | grep ngx_waf
```

Here are two examples.

```
2020/01/20 22:56:30 [alert] 6666#0: *30 ngx_waf: [BLACK-URL][(?i)(?:/\.env$)], client: 192.168.1.1, server: example.com, request: "GET /v1/.env HTTP/1.1", host: "example.com", referrer: "http:/example.com/v1/.env"

2020/01/20 22:58:40 [alert] 6667#0: *11 ngx_waf: [BLACK-POST][(?i)(?:select.+(?:from|limit))], client: 192.168.1.1, server: example.com, request: "POST /xmlrpc.php HTTP/1.1", host: "example.com", referrer: "https://example.com/"
```

## Debugging Log

When you adjust the error log level to `debug` in the nginx configuration file, 
the debug log will be output in `error.log` for troubleshooting purposes.
for troubleshooting purposes. The format is `ngx_waf_debug: debug information`.

You can use the following command to quickly view the debug log.

```sh
cat /path/to/error.log | grep ngx_waf_debug
```

Below is a typical modulation log that illustrates the flow of a CC defense detection.

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