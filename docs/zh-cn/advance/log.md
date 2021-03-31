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
cat /path/to/error.log | grep ngx_waf:
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
cat /path/to/error.log | grep ngx_waf_debug:
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

## 自定义日志格式

nginx 允许自定义日志格式，并且一个 server 块可以同时写入多个日志文件，
这就给我我们自定义日志格式的机会。本模块提供了三个[内置变量](/zh-cn/advance/variable.md)，稍加利用即可实现。
下面是一个例子。

```nginx
...

http {
    ...

    log_format  main    '$remote_addr - $remote_user [$time_local] "$request" '
                        '$status $body_bytes_sent "$http_referer" '
                        '"$http_user_agent" "$http_x_forwarded_for"';

    log_format  yaml    '- remote_addr: "$remote_addr"\n'
                        '  remote_user: "$remote_user"\n'
                        '  time_local: "$time_local"\n'
                        '  request: "$request"\n'
                        '  status: "$status"\n'
                        '  body_bytes_sent: "$body_bytes_sent"\n'
                        '  http_referer: "$http_referer"\n'
                        '  http_user_agent: "$http_user_agent"\n'
                        '  http_x_forwarded_for: "$http_x_forwarded_for"\n'
                        '  waf_blocked: $waf_blocked\n'
                        '  waf_rule_type: "$waf_rule_type"\n'
                        '  waf_rule_details: "$waf_rule_details"\n';


    server {
        ...

        access_log  logs/access.log  main;
        access_log  logs/access.yml  yaml;

        ...
    }

    ...
}

...
```

上述配置将常规的日志格式存入 `logs/access.log` 中，而 yaml 格式的日志会存入 `logs/access.yml` 中。
值得注意的是 yaml 格式的日志中使用了本模块提供了三个内置变量，
您可以通过程序方便地读取 `logs/access.yml`，然后就可以进行分析或者绘制图表了。

下面是一段 YAML 格式的日志。

```yaml
- remote_addr: "127.0.0.1"
  remote_user: "-"
  time_local: "14/Mar/2021:21:55:04 +0800"
  request: "GET /www.bak HTTP/1.1"
  status: "403"
  body_bytes_sent: "555"
  http_referer: "localhost"
  http_user_agent: "Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)"
  http_x_forwarded_for: "-"
  waf_blocked: true
  waf_rule_type: "BLACK-URL"
  waf_rule_details: "(?i)(?:\x5C.(?:bak|inc|old|mdb|sql|backup|java|class))$"

- remote_addr: "127.0.0.1"
  remote_user: "-"
  time_local: "14/Mar/2021:21:55:32 +0800"
  request: "GET / HTTP/1.1"
  status: "304"
  body_bytes_sent: "0"
  http_referer: "localhost"
  http_user_agent: "Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)"
  http_x_forwarded_for: "-"
  waf_blocked: false
  waf_rule_type: "null"
  waf_rule_details: "null"

- remote_addr: "127.0.0.1"
  remote_user: "-"
  time_local: "14/Mar/2021:21:55:33 +0800"
  request: "GET / HTTP/1.1"
  status: "304"
  body_bytes_sent: "0"
  http_referer: "localhost"
  http_user_agent: "Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)"
  http_x_forwarded_for: "-"
  waf_blocked: false
  waf_rule_type: "null"
  waf_rule_details: "null"

- remote_addr: "127.0.0.1"
  remote_user: "-"
  time_local: "14/Mar/2021:21:55:33 +0800"
  request: "GET / HTTP/1.1"
  status: "503"
  body_bytes_sent: "599"
  http_referer: "localhost"
  http_user_agent: "Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)"
  http_x_forwarded_for: "-"
  waf_blocked: false
  waf_rule_type: "CC-DENY"
  waf_rule_details: "null"

- remote_addr: "127.0.0.1"
  remote_user: "-"
  time_local: "14/Mar/2021:21:55:34 +0800"
  request: "GET / HTTP/1.1"
  status: "503"
  body_bytes_sent: "599"
  http_referer: "localhost"
  http_user_agent: "Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)"
  http_x_forwarded_for: "-"
  waf_blocked: true
  waf_rule_type: "CC-DENY"
  waf_rule_details: "null"
```

::: tip 关于 YAML 格式

YAML 是一种可读性高的数据序列化格式，学习十分简单，只要能看懂 JSON，学习 YAML 也就一会儿的事情。
可以自行搜索 YAML 的格式说明。

:::

