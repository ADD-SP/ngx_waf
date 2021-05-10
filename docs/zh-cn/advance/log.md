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
这就给我我们自定义日志格式的机会。本模块提供了几个[内置变量](/zh-cn/advance/variable.md)，稍加利用即可实现。
下面是一个例子。

```nginx
...

http {
    ...

    log_format  main    '$remote_addr - $remote_user [$time_local] "$request" '
                        '$status $body_bytes_sent "$http_referer" '
                        '"$http_user_agent" "$http_x_forwarded_for"';

    log_format yaml     '- remote_addr: "$remote_addr"\n'
                        '  remote_user: "$remote_user"\n'
                        '  time_local: "$time_local"\n'
                        '  request: "$request"\n'
                        '  status: "$status"\n'
                        '  body_bytes_sent: "$body_bytes_sent"\n'
                        '  http_referer: "$http_referer"\n'
                        '  http_user_agent: "$http_user_agent"\n'
                        '  http_x_forwarded_for: "$http_x_forwarded_for"\n'
                        '  waf_blocked: $waf_blocked\n'
                        '  waf_spend: $waf_spend\n'
                        '  waf_rule_type: "$waf_rule_type"\n'
                        '  waf_rule_details: "$waf_rule_details"\n';


    server {
        ...

        access_log  logs/access.log  main;
        access_log  logs/access.yml  yaml   if=$waf_log;
        access_log  logs/waf.yml     yaml   if=$waf_blocking_log;

        ...
    }

    ...
}

...
```

上述配置会有如下效果：

* 常规的访问日志写入 `logs/access.log` 中。
* YAML 格式的访问日志写入 `logs/access.yml` 中。
* YAML 格式的拦截日志写入 `logs/waf.yml` 中。


::: tip 日志分析

你可以自定义日志格式，然后通过程序分析并制作统计图表。

:::


::: tip 关于 YAML 格式

YAML 是一种可读性高的数据序列化格式，学习十分简单，只要能看懂 JSON，学习 YAML 也就一会儿的事情。
可以自行搜索 YAML 的格式说明。

:::

