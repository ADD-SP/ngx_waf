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
cat /path/to/error.log | grep ngx_waf:
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
cat /path/to/error.log | grep ngx_waf_debug:
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

## Customised Log Format

nginx allows custom log formats, and a server block can write to multiple log files at the same time, 
giving us the opportunity to customise our log formats. 
This module provides some [built-in Variables](/advance/variable.md) 
that can be used to customise the blocking log with a little effort.

Here is an example.

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

The above configuration stores the normal log format in `logs/access.log`,
while the yaml format logs are stored in `logs/access.yml`.
It is worth noting that yaml format logs use the three built-in variables provided by the module.
You can easily read `logs/access.The above configuration will have the following effect.

* normal access logs are written to `logs/access.log`.
* YAML-formatted access logs are written to `logs/access.yml`.
* YAML-formatted intercept logs are written to `logs/waf.yml`.


::: tip Log analysis

You can customize the log format, and then programmatically analyze it and make statistical graphs.

:::

::: tip ABOUT YAML FORMAT

YAML is a highly readable data serialisation format that is very easy to learn. 
As long as you can read JSON, learning YAML will be a snap.
You can search for a description of the YAML format yourself.

:::

