---
title: 配置
lang: zh-CN
sidebarDepth: 3
---

# 配置

您可以在 `nginx.conf` 内的一个 `server` 块中添加配置来开启 ngx_waf。
下面是一个例子。


::: warning 警告

请不要对下面列出的配置进行修改，除非你知道这些配置项的含义。

:::


```nginx
http {
    ...
    server {
        ...
        # on 表示启用，off 表示关闭。
        waf on;
        # 规则文件所在目录的绝对路径，必须以 / 结尾。
        waf_rule_path /usr/local/src/ngx_waf/rules/;
        # 防火墙工作模式，STD 表示标准模式。
        waf_mode STD;
        # CC 防御参数，1000 每分钟请求次数上限，60 表示超出上限后封禁对应 ip 60 分钟。
        waf_cc_deny_limit 1000 60;

        # 下面的配置仅开发版可用。

        # 用于缓存检查结果的内存空间的大小，设置为 10 MB。
        waf_cache_size 10m;
        ...
    }
    ...
}
```
