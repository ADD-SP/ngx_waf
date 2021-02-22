---
title: 配置
lang: zh-CN
sidebarDepth: 3
---

# 配置

您可以在 `nginx.conf` 内的一个 `server` 块中添加配置来开启 ngx_waf。
下面是一个例子。

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
        ...
    }
    ...
}
```
