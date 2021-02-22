---
title: Configuration Guide
lang: en
---

# Configuration Guide

You can enable ngx_waf by adding configuration to a `server` block inside `nginx.conf`.
Here is an example.

```nginx
http {
    ...
    server {
        ...
        # on means enabled, off means disabled.
        waf on;
        # The absolute path to the directory where the rule file is located, must end with /.
        waf_rule_path /usr/local/src/ngx_waf/rules/;
        # Firewall working mode, STD indicates standard mode.
        waf_mode STD;
        # CC protection parameter, 1000 maximum number of requests per minute, 
        # 60 means the corresponding ip is blocked for 60 minutes after exceeding the limit.
        waf_cc_deny_limit 1000 60;
        ...
    }
    ...
}
```
