---
title: Configuration Guide
lang: en
---

# Configuration Guide

You can enable ngx_waf by adding configuration to a `server` block inside `nginx.conf`.
Here is an example.

::: warning WARNING

The configurations listed below are required if you intend to change them unless you know what it means.

:::

```nginx
http {
    ...
    server {
        ...
        # on means enabled, off means disabled.
        waf on;

        # The absolute path to the directory where the rule file is located, must end with /.
        waf_rule_path /usr/local/src/ngx_waf/assets/rules/;

        # Firewall working mode, STD indicates standard mode.
        waf_mode STD;

        # CC defense parameter, 1000 requests per minute limit, 
        # block the corresponding ip for 60 minutes after exceeding the limit.
        waf_cc_deny rate=1000r/m duration=60m;

        # Cache detection results for up to 50 detection targets, 
        # effective for all detections 
        # except IP black and white list detection, CC protection and POST detection.
        waf_cache capacity=50;
        ...
    }
    ...
}
```
