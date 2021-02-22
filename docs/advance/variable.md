---
title: Built-in Variables
lang: en
---

# Built-in Variables

When writing `nginx.conf`, some variables are inevitably needed. For example, `$remote_addr` can be used to get the client IP address.

This module adds three available variables.

## `$waf_blocked`

Whether this request is intercepted by this module, if intercepted, its value is `'true'`, otherwise it is `'false'`.

## `$waf_rule_type

If current request was blocked by this module, this variable is set to the triggered rule type, otherwise `'null'`. The following are possible values.

+ `'BLACK-IPV4'`
+ `'BLACK-URL'`
+ `'BLACK-ARGS'`
+ `'BLACK-USER-AGENT'`
+ `'BLACK-REFERER'`
+ `'BLACK-COOKIE'`
+ `'BLACK-POST'`

## `'$waf_rule_details'`

If this request is blocked by this module, its value is the content of the specific rule triggered. If it is not blocked, its value is `'null'`.