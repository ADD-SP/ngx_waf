---
title: Built-in Variables
lang: en
---

# Built-in Variables

When writing `nginx.conf`, some variables are inevitably needed. For example, `$remote_addr` can be used to get the client IP address.

This module adds several available variables.

## `$waf_log`

Not an empty string if the firewall is checked in this request, otherwise an empty string. This variable is mainly used in the directive `access_log`, see [Customised Log Format](log.md#customised-log-format).

## `$waf_blocking_log`

Not an empty string if this request was originally blocked by the module, and vice versa. This variable is mainly used in the directive `access_log`, see [Customised Log Format](log.md#customised-log-format).

## `$waf_blocked`

Whether this request is intercepted by this module, if intercepted, its value is `'true'`, otherwise it is `'false'`.

## `$waf_spend`

Indicates how much time (in milliseconds) this check took, retaining 5 decimal places, with rounding rules depending on the specific C standard library implementation.

## `$waf_rule_type`

If a black and white list rule is in effect for this request, the value is the type of rule that triggered it. Here are the possible values. If no black and white list rule is in effect then the value is `''`.

+ `'CC-DENY'`
+ `'WHITE-IPV4'`
+ `'WHITE-IPV6'`
+ `'BLACK-IPV4'`
+ `'BLACK-IPV6'`
+ `'WHITE-URL'`
+ `'BLACK-URL'`
+ `'BLACK-ARGS'`
+ `'BLACK-USER-AGENT'`
+ `'WHITE-REFERER'`
+ `'BLACK-REFERER'`
+ `'BLACK-COOKIE'`
+ `'BLACK-POST'`
+ `'UNDER-ATTACK'`


## `$waf_rule_details`

If this request is blocked by this module, its value is the content of the specific rule triggered. If it is not blocked, its value is `''`.
