---
title: Known Issues
lang: en
---

# Known Issues

## Built-in variable name error

The built-in variable `waf_rule_details` was incorrectly set to `waf_rule_deatails` within the code.

* Severity: Very serious
* Priority: Highest
* Affected nginx version: >= 1.18.0
* Affected version of ngx_waf: >= 1.0.0
* Status: open
* Remarks: It has been fixed in the dev branch, but no beta version has been released yet

## Repeat inspection

Sometimes the inspection is repeated several times, which does not cause errors, but wastes time.

* Severity: It will hardly affect the use
* Priority: Lowest
* Affected nginx version: >= nginx-1.18.0
* Affected version of ngx_waf: all version
* Status: open
* Remarks: none