---
title: Known Issues
lang: en
---

# Known Issues

Bugs that exist in the latest stable release are listed here, 
bugs that have been fixed in the latest stable release are not listed here.

## Built-in variable name error

The built-in variable `waf_rule_details` was incorrectly set to `waf_rule_deatails` within the code.

* Severity: Very serious
* Priority: Highest
* Affected nginx version: >= 1.18.0
* Affected version of ngx_waf: 1.0.0 - 3.2.0-beta.1
* Status: Fixed
* Remarks: Fixed in v4.0.0-beta.1

## Superfluous inspection

Sometimes the inspection is repeated several times, which does not cause errors, but wastes time.

* Severity: It will hardly affect the use
* Priority: Lowest
* Affected nginx version: >= nginx-1.18.0
* Affected version of ngx_waf: 1.0.0 - 3.2.0-beta.1
* Status: Fixed
* Remarks: Fixed in v4.0.0-beta.1