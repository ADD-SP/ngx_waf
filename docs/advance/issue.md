---
title: Known Issues
lang: en
---

# Known Issues

Bugs that exist in the latest stable release are listed here, 
bugs that have been fixed in the latest stable release are not listed here.

## segmentation fault

When the number of worker processes in nginx is greater than one, the module will throw a segmentation fault. 

* Severity: Critical.
* Affected versions of ngx_waf: v3.1.0 ~ v4.1.0-beta.1
* Status: Fixed
* Priority: Highest
* Note: It has been fixed in the latest development version.

