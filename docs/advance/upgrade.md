---
title: Upgrade
lang: en
---

# Upgrade

The upgrade module needs to be reinstalled according to the instructions in [Installation Guide](/guide/installation.md).

## Upgrade from 5.x.x to 6.x.x

1. Create a new empty file named `advanced` in the rules directory.

2. If the directive `waf_priority` is used, you can delete it or modify it according to the directive in the documentation.

3. If the directive `waf_cc_deny` is used, you need to modify the directive according to the documentation.

4. Install redis and use the directive `waf_redis` correctly.

5. All functions of the directive `waf_cache` are removed, but `waf_cache` is reserved for subsequent extensions, so if you use this directive you should remove it.

