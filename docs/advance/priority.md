---
title: Rule Priority
lang: en
---

# Rule Priority

There are many inspection process in this module, so it is important to specify the inspection priority of each inspection process to avoid illogical inspection results.

The following is a list of all the tests in order of priority, from top to bottom.

1. IP whitelist inspection
2. IP blacklist inspection
3. CC protection
4. Under attack mode
5. Url whitelist inspection
6. Url blacklist inspection
7. Get parameter blacklist inspection
8. User-Agent blacklist inspection
9. Referer whitelist inspection
10. Referer blacklist inspection
11. Cookie blacklist inspection
12. Advanced rules
13. Post request body blacklist


::: tip Change priority

You can modify the priority through the configuration file, but the priority of the POST request body detection is not allowed to be modified, it will always have the lowest priority. See [waf_priority](directive.md#waf-priority) for details

:::
