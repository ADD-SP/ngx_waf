---
title: Rule Priority
lang: en
---

# Rule Priority

There are many inspection process in this module, so it is important to specify the inspection priority of each inspection process to avoid illogical inspection results.

The following is a list of all the tests in order of priority, from top to bottom.

1. CC protection
2. IP whitelist inspection
3. IP blacklist inspection
4. Url whitelist inspection
5. Url blacklist inspection
6. Get parameter blacklist inspection
7. User-Agent blacklist inspection
8. Referer whitelist inspection
9. Referer blacklist inspection
10. Cookie blacklist inspection
11. Post request body blacklist


::: tip Change priority

You can modify the priority through the configuration file, but the priority of the POST request body detection is not allowed to be modified, it will always have the lowest priority. See [waf_priority](syntax.md#waf-priority) for details

:::


::: tip CHANGES IN THE DEVELOPMENT VERSION

Swaps the default priority of CC protection and IP whitelist inspection.

:::
