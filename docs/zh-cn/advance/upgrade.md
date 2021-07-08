---
title: 升级
lang: zh-CN
---

# 升级

升级模块均需要按照[安装指南](/zh-cn/guide/installation.md)中的说明重新安装。

## 从 5.x.x 升级到 6.x.x

1. 在规则目录下新建一个名为 `advanced` 的空文件。

2. 如果使用了配置项 `waf_priority`，可以将其删除或者按照文档中对该配置项的说明进行修改。

3. 如果使用了配置项 `waf_cc_deny`，您需要按照文档中的说明对该配置项的进行修改。

4. 安装 redis 并正确配置 `waf_redis`。

5. 配置项 `waf_cache` 的所有功能被删除，但是 `waf_cache` 被保留下以便后续扩展功能，如果您使用了这个配置项您应该将其删除。