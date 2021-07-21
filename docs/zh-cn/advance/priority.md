---
title: 规则优先级
lang: zh-CN
---

# 规则优先级

本模块着诸多检测项目，那么一定要规定各个检测项目的检测优先级，避免出现不合逻辑的检测结果。

下面将按照优先级从高到底地列出所有的检测项目。

1. IP 白名单检测
2. IP 黑名单检测
3. CC 防御检测
4. Under-Attack 模式
5. Url 白名单检测
6. Url 黑名单检测
7. Get 参数黑名单检测
8. User-Agent 黑名单检测
9. Referer 白名单检测
10. Referer 黑名单检测
11. Cookie 黑名单检测
12. 高级规则
13. Post 请求体黑名单


::: tip 修改优先级

您可以通过配置文件修改优先级，但是 POST 请求体检测的优先级不允许修改，它的优先级永远是最低的。详见 [waf_priority](directive.md#waf-priority)。

:::
