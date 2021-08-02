---
title: 针对路径或文件限流
lang: zh-CN
---

# 针对路径或文件限流

## 概述

有时你可能想要限制不同的路径或文件的请求速率，比如静态资源和动态资源使用不同的速率限制。

## 配置

```nginx
# 将静态资源的请求速率限制到 10,000 次/分钟。
location /static/ {
    waf_cc_deny rate=10000r/m duration=1h;
}

# 将动态资源的请求速率限制到 2,000 次/分钟。
location /dynamic/ {
    waf_cc_deny rate=2000r/m duration=1h;
}