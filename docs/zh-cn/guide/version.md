---
title: 版本说明
lang: zh-CN
---

# 版本说明

## 语义化版本

本项目遵循[语义化版本 2.0.0](https://semver.org/lang/zh-CN/)。

## 长期维护版（LTS）

长期维护版至少维护一年，并且维护期间只会修复 bug，特别的是严重的 bug，一些比较轻的 bug 可能不会修复。

这个版本在大多数情况下是稳定的，但是没有功能性更新。

```sh
git clone -b master https://github.com/ADD-SP/ngx_waf.git

# 或

git clone -b lts https://github.com/ADD-SP/ngx_waf.git
```

## 最新版（Current）

最新版的 bug 也会被修复，但是最新版包含了全部的更新，比如新功能、功能变动、功能删除、性能优化等。

这个版本不如 LTS 版稳定，但是会有功能性更新。

```sh
git clone -b current https://github.com/ADD-SP/ngx_waf.git
```