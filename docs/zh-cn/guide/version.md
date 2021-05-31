---
title: 版本说明
lang: zh-CN
---

# 版本说明

## 语义化版本

本项目遵循[语义化版本 2.0.0](https://semver.org/lang/zh-CN/)。

## 稳定版

稳定版保证随时可以使用，其中包含了比较稳定的功能。您可以通过下列命令获取稳定版的模块源码。

```sh
git clone -b master https://github.com/ADD-SP/ngx_waf.git
```

## 开发版

开发版保证大多数情况下可以使用，其中相对于稳定版额外包含了一些改动，比如新功能、错误修复和功能变更等。
您可以通过下列命令获取开发版的模块源码。

```sh
git clone -b dev https://github.com/ADD-SP/ngx_waf.git
```

## 分支说明

* master：稳定版分支，保证随时可用。
* dev：开发版分支，保证大多数情况下可用。
* feature-xxxx：新功能开发分支，不保证可用性，开发完成后会合并到 `dev` 分支。
* bugfix-xxxx：错误修复分支，不保证可用性，修复完成后一般会合并到 `dev` 分支。
* hotfix-xxxx：热修复分支，不保证可用性，修复完成后会合并到 `master` 和 `dev`。
* change-xxxx：功能变动分支，不保证可用性，开发完成后会合并到 `dev` 分支。