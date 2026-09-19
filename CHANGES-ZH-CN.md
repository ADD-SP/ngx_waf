## Unreleased

* 模块逻辑正在用 Rust 重写：C 代码只保留 nginx 胶水层（模块与指令注册、请求数据
  打包、响应与变量落地），其余逻辑位于 `rust/`。
* 使用 nginx `config` 脚本、cargo 与 mise 任务取代 Bazel。
* FFI 头文件 `include/ngx_http_waf_ffi.h` 由 cbindgen 生成并入库。
* 构建入口从根 `Makefile` 迁移到 mise 任务（`.mise/tasks/`，`mise run <task>`）。
  `mise.toml` 还声明了固定版本的 cbindgen 与 Debian/Ubuntu 系统依赖；Rust 工具链
  仍由 rustup 与 `rust-toolchain.toml` 提供。
* C ABI 只保留边界本身的词汇：step、事件、请求方法与协议版本的枚举，配置与
  请求检测的不透明句柄，以及语义化的配置查询。实现的常量与内部类型不再跨边界。
* 所有检测项均已移植，包括异步部分：验证码与友好爬虫校验通过 nginx 的
  resolver 做反向解析、通过与验证码服务商的非阻塞请求完成验证。
  ModSecurity 的响应阶段尚未移植。与 C 实现的差异见 `rust/README.md`。

见 [https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/zh-cn/changes/overview.md](https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/zh-cn/changes/overview.md)。
