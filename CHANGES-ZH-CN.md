## Unreleased

* 模块逻辑正在用 Rust 重写：C 代码只保留 nginx 胶水层（模块与指令注册、请求数据
  打包、响应与变量落地），其余逻辑位于 `rust/`。
* 使用 nginx `config` 脚本、cargo 与 `Makefile` 取代 Bazel。
* FFI 头文件 `include/ngx_http_waf_ffi.h` 由 cbindgen 生成并入库。
* 尚未移植的检测项（验证码、友好爬虫校验、五秒盾、ModSecurity）会被配置解析
  接受、输出警告，但目前不生效。

见 [https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/zh-cn/changes/overview.md](https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/zh-cn/changes/overview.md)。
