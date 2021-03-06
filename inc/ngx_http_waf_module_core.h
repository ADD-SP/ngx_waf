/**
 * @file ngx_http_waf_module_core.h
 * @brief 配置块的初始化和请求检测函数。
*/

#include <stdio.h>
#include <uthash.h>
#include <time.h>
#include <math.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_check.h>
#include <ngx_http_waf_module_config.h>
#include <ngx_http_waf_module_util.h>

#ifndef NGX_HTTP_WAF_MODULE_CORE_H
#define NGX_HTTP_WAF_MODULE_CORE_H

/**
 * @defgroup core 核心模块
 * @brief 配置块的初始化和请求检测函数。
 * @addtogroup core 核心模块
 * @{
*/

/**
 * @brief NGX_HTTP_SERVER_REWRITE_PHASE 阶段的处理函数
*/
static ngx_int_t ngx_http_waf_handler_server_rewrite_phase(ngx_http_request_t* r);

/**
 * @brief NGX_HTTP_ACCESS_PHASE 阶段的处理函数
*/
static ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r);

/**
 * @brief 执行全部的检查项目
*/
static ngx_int_t check_all(ngx_http_request_t* r);

/**
 * @}
*/

#endif // !NGX_HTTP_WAF_MODULE_CORE_H
