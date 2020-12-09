/**
 * @file ngx_http_waf_module_core.h
 * @brief 配置块的初始化和请求检测函数。
*/

#include <stdio.h>
#include <uthash.h>
#include <time.h>
#include <math.h>
#include <sys/io.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include "ngx_http_waf_module_macro.h"
#include "ngx_http_waf_module_type.h"
#include "ngx_http_waf_module_check.h"
#include "ngx_http_waf_module_config.h"
#include "ngx_http_waf_module_util.h"

#ifndef NGX_HTTP_WAF_MODULE_CORE_H
#define NGX_HTTP_WAF_MODULE_CORE_H

/**
 * @defgroup core 核心模块
 * @brief 配置块的初始化和请求检测函数。
 * @addtogroup core 核心模块
 * @{
*/

/**
 * @brief 检查 URL、ARGS 是否命中规则并决定是否拦截请求。
*/
static ngx_int_t ngx_http_waf_handler_url_args(ngx_http_request_t* r);

/**
 * @brief 检查 IP、URL、REFERER、UA、ARGS、COOKIE 和 POST 内容是否命中规则并决定是否拦截请求。
*/
static ngx_int_t ngx_http_waf_handler_ip_url_referer_ua_args_cookie_post(ngx_http_request_t* r);

/**
 * @}
*/

#endif // !NGX_HTTP_WAF_MODULE_CORE_H
