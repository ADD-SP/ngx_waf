/**
 * @file ngx_http_waf_module_core.h
 * @brief 配置块的初始化和请求检测函数。
*/

#ifndef NGX_HTTP_WAF_MODULE_CORE_H
#define NGX_HTTP_WAF_MODULE_CORE_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include <uthash.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_check.h>
#include <ngx_http_waf_module_config.h>
#include <ngx_http_waf_module_util.h>

/**
 * @defgroup core 核心模块
 * @brief 配置块的初始化和请求检测函数。
 * @addtogroup core 核心模块
 * @{
*/


/**
 * @brief 当 Worker 进程启动时调用的函数，用于重置随机数种子。
*/
ngx_int_t ngx_http_waf_init_process(ngx_cycle_t *cycle);


/**
 * @brief NGX_HTTP_ACCESS_PHASE 阶段的处理函数
*/
ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r);


/**
 * @brief NGX_HTTP_CONTENT_PHASE 阶段的处理函数
*/
ngx_int_t ngx_http_waf_handler_precontent_phase(ngx_http_request_t* r);


/**
 * @brief NGX_HTTP_LOG_PHASE 阶段的处理函数
*/
ngx_int_t ngx_http_waf_handler_log_phase(ngx_http_request_t* r);


/**
 * @brief 执行全部的检查项目
 * @param r 本次要处理的请求
 * @param is_check_cc 是否执行 CC 防护逻辑
 * @return http 状态码或者 nginx 控制量
 * @retval NGX_DECLINED 放行本次请求
 * @retval NGX_DONE 将在其它地方进行检查，通常是因为执行了 POST 检测
*/
ngx_int_t ngx_http_waf_check_all(ngx_http_request_t* r, ngx_int_t is_check_cc);


void ngx_http_waf_handler_cleanup(void *data);

/**
 * @}
*/

#endif // !NGX_HTTP_WAF_MODULE_CORE_H
