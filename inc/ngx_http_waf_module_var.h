#ifndef __NGX_HTTP_WAF_VAR_H__
#define __NGX_HTTP_WAF_VAR_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>


/**
 * @brief 当读取 waf_log 变量时的回调函数，这个变量当启动检查时不为空，反之为空字符串。
*/
ngx_int_t ngx_http_waf_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_blocking_log 变量时的回调函数，这个变量当拦截时不为空，反之为空字符串。
*/
ngx_int_t ngx_http_waf_blocking_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_blocked 变量时的回调函数，这个变量当请求被拦截的时候是 "true"，反之是 "false"。
*/
ngx_int_t ngx_http_waf_blocked_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_rule_type 变量时的回调函数，这个变量会显示触发了的规则类型。
*/
ngx_int_t ngx_http_waf_rule_type_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_rule_deatils 变量时的回调函数，这个变量会显示触发了的规则的细节。
*/
ngx_int_t ngx_http_waf_rule_deatils_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_spend 变量时的回调函数，这个变量表示本次检查花费的时间（毫秒）。
*/
ngx_int_t ngx_http_waf_spend_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


#endif