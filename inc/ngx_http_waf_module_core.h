#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include "uthash/src/uthash.h"
#include "ngx_http_waf_module_macro.h"
#include "ngx_http_waf_module_type.h"

#ifndef NGX_HTTP_WAF_MODULE_CORE_H
#define NGX_HTTP_WAF_MODULE_CORE_H


static void* ngx_http_waf_create_srv_conf(ngx_conf_t* cf);


static ngx_int_t ngx_http_waf_blocked_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


static ngx_int_t ngx_http_waf_rule_type_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


static ngx_int_t ngx_http_waf_rule_deatils_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


static ngx_int_t ngx_http_waf_handler_url_args(ngx_http_request_t* r);


static ngx_int_t ngx_http_waf_handler_ip_url_referer_ua_args_cookie_post(ngx_http_request_t* r);

/*
* 将一个字符串形式的 IPV4 地址转化为 ngx_ipv4_t
* 合法的字符串只有类似 192.168.1.1 和 1.1.1.0/24 这两种形式
* 如果成功则返回 SUCCESS，反之返回 FALI
*/
static ngx_int_t parse_ipv4(ngx_str_t text, ipv4_t* ipv4);




/* 将 ngx_str 转化为 C 风格的字符串 */
static char* to_c_str(u_char* destination, ngx_str_t ngx_str);

/*
* 读取指定文件的内容到数组中
* 当 mode = 0 时会将读取到文本编译成正则表达式再存储
* 当 mode = 1 时会将读取到的文本转化为 ngx_ipv4_t 再存储
* 如果成功则返回 SUCCESS，反之返回 FAIL
*/
static ngx_int_t load_into_array(ngx_conf_t* cf, const char* file_name, ngx_array_t* ngx_array, ngx_int_t mode);


/*
* 检查请求体内容是否存在于黑名单中
* 存在则拦截，反之放行。
*/
void check_post(ngx_http_request_t* r);

#endif // !NGX_HTTP_WAF_MODULE_CORE_H
