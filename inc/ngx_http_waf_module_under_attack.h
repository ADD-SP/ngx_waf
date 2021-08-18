#ifndef __NGX_HTTP_WAF_MODULE_UNDER_ATTACK_H__
#define __NGX_HTTP_WAF_MODULE_UNDER_ATTACK_H__


#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_check.h>

extern ngx_module_t ngx_http_waf_module; /**< 模块详情 */

/**
 * @brief 进行五秒盾检测
*/
ngx_int_t ngx_http_waf_handler_under_attack(ngx_http_request_t* r, ngx_int_t* out_http_status);


#endif