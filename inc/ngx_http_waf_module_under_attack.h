#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_check.h>

#ifndef __NGX_HTTP_WAF_MODULE_UNDER_ATTACK_H__
#define __NGX_HTTP_WAF_MODULE_UNDER_ATTACK_H__


extern ngx_module_t ngx_http_waf_module; /**< 模块详情 */

/**
 * @brief 进行五秒盾检测
*/
ngx_int_t ngx_http_waf_check_under_attack(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 生成用于验证五秒盾的三个 Cookie
*/
ngx_int_t ngx_http_waf_gen_cookie(ngx_http_request_t *r);


/**
 * @brief 生成 Cookie 完整性校验码
 * @param[in] uid  对应 Cookie __waf_under_attack_uid
 * @param[in] uid_len 不包括结尾的 \0
 * @param[out] dst 对应 Cookie __waf_under_attack_verification，生成的校验码将保存到此处。
 * @param[in] dst_len 不包括结尾的 \0
 * @param[in] now 对应 Cookie __waf_under_attack_time
 * @param[in] now_len 不包括结尾的 \0
*/
ngx_int_t ngx_http_waf_gen_verification(ngx_http_request_t *r, 
                                                u_char* uid, 
                                                size_t uid_len, 
                                                u_char* dst, 
                                                size_t dst_len, 
                                                u_char* now,
                                                size_t now_len);


void ngx_http_waf_gen_ctx_and_header_location(ngx_http_request_t *r);


#endif