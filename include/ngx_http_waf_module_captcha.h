#ifndef __NGX_HTTP_WAF_MODULE_CAPTCHA_H__
#define __NGX_HTTP_WAF_MODULE_CAPTCHA_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_action.h>
#include <ngx_http_waf_module_check.h>
#include <cjson/cJSON.h>


ngx_int_t ngx_http_waf_handler_captcha(ngx_http_request_t* r);


ngx_int_t ngx_http_waf_captcha_test(ngx_http_request_t* r);


ngx_int_t ngx_http_waf_captcha_inc_fails(ngx_http_request_t* r);


#endif