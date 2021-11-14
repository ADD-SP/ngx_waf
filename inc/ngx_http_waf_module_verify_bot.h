#ifndef __NGX_HTTP_WAF_VERIFY_BOT_H__
#define __NGX_HTTP_WAF_VERIFY_BOT_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_check.h>


ngx_int_t ngx_http_waf_handler_verify_bot(ngx_http_request_t* r);


#endif