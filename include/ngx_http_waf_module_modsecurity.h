#ifndef __NGX_hTTP_WAF_MODULE_MODSECURITY_H__
#define __NGX_hTTP_WAF_MODULE_MODSECURITY_H__

#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_check.h>


void ngx_http_waf_header_filter_init();


void ngx_http_waf_body_filter_init();


void ngx_http_waf_modsecurity_handler_log(void* log, const void* data);


ngx_int_t ngx_http_waf_handler_modsecurity(ngx_http_request_t* r);


ngx_int_t ngx_http_waf_header_filter(ngx_http_request_t *r);


ngx_int_t ngx_http_waf_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

#endif