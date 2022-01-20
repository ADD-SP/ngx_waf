#ifndef __NGX_HTTP_WAF_MODULE_SYSGUARD_H__
#define __NGX_HTTP_WAF_MODULE_SYSGUARD_H__

#include <stdlib.h>
#include <sys/sysinfo.h>
#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_action.h>


ngx_int_t ngx_http_waf_handler_sysguard(ngx_http_request_t* r);

#endif