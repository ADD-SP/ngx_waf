#ifndef __NGX_HTTP_WAF_MODULE_VM_H__
#define __NGX_HTTP_WAF_MODULE_VM_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_check.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_inet.h>
#include <utstack.h>
#include <libinjection/src/libinjection.h>
#include <libinjection/src/libinjection_sqli.h>
#include <libinjection/src/libinjection_xss.h>

void ngx_http_waf_print_code(UT_array* array);


/**
 * @brief 执行高级规则
 * @param[out] out_http_status 要返回的 HTTP 状态码
 * @return 如果命中规则则返回 NGX_HTTP_WAF_MATCHED，反之则为 NGX_HTTP_WAF_NOT_MATCHED。
*/ 
ngx_int_t ngx_http_waf_vm_exec(ngx_http_request_t* r, ngx_int_t* out_http_status);

#endif