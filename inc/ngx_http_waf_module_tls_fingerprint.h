#ifndef __NGX_HTTP_WAF_TLS_FINGERPRINT_H__
#define __NGX_HTTP_WAF_TLS_FINGERPRINT_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_check.h>
#include <ngx_core.h>
#include <ngx_http_v2.h>

#define IS_GREASE_CODE(code) (((code)&0x0f0f) == 0x0a0a && ((code)&0xff) == ((code)>>8))

int ngx_ssl_fingerprint(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *fingerprint);
int ngx_http2_fingerprint(ngx_connection_t *c, ngx_http_v2_connection_t *h2c, ngx_pool_t *pool, ngx_str_t *fingerprint);

#endif // __NGX_HTTP_WAF_TLS_FINGERPRINT_H__
