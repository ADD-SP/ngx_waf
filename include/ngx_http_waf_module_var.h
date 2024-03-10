#ifndef __NGX_HTTP_WAF_VAR_H__
#define __NGX_HTTP_WAF_VAR_H__

#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_util.h>


/**
 * @brief 添加所有的内置变量。
*/
ngx_int_t ngx_http_waf_install_add_var(ngx_conf_t* cf);


#endif
