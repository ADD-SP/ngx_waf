#ifndef __NGX_HTTP_WAF_MODULE_SHM_H__

#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_mem_pool.h>


void ngx_http_waf_shm_clear_inner_data();


ngx_int_t ngx_http_waf_shm_init(shm_t* shm, ngx_conf_t* cf, ngx_str_t* name, size_t size);


shm_init_t* ngx_http_waf_shm_init_handler_add(shm_t* shm);


ngx_int_t ngx_http_waf_shm_gc(shm_t* shm);


shm_t* ngx_http_waf_shm_get(ngx_str_t* name);


ngx_int_t ngx_http_waf_shm_tag_is_used(ngx_str_t* name, ngx_str_t* tag);


#endif