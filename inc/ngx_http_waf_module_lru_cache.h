/**
 * @file ngx_http_waf_module_lru_cache.h.h
 * @brief LRU 缓存管理器
*/

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_mem_pool.h>

#ifndef __NGX_HTTP_WAF_MODULE_LRU_CACHE_H__
#define __NGX_HTTP_WAF_MODULE_LRU_CACHE_H__


void lru_cache_init(lru_cache_t** lru, size_t capacity, mem_pool_type_e pool_type, void* native_pool);


lru_cache_add_result_t lru_cache_add(lru_cache_t* lru, void* key, size_t key_len);


lru_cache_find_result_t lru_cache_find(lru_cache_t* lru, void* key, size_t key_len);


void* lru_cache_calloc(lru_cache_t* lru, size_t size);


void lru_cache_free(lru_cache_t* lru, void* addr);


void lru_cache_delete(lru_cache_t* lru, void* key, size_t key_len);


void lru_cache_eliminate(lru_cache_t* lru, size_t count);


void lru_cache_destory(lru_cache_t* lru);


#endif