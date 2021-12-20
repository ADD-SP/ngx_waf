/**
 * @file ngx_http_waf_module_lru_cache.h.h
 * @brief LRU 缓存管理器
*/

#ifndef __NGX_HTTP_WAF_MODULE_LRU_CACHE_H__
#define __NGX_HTTP_WAF_MODULE_LRU_CACHE_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_mem_pool.h>


void lru_cache_init(lru_cache_t** lru, size_t capacity, mem_pool_t* pool);


lru_cache_add_result_t lru_cache_add(lru_cache_t* lru, void* key, size_t key_len, time_t expire);


lru_cache_find_result_t lru_cache_find(lru_cache_t* lru, void* key, size_t key_len);


void lru_cache_set_expire(lru_cache_t* lru, void* key, size_t key_len, time_t expire);


void* lru_cache_calloc(lru_cache_t* lru, size_t size);


void lru_cache_free(lru_cache_t* lru, void* addr);


void lru_cache_delete(lru_cache_t* lru, void* key, size_t key_len);


ngx_uint_t lru_cache_eliminate_expire(lru_cache_t* lru, size_t count);


ngx_uint_t lru_cache_eliminate(lru_cache_t* lru, size_t count);


void lru_cache_clear(lru_cache_t* lru);


void lru_cache_destroy(lru_cache_t* lru);


#endif