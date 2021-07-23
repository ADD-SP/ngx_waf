/**
 * @file ngx_http_waf_module_lru_cache.h.h
 * @brief IP 令牌桶集合
*/

#ifndef __NGX_HTTP_WAF_MODULE_LRU_CACHE_H__
#define __NGX_HTTP_WAF_MODULE_LRU_CACHE_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_mem_pool.h>


void lru_cache_init(lru_cache_t** lru, size_t capacity, mem_pool_type_e pool_type, void* native_pool);

lru_cache_add_result_t lru_cache_add(lru_cache_t* lru, void* key, size_t key_len);

lru_cache_find_result_t lru_cache_find(lru_cache_t* lru, void* key, size_t key_len);

void lru_cache_delete(lru_cache_t* lru, void* key, size_t key_len);

void lru_cache_eliminate(lru_cache_t* lru, size_t count);

lru_cache_item_t* _lru_cache_hash_find(lru_cache_t* lru, void* key, size_t key_len);

void _lru_cache_hash_add(lru_cache_t* lru, lru_cache_item_t* item);

void _lru_cache_hash_delete(lru_cache_t* lru, lru_cache_item_t* item);

void* _lru_cache_hash_calloc(lru_cache_t* lru, size_t n);

void _lru_cache_hash_free(lru_cache_t* lru, void* addr);


#endif