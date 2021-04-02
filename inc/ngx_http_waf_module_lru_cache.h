/**
 * @file ngx_http_waf_module_lru_cache.h.h
 * @brief IP 令牌桶集合
*/

#ifndef __NGX_HTTP_WAF_MODULE_LRU_CACHE_H__
#define __NGX_HTTP_WAF_MODULE_LRU_CACHE_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_mem_pool.h>

/**
 * @brief 初始化一个 LRU 缓存管理器
 * @param[out] manager 要初始化的 LRU 缓存管理器
 * @param[in] pool_type 所使用的内存池的类型
 * @param[in] native_pool 要使用的内存池的指针
 * @return 如果成功则返回 SUCCESS，反之则不是。
*/
static ngx_int_t lru_cache_manager_init(lru_cache_manager_t* manager, 
                                        ngx_uint_t capacity, 
                                        mem_pool_type_e pool_type, 
                                        void* native_pool);

/**
 * @brief 添加一个缓存项
 * @param[in] manager 要操作的 LRU 缓存管理器
 * @param[in] u_char 用于查询缓存的关键字指针
 * @param[in] key_byte_length 关键字占用的字节数
 * @param[in] match_status 要缓存的规则匹配结果
 * @param[in] rule_detail 要缓存的被匹配的规则的细节
 * @return 如果成功则返回 SUCCESS，反之则不是。
 * @note 如果内存不足会按照 LRU 策略自动淘汰其它缓存项。
 * @note 如果关键字已经存在则什么都不做，返回 SUCCESS。
*/
static ngx_int_t lru_cache_manager_add( lru_cache_manager_t* manager, 
                                        u_char* key, 
                                        ngx_uint_t key_byte_length, 
                                        ngx_int_t match_status,
                                        u_char* rule_detail);

/**
 * @brief 查询缓存项
 * @param[in] manager 要操作的 LRU 缓存管理器
 * @param[in] u_char 用于查询缓存的关键字指针
 * @param[in] key_byte_length 关键字占用的字节数
 * @param[in] out_match_status 被缓存的规则匹配结果
 * @param[in] out_rule_detail 被缓存的被匹配的规则的细节
 * @return 如果缓存项存在则返回 SUCCESS，反之则不是。
*/
static ngx_int_t lru_cache_manager_find(lru_cache_manager_t* manager, 
                                        u_char* key, 
                                        ngx_uint_t key_byte_length,
                                        ngx_int_t* out_match_status,
                                        u_char** out_rule_detail);


/**
 * @brief 删除一个缓存项
 * @param[in] manager 要操作的 LRU 缓存管理器
 * @param[in] u_char 用于查询缓存的关键字指针
 * @param[in] key_byte_length 关键字占用的字节数
 * @return 如果缓存项存在则返回 SUCCESS，反之则不是。
*/
static ngx_int_t lru_cache_manager_remove(  lru_cache_manager_t* manager, 
                                            u_char* key, 
                                            ngx_uint_t key_byte_length);

/**
 * @brief 按照 LRU 策略淘汰掉一个缓存项
 * @param[in] manager 要操作的 LRU 缓存管理器
 * @return 如果淘汰成功则返回 SUCCESS，反之则不是。
*/
static ngx_int_t lru_cache_manager_eliminate(lru_cache_manager_t* manager);

/**
 * @brief 按照 LRU 策略淘汰掉一定百分比的缓存项
 * @param[in] manager 要操作的 LRU 缓存管理器
 * @param[in] percent 要淘汰掉的缓存项所占总量的百分比
 * @return 如果淘汰成功则返回 SUCCESS，反之则不是。
 * @warning 此函数无论成功与否都会清零 eliminate_times 字段。
*/
static ngx_int_t lru_cache_manager_eliminate_percent(lru_cache_manager_t* manager, double percent);

// static void lru_cache_manager_clear(lru_cache_manager_t* manager);




static ngx_int_t lru_cache_manager_init(lru_cache_manager_t* manager, 
                                        ngx_uint_t capacity,
                                        mem_pool_type_e pool_type, 
                                        void* native_pool) {
    if (manager == NULL) {
        return FAIL;
    }

    if (mem_pool_init(&(manager->pool), pool_type, native_pool) != SUCCESS) {
        return FAIL;
    }

    manager->last_eliminate = time(NULL);
    manager->capacity = capacity;
    manager->size = 0;
    manager->hash_head = NULL;
    manager->chain_head = NULL;

    return SUCCESS;
}

static ngx_int_t lru_cache_manager_add( lru_cache_manager_t* manager, 
                                        u_char* key, 
                                        ngx_uint_t key_byte_length, 
                                        ngx_int_t match_status,
                                        u_char* rule_detail) {
    if (manager == NULL || key == NULL) {
        return FAIL;
    }

    lru_cache_item_t* hash_item = NULL;
    HASH_FIND(hh, manager->hash_head, key, key_byte_length, hash_item);
    if (hash_item != NULL) {
        return SUCCESS;
    }

    hash_item = NULL;
    lru_cache_item_t* chain_item = NULL;

    while (manager->size + 1 > manager->capacity) {
        if (lru_cache_manager_eliminate(manager) != SUCCESS) {
            return FAIL;
        }
    }
    
    do {
        chain_item = (lru_cache_item_t*)mem_pool_calloc(&(manager->pool), sizeof(lru_cache_item_t));
        if (chain_item == NULL && lru_cache_manager_eliminate(manager) == FAIL) {
            return FAIL;
        }
    } while (chain_item == NULL);

    do {
        hash_item = (lru_cache_item_t*)mem_pool_calloc(&(manager->pool), sizeof(lru_cache_item_t));
        if (hash_item == NULL && lru_cache_manager_eliminate(manager) == FAIL) {
            return FAIL;
        }
    } while (hash_item == NULL);

    u_char* key_copy = NULL;
    do {
        key_copy = (u_char*)mem_pool_calloc(&(manager->pool), key_byte_length);
        if (key_copy == NULL && lru_cache_manager_eliminate(manager) == FAIL) {
            return FAIL;
        }
    } while (key_copy == NULL);
    ngx_memcpy(key_copy, key, key_byte_length);

    chain_item->key = key_copy;
    chain_item->value.value.match_status = match_status;
    chain_item->value.value.rule_detail = rule_detail;
    hash_item->key = key_copy;
    hash_item->value.chain_item = chain_item;

    CDL_PREPEND(manager->chain_head, chain_item);
    HASH_ADD_KEYPTR(hh, manager->hash_head, key_copy, key_byte_length, hash_item);
    ++(manager->size);

    return SUCCESS;
}


static ngx_int_t lru_cache_manager_find(lru_cache_manager_t* manager, 
                                        u_char* key, 
                                        ngx_uint_t key_byte_length,
                                        ngx_int_t* out_match_status,
                                        u_char** out_rule_detail) {
    if (manager == NULL || key == NULL || out_match_status == NULL) {
        return FAIL;
    }

    lru_cache_item_t* hash_item = NULL;
    HASH_FIND(hh, manager->hash_head, key, key_byte_length, hash_item);
    if (hash_item == NULL) {
        return FAIL;
    }

    lru_cache_item_t* chain_item = hash_item->value.chain_item;
    *out_match_status = chain_item->value.value.match_status;
    *out_rule_detail = chain_item->value.value.rule_detail;

    CDL_DELETE(manager->chain_head, chain_item);
    CDL_PREPEND(manager->chain_head, chain_item);

    return SUCCESS;

}


static ngx_int_t lru_cache_manager_remove(  lru_cache_manager_t* manager, 
                                            u_char* key, 
                                            ngx_uint_t key_byte_length) {
    if (manager == NULL || key == NULL) {
        return FAIL;
    }

    lru_cache_item_t* hash_item = NULL;
    HASH_FIND(hh, manager->hash_head, key, key_byte_length, hash_item);
    if (hash_item == NULL) {
        return FAIL;
    }
    HASH_DELETE(hh, manager->hash_head, hash_item);

    lru_cache_item_t* chain_item = hash_item->value.chain_item;
    CDL_DELETE(manager->chain_head, chain_item);

    if (    mem_pool_free(&(manager->pool), chain_item->key)    != SUCCESS 
        ||  mem_pool_free(&(manager->pool), hash_item)          != SUCCESS
        ||  mem_pool_free(&(manager->pool), chain_item)         != SUCCESS) {
        return FAIL;
    }

    --(manager->size);
    return SUCCESS;
}


static ngx_int_t lru_cache_manager_eliminate(lru_cache_manager_t* manager) {
    if (manager == NULL || manager->chain_head == NULL || manager->hash_head == NULL) {
        return FAIL;
    }

    lru_cache_item_t* chain_tail = manager->chain_head->prev;

    ngx_int_t ret = lru_cache_manager_remove(manager, chain_tail->key, chain_tail->key_byte_length);

    return ret;
}


static ngx_int_t lru_cache_manager_eliminate_percent(lru_cache_manager_t* manager, double percent) {
    if (manager == NULL || percent > 1.0) {
        return FAIL;
    }

    ngx_uint_t target_size = (ngx_uint_t)((double)(manager->size) * (1.0 - percent));

    while (manager->size > target_size) {
        ngx_int_t ret = lru_cache_manager_eliminate(manager);
        if (ret != SUCCESS) {
            return ret;
        }
    }
    
    return SUCCESS;
}

// static void lru_cache_manager_clear(lru_cache_manager_t* manager) {
//     while (lru_cache_manager_eliminate(manager) == SUCCESS) {}
// }

#endif