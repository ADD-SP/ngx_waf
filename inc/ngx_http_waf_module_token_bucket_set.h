/**
 * @file ngx_http_waf_module_token_bucket_set.h
 * @brief IP 令牌桶集合
*/

#ifndef __NGX_HTTP_WAF_MODULE_TOKEN_BUCKET_SET_H__
#define __NGX_HTTP_WAF_MODULE_TOKEN_BUCKET_SET_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>

/**
 * @defgroup token_bucket_set IP 令牌桶集合
 * @addtogroup token_bucket_set IP 令牌桶集合
 * @{
*/


/**
 * @brief 初始化一个令牌桶集合
 * @param[out] set 要操作的令牌桶集合
 * @param[in] memory_pool_type_e 内存池类型
 * @param[in] memory_pool 内存池
 * @param[in] init_count 令牌桶初始令牌数
 * @param[in] ban_duration 令牌桶为空后令牌桶的拉黑时间（分钟）
 * @return 如果成功返回 SUCCESS，反之则不是。
 * @retval SUCCESS 成功
 * @retval 其它 失败
*/
ngx_int_t token_bucket_set_init(token_bucket_set_t* set, 
                                memory_pool_type_e pool_type, 
                                void* memory_pool,
                                ngx_uint_t init_count,
                                ngx_uint_t ban_duration);


/**
 * @brief 从一个令牌桶中取出一定数量的令牌，如果不存在则自动初始化并填充令牌。
 * @param[in] set 要操作的令牌桶集合。
 * @param[in] inx_addr IP 地址。
 * @param[in] count 取出的令牌数。
 * @param[in] init_count 初始化令牌桶时填充的令牌数量。
 * @return 如果成功返回 SUCCESS，反之则不是。
 * @retval SUCCESS 成功
 * @retval 其它 失败
 * @note 时间复杂度 O(1)。
*/
ngx_int_t token_bucket_set_take(token_bucket_set_t* set, inx_addr_t* inx_addr, ngx_uint_t count, time_t now);


/**
 * @brief 从一个令牌桶中取出一定数量的令牌，如果不存在则自动初始化并填充令牌。
 * @param[in] set 要操作的令牌桶集合。
 * @param[in] inx_addr IP 地址，如果为 NULL 则为所有令牌桶填充令牌。
 * @param[in] count 填充的数量，如果 inx_addr 为 NULL 则会将所有令牌桶的数量设置为 count，而不是增加。
 * @return 如果成功返回 SUCCESS，反之则不是。
 * @retval SUCCESS 成功
 * @retval 其它 失败
 * @note 时间复杂度当 inx_addr 不为 NULL 时为 O(1)，反之为 O(n)。
*/
ngx_int_t token_bucket_set_put(token_bucket_set_t* set, inx_addr_t* inx_addr, ngx_uint_t count, time_t now);


/**
 * @brief 清空令牌桶
 * @param[in] set 要操作的令牌桶集合。
 * @return 如果成功返回 SUCCESS，反之则不是。
 * @retval SUCCESS 成功
 * @retval 其它 失败
 * @note 时间复杂度 O(n)
*/
ngx_int_t token_bucket_set_clear(token_bucket_set_t* set);

/**
 * @brief 申请并自动清零一段内存。
 * @param[in] set 要操作的令牌桶集合
 * @param[in] size 内存的字节长度
 * @return 如果成功则返回首地址，反之返回 NULL。
 * @retval NULL 失败
 * @retval 其它 成功
*/
void* _token_bucket_set_malloc(token_bucket_set_t* set, size_t size);

/**
 * @brief 释放一段内存。
 * @param[in] set 要操作的令牌桶集合
 * @param[in] 要释放的内存的首地址
 * @return 如果成功返回 SUCCESS，反之则不是。
 * @retval SUCCESS 成功
 * @retval 其它 失败
*/
ngx_int_t _token_bucket_set_free(token_bucket_set_t* set, void* addr);

/**
 * @}
*/



ngx_int_t token_bucket_set_init(token_bucket_set_t* set, 
                                memory_pool_type_e pool_type, 
                                void* memory_pool,
                                ngx_uint_t init_count,
                                ngx_uint_t ban_duration) {
    if (set == NULL || memory_pool == NULL) {
        return FAIL;
    }

    set->memory_pool_type = pool_type;
    set->memory_pool = memory_pool;
    set->bucket_count = 0;
    set->head = NULL;
    set->last_clear = time(NULL);
    set->last_put = time(NULL);
    set->init_count = init_count;
    set->ban_duration = ban_duration;
    
    return SUCCESS;
}

ngx_int_t token_bucket_set_take(token_bucket_set_t* set, inx_addr_t* inx_addr, ngx_uint_t count, time_t now) {
    token_bucket_t* bucket = NULL;
    ngx_int_t ret_status = SUCCESS;
    HASH_FIND(hh, set->head, inx_addr, sizeof(inx_addr_t), bucket);

    if (bucket == NULL) {
        bucket = (token_bucket_t*)_token_bucket_set_malloc(set, sizeof(token_bucket_t));
        if (bucket == NULL) {
            ret_status = FAIL;
        }
        memcpy(&(bucket->inx_addr), inx_addr, sizeof(inx_addr_t));
        bucket->count = set->init_count;
        bucket->is_ban = FALSE;
        bucket->last_ban_time = 0;
        HASH_ADD(hh, set->head, inx_addr, sizeof(inx_addr_t), bucket);
    }

    if (ret_status == SUCCESS && bucket->is_ban == FALSE) {
        if (bucket->count >= count) {
            bucket->count -= count;
        } else {
            bucket->is_ban = TRUE;
            bucket->last_ban_time = now;
            ret_status = FAIL;
        }
    } else {
        ret_status = FAIL;
    }

    return ret_status;
}


ngx_int_t token_bucket_set_put(token_bucket_set_t* set, inx_addr_t* inx_addr, ngx_uint_t count, time_t now) {
    token_bucket_t* bucket = NULL;
    ngx_int_t ret_status = SUCCESS;

    if (inx_addr != NULL) {
        HASH_FIND(hh, set->head, &bucket->inx_addr, sizeof(inx_addr_t), bucket);

        if (bucket == NULL) {
            bucket = (token_bucket_t*)_token_bucket_set_malloc(set, sizeof(token_bucket_t));
            if (bucket == NULL) {
                ret_status = FAIL;
            }
            memcpy(&(bucket->inx_addr), inx_addr, sizeof(inx_addr_t));
            bucket->is_ban = FALSE;
            bucket->last_ban_time = 0;
            bucket->count = count;
            HASH_ADD(hh, set->head, inx_addr, sizeof(inx_addr_t), bucket);
        }

        if (ret_status == SUCCESS) {
           if (bucket->is_ban == TRUE) {
                double diff_time_minute = difftime(now, bucket->last_ban_time) / 60;
                if (diff_time_minute > set->ban_duration) {
                    bucket->is_ban = FALSE;
                    bucket->count = count;
                }
            } else {
                bucket->count += count;
            }
        }
    } else {
        for (bucket = set->head; bucket != NULL; bucket = (token_bucket_t*)(bucket->hh.next)) {
            if (bucket->is_ban == TRUE) {
                double diff_time_minute = difftime(now, bucket->last_ban_time) / 60;
                if (diff_time_minute > set->ban_duration) {
                    bucket->is_ban = FALSE;
                    bucket->count = count;
                }
            } else {
                bucket->count = count;
            }
        }
    }

    return ret_status;
}

ngx_int_t token_bucket_set_clear(token_bucket_set_t* set) {
    token_bucket_t *p, *prev;
    for (p = set->head; p != NULL; ) {
        prev = p;
        p = (token_bucket_t*)(p->hh.next);
        if (_token_bucket_set_free(set, prev) != SUCCESS) {
            set->head = NULL;
            return FAIL;
        }
    }
    set->head = NULL;
    return SUCCESS;
}


void* _token_bucket_set_malloc(token_bucket_set_t* set, size_t size) {
    void* addr;
    switch (set->memory_pool_type) {
        case gernal_pool: addr = ngx_pcalloc((ngx_pool_t*)set->memory_pool, size); break;
        case slab_pool: addr = ngx_slab_calloc_locked((ngx_slab_pool_t*)set->memory_pool, size); break;
        default: addr = NULL; break;
    }
    return addr;
}

ngx_int_t _token_bucket_set_free(token_bucket_set_t* set, void* addr) {
    switch (set->memory_pool_type) {
        case gernal_pool: ngx_pfree((ngx_pool_t*)set->memory_pool, addr); break;
        case slab_pool: ngx_slab_free_locked((ngx_slab_pool_t*)set->memory_pool, addr); break;
        default: return FAIL;
    }
    return SUCCESS;
}

#endif