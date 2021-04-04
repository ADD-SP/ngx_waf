/**
 * @file ngx_http_waf_module_token_bucket_set.h
 * @brief IP 令牌桶集合
*/

#ifndef __NGX_HTTP_WAF_MODULE_TOKEN_BUCKET_SET_H__
#define __NGX_HTTP_WAF_MODULE_TOKEN_BUCKET_SET_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_mem_pool.h>

/**
 * @defgroup token_bucket_set IP 令牌桶集合
 * @addtogroup token_bucket_set IP 令牌桶集合
 * @{
*/


/**
 * @brief 初始化一个令牌桶集合
 * @param[out] set 要操作的令牌桶集合
 * @param[in] pool_type 内存池类型
 * @param[in] memory_pool 内存池
 * @param[in] init_count 令牌桶初始令牌数
 * @param[in] ban_duration 令牌桶为空后令牌桶的拉黑时间（分钟）
 * @return 如果成功返回 NGX_HTTP_WAF_SUCCESS，反之则不是。
*/
ngx_int_t token_bucket_set_init(token_bucket_set_t* set, 
                                mem_pool_type_e pool_type, 
                                void* memory_pool,
                                ngx_uint_t init_count,
                                ngx_uint_t ban_duration);


/**
 * @brief 从一个令牌桶中取出一定数量的令牌，如果不存在则自动初始化并填充令牌。
 * @param[in] set 要操作的令牌桶集合。
 * @param[in] inx_addr IP 地址。
 * @param[in] count 取出的令牌数。
 * @param[in] init_count 初始化令牌桶时填充的令牌数量。
 * @return 如果成功返回 NGX_HTTP_WAF_SUCCESS，反之则不是。
 * @note 时间复杂度 O(1)。
*/
ngx_int_t token_bucket_set_take(token_bucket_set_t* set, inx_addr_t* inx_addr, ngx_uint_t count, time_t now);


/**
 * @brief 从一个令牌桶中取出一定数量的令牌，如果不存在则自动初始化并填充令牌。
 * @param[in] set 要操作的令牌桶集合。
 * @param[in] inx_addr IP 地址，如果为 NULL 则为所有令牌桶填充令牌。
 * @param[in] count 填充的数量，如果 inx_addr 为 NULL 则会将所有令牌桶的数量设置为 count，而不是增加。
 * @return 如果成功返回 NGX_HTTP_WAF_SUCCESS，反之则不是。
 * @note 时间复杂度当 inx_addr 不为 NULL 时为 O(1)，反之为 O(n)。
*/
ngx_int_t token_bucket_set_put(token_bucket_set_t* set, inx_addr_t* inx_addr, ngx_uint_t count, time_t now);


/**
 * @brief 清空令牌桶
 * @param[in] set 要操作的令牌桶集合。
 * @return 如果成功返回 SUCCESS，反之则不是。
 * @retval NGX_HTTP_WAF_SUCCESS 成功
 * @note 时间复杂度 O(n)
*/
ngx_int_t token_bucket_set_clear(token_bucket_set_t* set);

/**
 * @}
*/



ngx_int_t token_bucket_set_init(token_bucket_set_t* set, 
                                mem_pool_type_e pool_type, 
                                void* memory_pool,
                                ngx_uint_t init_count,
                                ngx_uint_t ban_duration) {
    if (set == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (mem_pool_init(&set->pool, pool_type, memory_pool) != NGX_HTTP_WAF_SUCCESS) {
        return NGX_HTTP_WAF_FAIL;
    }

    set->bucket_count = 0;
    set->head = NULL;
    set->last_clear = time(NULL);
    set->last_put = time(NULL);
    set->init_count = init_count;
    set->ban_duration = ban_duration;
    
    return NGX_HTTP_WAF_SUCCESS;
}

ngx_int_t token_bucket_set_take(token_bucket_set_t* set, inx_addr_t* inx_addr, ngx_uint_t count, time_t now) {
    token_bucket_t* bucket = NULL;
    HASH_FIND(hh, set->head, inx_addr, sizeof(inx_addr_t), bucket);

    if (bucket == NULL) {
        bucket = (token_bucket_t*)mem_pool_calloc(&(set->pool), sizeof(token_bucket_t));
        if (bucket == NULL) {
            return NGX_HTTP_WAF_MALLOC_ERROR;
        } else {
            ngx_memcpy(&(bucket->inx_addr), inx_addr, sizeof(inx_addr_t));
            bucket->count = set->init_count;
            bucket->is_ban = NGX_HTTP_WAF_FALSE;
            bucket->last_ban_time = 0;
            HASH_ADD(hh, set->head, inx_addr, sizeof(inx_addr_t), bucket);
        }
    }

    if (bucket->is_ban == NGX_HTTP_WAF_FALSE) {
        if (bucket->count >= count) {
            bucket->count -= count;
        } else {
            bucket->is_ban = NGX_HTTP_WAF_TRUE;
            bucket->last_ban_time = now;
            return NGX_HTTP_WAF_FAIL;
        }
    } else {
        return NGX_HTTP_WAF_FAIL;
    }

    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t token_bucket_set_put(token_bucket_set_t* set, inx_addr_t* inx_addr, ngx_uint_t count, time_t now) {
    token_bucket_t* bucket = NULL;

    if (inx_addr != NULL) {
        HASH_FIND(hh, set->head, &bucket->inx_addr, sizeof(inx_addr_t), bucket);

        if (bucket == NULL) {
            bucket = (token_bucket_t*)mem_pool_calloc(&(set->pool), sizeof(token_bucket_t));
            if (bucket == NULL) {
                return NGX_HTTP_WAF_MALLOC_ERROR;
            } else {
                ngx_memcpy(&(bucket->inx_addr), inx_addr, sizeof(inx_addr_t));
                bucket->is_ban = NGX_HTTP_WAF_FALSE;
                bucket->last_ban_time = 0;
                bucket->count = count;
                HASH_ADD(hh, set->head, inx_addr, sizeof(inx_addr_t), bucket);  
            }
        }

        if (bucket->is_ban == NGX_HTTP_WAF_TRUE) {
            double diff_time_minute = difftime(now, bucket->last_ban_time) / 60;
            if (diff_time_minute > set->ban_duration) {
                bucket->is_ban = NGX_HTTP_WAF_FALSE;
                bucket->count = count;
            }
        } else {
            bucket->count += count;
        }

    } else {
        for (bucket = set->head; bucket != NULL; bucket = (token_bucket_t*)(bucket->hh.next)) {
            if (bucket->is_ban == NGX_HTTP_WAF_TRUE) {
                double diff_time_minute = difftime(now, bucket->last_ban_time) / 60;
                if (diff_time_minute > set->ban_duration) {
                    bucket->is_ban = NGX_HTTP_WAF_FALSE;
                    bucket->count = count;
                }
            } else {
                bucket->count = count;
            }
        }
    }

    return NGX_HTTP_WAF_SUCCESS;
}

ngx_int_t token_bucket_set_clear(token_bucket_set_t* set) {
    token_bucket_t *p = NULL, *prev = NULL;
    for (p = set->head; p != NULL; ) {
        prev = p;
        p = (token_bucket_t*)(p->hh.next);
        if (mem_pool_free(&(set->pool), prev) != NGX_HTTP_WAF_SUCCESS) {
            set->head = NULL;
            return NGX_HTTP_WAF_FAIL;
        }
    }
    set->head = NULL;
    return NGX_HTTP_WAF_SUCCESS;
}

#endif
