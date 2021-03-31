/**
 * @file ngx_http_waf_module_memory_pool.h
 * @brief 内存池
*/


#ifndef __NGX_HTTP_WAF_MODULE_MEMORY_POOL_H__
#define __NGX_HTTP_WAF_MODULE_MEMORY_POOL_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>


/**
 * @brief 初始化一个内存池
 * @param[out] pool 要初始化的内存池
 * @param[in] type 内存池类型
 * @param[in] native_pool 内存池
 * @return 如果成功返回 SUCCESS，反之则不是。
 * @retval SUCCESS 成功
 * @retval 其它 失败 
*/
static ngx_int_t mem_pool_init(mem_pool_t* pool, mem_pool_type_e type, void* native_pool);

/**
 * @brief 申请一段连续的内存
 * @param[in] pool 要操作的内存池
 * @param[in] byte_size 内存的字节数
 * @return 成功则返回内存首地址，反之为 NULL。
*/
static void* mem_pool_calloc(mem_pool_t* pool, ngx_uint_t byte_size);

/**
 * @brief 释放一段连续的内存
 * @param[in] pool 要操作的内存池
 * @param[in] buffer 内存的首地址
 * @return 成功则返回 SUCCESS，反之则不是。
*/
static ngx_int_t mem_pool_free(mem_pool_t* pool, void* buffer);

static ngx_int_t mem_pool_init(mem_pool_t* pool, mem_pool_type_e type, void* native_pool) {
    if (pool == NULL || native_pool == NULL) {
        return FAIL;
    }

    pool->type = type;
    
    switch (type) {
        case gernal_pool: pool->native_pool.gernal_pool = (ngx_pool_t*)native_pool; break;
        case slab_pool: pool->native_pool.slab_pool = (ngx_slab_pool_t*)native_pool; break;
    }

    return SUCCESS;
}

static void* mem_pool_calloc(mem_pool_t* pool, ngx_uint_t byte_size) {
    void* addr;
    switch (pool->type) {
        case gernal_pool: addr = ngx_pcalloc(pool->native_pool.gernal_pool, byte_size); break;
        case slab_pool: addr = ngx_slab_calloc_locked(pool->native_pool.slab_pool, byte_size); break;
        default: addr = NULL; break;
    }
    return addr;
}

static ngx_int_t mem_pool_free(mem_pool_t* pool, void* buffer) {
    switch (pool->type) {
        case gernal_pool: ngx_pfree(pool->native_pool.gernal_pool, buffer); break;
        case slab_pool: ngx_slab_free_locked(pool->native_pool.slab_pool, buffer); break;
        default: return FAIL;
    }
    return SUCCESS;
}


#endif