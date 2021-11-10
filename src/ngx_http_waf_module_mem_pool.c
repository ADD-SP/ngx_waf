#include <ngx_http_waf_module_mem_pool.h>

ngx_int_t mem_pool_init(mem_pool_t* pool, mem_pool_flag_e flag, void* native_pool) {
    pool->flag = flag;
    pool->native_pool = native_pool;
    return NGX_HTTP_WAF_SUCCESS;
}

void* mem_pool_calloc(mem_pool_t* pool, ngx_uint_t byte_size) {
    if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_STDC)) {
        return calloc(sizeof(uint8_t), byte_size);

    } else if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_NGX_SHARD)) {
        return ngx_slab_calloc_locked(pool->native_pool, byte_size);

    } else if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_NGX)) {
        return ngx_pcalloc(pool->native_pool, byte_size);

    } else {
        abort();
    }
}

void mem_pool_free(mem_pool_t* pool, void* buffer) {
    if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_STDC)) {
        free(buffer);

    } else if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_NGX_SHARD)) {
        ngx_slab_free_locked(pool->native_pool, buffer);

    } else if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_NGX)) {
        ngx_pfree(pool->native_pool, buffer);

    } else {
        abort();
    }
}