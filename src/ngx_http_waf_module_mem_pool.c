#include <ngx_http_waf_module_mem_pool.h>

ngx_int_t mem_pool_init(mem_pool_t* pool, mem_pool_flag_e flag, void* native_pool, size_t capacity) {
    pool->flag = flag;
    pool->native_pool = native_pool;
    pool->used = 0;

    if (!ngx_http_waf_check_flag(flag, MEM_POOL_FLAG_FIXED)) {
        pool->capacity = SIZE_MAX;

    } else {
        pool->capacity = capacity;
    }
    
    return NGX_HTTP_WAF_SUCCESS;
}

void* mem_pool_calloc(mem_pool_t* pool, ngx_uint_t byte_size) {
    ngx_uint_t* ptr = NULL;
    ngx_uint_t _byte_size = byte_size + sizeof(ngx_uint_t);

    if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_FIXED)) {
        if (pool->used + _byte_size > pool->capacity) {
            return NULL;
        }
    }

    if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_STDC)) {
        ptr = calloc(sizeof(uint8_t), _byte_size);

    } else if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_NGX_SHARD)) {
        ptr = ngx_slab_calloc_locked(pool->native_pool, _byte_size);

    } else if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_NGX)) {
        ptr = ngx_pcalloc(pool->native_pool, _byte_size);

    } else {
        abort();
    }

    pool->used += _byte_size;
    ptr[0] = _byte_size;
    return ptr + 1;
}

void mem_pool_free(mem_pool_t* pool, void* ptr) {
    ngx_uint_t* _ptr = (ngx_uint_t*)(ptr) - 1;
    ngx_uint_t _byte_size = _ptr[0];

    if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_STDC)) {
        free(_ptr);

    } else if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_NGX_SHARD)) {
        ngx_slab_free_locked(pool->native_pool, _ptr);

    } else if (ngx_http_waf_check_flag(pool->flag, MEM_POOL_FLAG_NGX)) {
        ngx_pfree(pool->native_pool, _ptr);

    } else {
        abort();
    }

    pool->used -= _byte_size;
}