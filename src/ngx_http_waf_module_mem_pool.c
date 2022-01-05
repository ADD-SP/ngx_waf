#include <ngx_http_waf_module_mem_pool.h>

ngx_int_t mem_pool_init(mem_pool_t* pool, mem_pool_type_e type, void* native_pool) {
    if (pool == NULL || (type != std && native_pool == NULL)) {
        return NGX_HTTP_WAF_FAIL;
    }

    pool->type = type;
    
    switch (type) {
        case std: break;
        case gernal_pool: pool->native_pool.gernal_pool = (ngx_pool_t*)native_pool; break;
        case slab_pool: pool->native_pool.slab_pool = (ngx_slab_pool_t*)native_pool; break;
    }

    return NGX_HTTP_WAF_SUCCESS;
}

void* mem_pool_calloc(mem_pool_t* pool, ngx_uint_t byte_size) {
    void* addr;
    switch (pool->type) {
        case std: addr = malloc(byte_size); ngx_memzero(addr, byte_size); break;
        case gernal_pool: addr = ngx_pcalloc(pool->native_pool.gernal_pool, byte_size); break;
        case slab_pool: addr = ngx_slab_calloc_locked(pool->native_pool.slab_pool, byte_size); break;
        default: addr = NULL; break;
    }
    return addr;
}

ngx_int_t mem_pool_free(mem_pool_t* pool, void* buffer) {
    switch (pool->type) {
        case std: free(buffer); break;
        case gernal_pool: ngx_pfree(pool->native_pool.gernal_pool, buffer); break;
        case slab_pool: ngx_slab_free_locked(pool->native_pool.slab_pool, buffer); break;
        default: return NGX_HTTP_WAF_FAIL;
    }
    return NGX_HTTP_WAF_SUCCESS;
}