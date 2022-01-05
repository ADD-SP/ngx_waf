#include <ngx_http_waf_module_lru_cache.h>


lru_cache_item_t* _lru_cache_hash_find(lru_cache_t* lru, void* key, size_t key_len);


void _lru_cache_hash_add(lru_cache_t* lru, lru_cache_item_t* item);


void _lru_cache_hash_delete(lru_cache_t* lru, lru_cache_item_t* item);


void* _lru_cache_hash_calloc(lru_cache_t* lru, size_t n);


void _lru_cache_hash_free(lru_cache_t* lru, void* addr);


void lru_cache_init(lru_cache_t** lru, size_t capacity, mem_pool_type_e pool_type, void* native_pool) {
    assert(lru != NULL);

    lru_cache_t* _lru;
    
    if (pool_type != std) {
        assert(native_pool != NULL);
    }

    mem_pool_t pool;
    assert(mem_pool_init(&pool, pool_type, native_pool) == NGX_HTTP_WAF_SUCCESS);

    _lru = mem_pool_calloc(&pool, sizeof(lru_cache_t));
    assert(_lru != NULL);

    ngx_memzero(_lru, sizeof(lru_cache_t));

    ngx_memcpy(&_lru->pool, &pool, sizeof(mem_pool_t));
    _lru->last_eliminate = time(NULL);
    _lru->capacity = capacity;
    _lru->hash_head = NULL;
    _lru->chain_head = NULL;

    *lru = _lru;
}


lru_cache_add_result_t lru_cache_add(lru_cache_t* lru, void* key, size_t key_len) {
    assert(lru != NULL);
    assert(key != NULL);
    assert(key_len != 0);

    lru_cache_add_result_t ret;

    lru_cache_item_t* item = _lru_cache_hash_find(lru, key, key_len);
    if (item != NULL) {
        CDL_DELETE(lru->chain_head, item);
        CDL_PREPEND(lru->chain_head, item);
        ret.status = NGX_HTTP_WAF_KEY_EXISTS;
        ret.data = &item->data;
        return ret;
    }

    if (HASH_COUNT(lru->hash_head) >= lru->capacity) {
        lru_cache_eliminate(lru, 1);
    }


    item = mem_pool_calloc(&lru->pool, sizeof(lru_cache_item_t));
    while (item == NULL && HASH_COUNT(lru->hash_head) != 0) {
        lru_cache_eliminate(lru, 1);
        item = mem_pool_calloc(&lru->pool, sizeof(lru_cache_item_t));
    }

    if (item == NULL) {
        ret.status = NGX_HTTP_WAF_MALLOC_ERROR;
        ret.data = NULL;
        return ret;
    }

    item->key_ptr = mem_pool_calloc(&lru->pool, key_len);
    while (item->key_ptr == NULL && HASH_COUNT(lru->hash_head) != 0) {
        lru_cache_eliminate(lru, 1);
        item->key_ptr = mem_pool_calloc(&lru->pool, key_len);
    }

    if (item->key_ptr == NULL) {
        mem_pool_free(&lru->pool, item);
        ret.status = NGX_HTTP_WAF_MALLOC_ERROR;
        ret.data = NULL;
        return ret;
    }

    ngx_memcpy(item->key_ptr, key, key_len);
    item->key_byte_length = key_len;
    CDL_PREPEND(lru->chain_head, item);
    _lru_cache_hash_add(lru, item);

    ret.status = NGX_HTTP_WAF_SUCCESS;
    ret.data = &item->data;

    return ret;
}


lru_cache_find_result_t lru_cache_find(lru_cache_t* lru, void* key, size_t key_len) {
    assert(lru != NULL);
    assert(key != NULL);
    assert(key_len != 0);

    lru_cache_find_result_t ret;

    lru_cache_item_t* item = _lru_cache_hash_find(lru, key, key_len);
    if (item != NULL) {
        CDL_DELETE(lru->chain_head, item);
        CDL_PREPEND(lru->chain_head, item);
        ret.status = NGX_HTTP_WAF_KEY_EXISTS;
        ret.data = &item->data;
    } else {
        ret.status = NGX_HTTP_WAF_KEY_NOT_EXISTS;
        ret.data = NULL;
    }

    return ret;
}


void* lru_cache_calloc(lru_cache_t* lru, size_t size) {
    assert(lru != NULL);
    assert(size != 0);
    return mem_pool_calloc(&lru->pool, size);
}


void lru_cache_free(lru_cache_t* lru, void* addr) {
    assert(lru != NULL);
    assert(addr != NULL);
    assert(addr != NGX_CONF_UNSET_PTR);
    mem_pool_free(&lru->pool, addr);
}


void lru_cache_delete(lru_cache_t* lru, void* key, size_t key_len) {
    assert(lru != NULL);
    assert(key != NULL);
    assert(key_len != 0);

    lru_cache_item_t* item = _lru_cache_hash_find(lru, key, key_len);
    if (item != NULL) {
        _lru_cache_hash_delete(lru, item);
        CDL_DELETE(lru->chain_head, item);

        if (item->data != NULL) {
            lru_cache_free(lru, item->data);
        }

        mem_pool_free(&lru->pool, item->key_ptr);
        mem_pool_free(&lru->pool, item);
    }
}


void lru_cache_eliminate(lru_cache_t* lru, size_t count) {
    assert(lru != NULL);
    assert(count != 0);

    for (size_t i = 0; i < count; i++) {
        if (lru->chain_head != NULL) {
            lru_cache_item_t* tail = lru->chain_head->prev;
            lru_cache_delete(lru, tail->key_ptr, tail->key_byte_length);
        }
    }
}


void lru_cache_destory(lru_cache_t* lru) {
    mem_pool_free(&lru->pool, lru);
}


lru_cache_item_t* _lru_cache_hash_find(lru_cache_t* lru, void* key, size_t key_len) {
    lru_cache_item_t* ret;
    HASH_FIND(hh, lru->hash_head, key, key_len, ret);
    return ret;
}

void _lru_cache_hash_add(lru_cache_t* lru, lru_cache_item_t* item) {
    #undef uthash_malloc
    #undef uthash_free
    #define uthash_malloc(n) _lru_cache_hash_calloc(lru, n)
    #define uthash_free(ptr,sz) _lru_cache_hash_free(lru, ptr)
    HASH_ADD_KEYPTR(hh, lru->hash_head, item->key_ptr, item->key_byte_length, item);
    #undef uthash_malloc
    #undef uthash_free
    #define uthash_malloc(n) malloc(n)
    #define uthash_free(ptr, sz) free(ptr)
}


void _lru_cache_hash_delete(lru_cache_t* lru, lru_cache_item_t* item) {
    #undef uthash_malloc
    #undef uthash_free
    #define uthash_malloc(n) _lru_cache_hash_calloc(lru, n)
    #define uthash_free(ptr,sz) _lru_cache_hash_free(lru, ptr)
    HASH_DELETE(hh, lru->hash_head, item);
    #undef uthash_malloc
    #undef uthash_free
    #define uthash_malloc(n) malloc(n)
    #define uthash_free(ptr, sz) free(ptr)
}


void* _lru_cache_hash_calloc(lru_cache_t* lru, size_t n) {
    void* ret = mem_pool_calloc(&lru->pool, n);
    while (ret == NULL && HASH_COUNT(lru->hash_head) != 0) {
        lru_cache_eliminate(lru, 1);
        ret = mem_pool_calloc(&lru->pool, n);
    }
    assert(ret != NULL);
    return ret;
}


void _lru_cache_hash_free(lru_cache_t* lru, void* addr) {
    mem_pool_free(&lru->pool, addr);
}