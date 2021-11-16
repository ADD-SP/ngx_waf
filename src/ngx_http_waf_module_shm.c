#include <ngx_http_waf_module_shm.h>


typedef struct _zone_s {
    ngx_str_t name;
    shm_t* shm;
    struct _zone_s* next;
} _zone_t;


extern ngx_module_t ngx_http_waf_module;


static _zone_t* _zones = NULL;


static ngx_int_t _shm_zone_init_handler(ngx_shm_zone_t *zone, void *data);


void ngx_http_waf_shm_clear_inner_data() {
    _zones = NULL;
}



ngx_int_t ngx_http_waf_shm_init(shm_t* shm, ngx_conf_t* cf, ngx_str_t* name, size_t size) {
    if (ngx_http_waf_shm_get(name) != NULL) {
        return NGX_HTTP_WAF_ALREADY_EXISTS;
    }

    shm->cf = cf;
    shm->name.data = ngx_pstrdup(cf->pool, name);
    shm->name.len = name->len;
    shm->size = size;
    shm->init_chain = NULL;
    shm->pool = NULL;
    shm->zone = ngx_shared_memory_add(cf, name, size, &ngx_http_waf_module);

    if (shm->zone == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    shm->zone->data = shm;
    shm->zone->init = _shm_zone_init_handler;

    _zone_t* zone = ngx_pcalloc(cf->pool, sizeof(_zone_t));

    if (zone == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }
    
    zone->name = shm->name;
    zone->shm = shm;
    zone->next = NULL;

    LL_PREPEND(_zones, zone);

    return NGX_HTTP_WAF_SUCCESS;
}


shm_init_t* ngx_http_waf_shm_init_handler_add(shm_t* shm) {
    shm_init_t* init = ngx_pcalloc(shm->cf->pool, sizeof(shm_init_t));

    if (init == NULL) {
        return NULL;
    }

    init->init_handler = NULL;
    init->gc_handler = NULL;
    init->data = NULL;
    ngx_str_null(&init->tag);

    LL_PREPEND(shm->init_chain, init);

    return init;
}


ngx_int_t ngx_http_waf_shm_gc(shm_t* shm) {
    shm_init_t* init = NULL;

    ngx_int_t low_memory = NGX_HTTP_WAF_FALSE;

    LL_FOREACH(shm->init_chain, init) {
        if (init->gc_handler != NULL) {
            ngx_int_t rc = init->gc_handler(shm, init->data, &low_memory);

            if (low_memory == NGX_HTTP_WAF_TRUE) {
                break;
            }

            if (rc != NGX_HTTP_WAF_SUCCESS) {
                return NGX_HTTP_WAF_FAIL;
            }
        }
    }

    if (low_memory == NGX_HTTP_WAF_TRUE) {
        LL_FOREACH(shm->init_chain, init) {
            if (init->gc_handler != NULL) {
                ngx_int_t rc = init->gc_handler(shm, init->data, &low_memory);

                if (rc != NGX_HTTP_WAF_SUCCESS) {
                    return NGX_HTTP_WAF_FAIL;
                }
            }
        }
    }

    return NGX_HTTP_WAF_SUCCESS;
}


shm_t* ngx_http_waf_shm_get(ngx_str_t* name) {
    _zone_t* elt = NULL;
    LL_FOREACH(_zones, elt) {
        if (elt->name.len != name->len) {
            continue;
        }

        if (ngx_strncmp(elt->name.data, name->data, name->len) != 0) {
            continue;
        }

        return elt->shm;
    }
    return NULL;
}


ngx_int_t ngx_http_waf_shm_tag_is_used(ngx_str_t* name, ngx_str_t* tag) {
    shm_t* shm = ngx_http_waf_shm_get(name);
    
    if (shm == NULL) {
        return NGX_HTTP_WAF_TRUE;
    }

    shm_init_t* init = NULL;
    LL_FOREACH(shm->init_chain, init) {
        if (init->tag.len != tag->len) {
            continue;
        }

        if (ngx_strncmp(init->tag.data, tag->data, tag->len) != 0) {
            continue;
        }

        return NGX_HTTP_WAF_TRUE;
    }

    return NGX_HTTP_WAF_FALSE;
}


static ngx_int_t _shm_zone_init_handler(ngx_shm_zone_t *zone, void *data) {
    shm_t* shm = zone->data;
    shm_t* old_shm = data;

    if (old_shm != NULL) {
        shm->pool = old_shm->pool;
    }

    if (shm->pool == NULL) {
        ngx_slab_pool_t* shpool = (ngx_slab_pool_t*)zone->shm.addr;
        shm->pool = ngx_slab_calloc(shpool, sizeof(mem_pool_t));
        mem_pool_init(shm->pool, MEM_POOL_FLAG_NGX_SHARD, shpool);
    }

    shm_init_t* init = NULL;
    LL_FOREACH(shm->init_chain, init) {
        if (old_shm != NULL) {
            shm_init_t* old_init = NULL;
            LL_FOREACH(old_shm->init_chain, old_init) {
                if (old_init->tag.len != init->tag.len) {
                    continue;
                }

                if (ngx_strncmp(old_init->tag.data, init->tag.data, init->tag.len) != 0) {
                    continue;
                }

                if (init->init_handler(shm, init->data, old_init->data) != NGX_HTTP_WAF_SUCCESS) {
                    return NGX_ERROR;
                }
            }
        } else {
            if (init->init_handler(shm, init->data, NULL) != NGX_HTTP_WAF_SUCCESS) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}