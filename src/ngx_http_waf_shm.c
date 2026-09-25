/*
 * The shared memory zone of a `waf_zone`: the callbacks the Rust core
 * allocates through, the zone init handler and the handle lookup.
 */

#include "ngx_http_waf_module.h"

static void ngx_http_waf_shm_lock(void* ctx) {
    ngx_shmtx_lock(&((ngx_slab_pool_t *) ctx)->mutex);
}


static void ngx_http_waf_shm_unlock(void* ctx) {
    ngx_shmtx_unlock(&((ngx_slab_pool_t *) ctx)->mutex);
}


static void *ngx_http_waf_shm_alloc_locked(void* ctx, size_t size) {
    /*
     * The Rust core only allocates while it holds the zone lock: `ZoneLock` is
     * the guard that says so, which is why the callback does not take the lock
     * itself.
     */
    return ngx_slab_alloc_locked((ngx_slab_pool_t *) ctx, size);
}


ngx_int_t ngx_http_waf_shm_zone_init(ngx_shm_zone_t* zone, void* data) {
    ngx_http_waf_zone_t* z = zone->data;
    ngx_http_waf_zone_t* old = data;
    ngx_slab_pool_t* pool = (ngx_slab_pool_t *) zone->shm.addr;
    ngx_waf_shm_ops_t ops;

    ops.lock = ngx_http_waf_shm_lock;
    ops.unlock = ngx_http_waf_shm_unlock;
    ops.alloc_locked = ngx_http_waf_shm_alloc_locked;
    ops.ctx = pool;

    z->handle = ngx_waf_shm_zone_init(
        zone->shm.addr,
        zone->shm.size,
        old != NULL ? old->handle : NULL,
        &ops);

    if (z->handle == NULL) {
        ngx_log_error(NGX_LOG_EMERG, zone->shm.log, 0,
            "ngx_waf: failed to initialize the shared memory zone \"%V\"",
            &z->name);
        return NGX_ERROR;
    }

    return NGX_OK;
}


void *ngx_http_waf_zone_handle(ngx_http_waf_main_conf_t* mcf, ngx_waf_str_t name)
{
    ngx_uint_t i;

    if (mcf == NULL || mcf->zones == NULL || name.len == 0 || name.data == NULL) {
        return NULL;
    }

    for (i = 0; i < mcf->zones->nelts; i++) {
        ngx_http_waf_zone_t* zone = ((ngx_http_waf_zone_t **) mcf->zones->elts)[i];

        if (zone->name.len == name.len
            && ngx_strncmp(zone->name.data, name.data, name.len) == 0)
        {
            return zone->handle;
        }
    }

    return NULL;
}
