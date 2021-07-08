/**
 * @file ngx_http_waf_module_spinlock.h
 * @brief 基于 redis 的自旋锁
*/

#ifndef __NGX_HTTP_WAF_MODUEL_SPINLOCK_H__
#define __NGX_HTTP_WAF_MODUEL_SPINLOCK_H__


#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <utstack.h>

extern char ngx_http_waf_module_nonce[17];


static
ngx_int_t ngx_http_waf_spinlock_init(spinlock_t* lock, ngx_http_waf_srv_conf_t* conf, u_char* id) {
    if (lock == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    lock->srv_conf = conf;
    lock->id = ngx_strdup(id);

    return NGX_HTTP_WAF_SUCCESS;
}


static
ngx_int_t ngx_http_waf_spinlock_lock(spinlock_t* lock) {
    ngx_http_waf_srv_conf_t* srv_conf = lock->srv_conf;
    u_char* prefix = srv_conf->redis_key_prefix;
    redisContext* ctx = srv_conf->redis_ctx;

    if (ensure_redis_ctx_healthy(srv_conf) != NGX_HTTP_WAF_TRUE) {
        return NGX_HTTP_WAF_FAIL;
    }

    redisReply* reply = redisCommand(ctx,
                                     "SET %s_%s_spinlock %s NX PX 50",
                                     ngx_http_waf_module_nonce,
                                     (char*)(lock->id),
                                     (char*)(prefix));
    
    while (reply == NULL 
        || reply->type != REDIS_REPLY_STATUS 
        || strcasecmp(reply->str, "OK") != 0) {

        if (reply == NULL) {
            return NGX_HTTP_WAF_FAIL;
        }

        if (reply->type != REDIS_REPLY_NIL) {
            freeReplyObject(reply);
            reply = NULL;
            return NGX_HTTP_WAF_FAIL;
        }

        freeReplyObject(reply);
        reply = NULL;

        ngx_cpu_pause();

        reply = redisCommand(ctx,
                             "SET %s_%s_spinlock %s NX PX 50",
                             ngx_http_waf_module_nonce,
                             (char*)(lock->id),
                             (char*)(prefix));
    }

    return NGX_HTTP_WAF_SUCCESS;
}


static
ngx_int_t ngx_http_waf_spinlock_unlock(spinlock_t* lock) {
    ngx_http_waf_srv_conf_t* srv_conf = lock->srv_conf;
    u_char* prefix = srv_conf->redis_key_prefix;
    redisContext* ctx = srv_conf->redis_ctx;


    if (ensure_redis_ctx_healthy(srv_conf) != NGX_HTTP_WAF_TRUE) {
        return NGX_HTTP_WAF_FAIL;
    }

    redisReply* reply = redisCommand(ctx,
                                     "GET %s_spinlock",
                                     (char*)(lock->id));

    
    if (reply == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (reply->type == REDIS_REPLY_NIL) {
        return NGX_HTTP_WAF_SUCCESS;
    }

    if (reply->type != REDIS_REPLY_STRING) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (ngx_strcmp(reply->str, prefix) == 0) {
        freeReplyObject(reply);
        reply = NULL;

        reply = redisCommand(ctx,
                             "DEL %s_spinlock",
                             (char*)(lock->id));

        if (reply == NULL || reply->type != REDIS_REPLY_INTEGER) {
            return NGX_HTTP_WAF_FAIL;
        }

        long long int ret = reply->integer;
        freeReplyObject(reply);
        reply = NULL;

        if (ret >= 1) {
            return NGX_HTTP_WAF_FAIL;
        }

        return NGX_HTTP_WAF_SUCCESS;
    }

    freeReplyObject(reply);
    return NGX_HTTP_WAF_FAIL;
}


static
ngx_int_t ngx_http_waf_spinlock_free(spinlock_t* lock) {
    free(lock->id);
    return NGX_HTTP_WAF_SUCCESS;
}


#endif