/*
 * The `$waf_*` variables of the module.
 */

#include "ngx_http_waf_module.h"

ngx_int_t ngx_http_waf_var_log(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->step == NULL || !ctx->step->decision.checked) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = 4;
    v->data = (u_char*)"true";
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


ngx_int_t ngx_http_waf_var_blocking_log(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->step == NULL || !ctx->step->decision.blocked) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (u_char*)"true";
    v->len = 4;
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


ngx_int_t ngx_http_waf_var_blocked(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->step == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->step->decision.blocked) {
        v->data = (u_char*)"true";
        v->len = 4;
    } else {
        v->data = (u_char*)"false";
        v->len = 5;
    }

    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


ngx_int_t ngx_http_waf_var_rule_type(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->step == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->step->decision.rule_type.data != NULL
        ? (u_char*) ctx->step->decision.rule_type.data : (u_char*)"";
    v->len = ctx->step->decision.rule_type.len;
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


ngx_int_t ngx_http_waf_var_rule_details(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->step == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->step->decision.rule_details.data != NULL
        ? (u_char*) ctx->step->decision.rule_details.data : (u_char*)"";
    v->len = ctx->step->decision.rule_details.len;
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


ngx_int_t ngx_http_waf_var_spend(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);
    u_char text[64];

    if (ctx == NULL || ctx->step == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = snprintf((char*) text, sizeof(text), "%.5lf", ctx->step->decision.spend);
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(v->data, text, v->len);
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


ngx_int_t ngx_http_waf_var_rate(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->step == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN + 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }
    v->len = ngx_sprintf(v->data, "%L", ctx->step->decision.rate) - v->data;
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}
