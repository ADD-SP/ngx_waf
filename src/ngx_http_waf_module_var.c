#include <ngx_http_waf_module_var.h>

ngx_int_t ngx_http_waf_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp(r, "ngx_http_waf_log_get_handler() ... start");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    v->valid = 1;
    v->no_cacheable = 1;

    if (ctx == NULL) {
        ngx_http_waf_dp(r, "no ctx ... return");
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->checked == NGX_HTTP_WAF_FALSE) {
        ngx_http_waf_dp(r, "not checked ... return");
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_http_waf_dp(r, "checked ... return");
    v->not_found = 0;
    v->data = (u_char*)"true";
    v->len = 4;

    ngx_http_waf_dp(r, "ngx_http_waf_log_get_handler() ... end");
    return NGX_OK;
}


ngx_int_t ngx_http_waf_blocking_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp(r, "ngx_http_waf_blocking_log_get_handler() ... start");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    v->valid = 1;
    v->no_cacheable = 1;

    if (ctx == NULL) {
        ngx_http_waf_dp(r, "no ctx ... return");
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->blocked == NGX_HTTP_WAF_FALSE) {
        ngx_http_waf_dp(r, "not blocked ... return");
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_http_waf_dp(r, "blocked ... return");
    v->not_found = 0;
    v->data = (u_char*)"true";
    v->len = 4;

    ngx_http_waf_dp(r, "ngx_http_waf_blocking_log_get_handler() ... end");
    return NGX_OK;
}


ngx_int_t ngx_http_waf_blocked_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp(r, "ngx_http_waf_blocked_get_handler() ... start");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    v->valid = 1;
    v->no_cacheable = 1;

    if (ctx == NULL) {
        ngx_http_waf_dp(r, "no ctx ... return");
        v->not_found = 1;
        return NGX_OK;
    }
    
    if (ctx->blocked == NGX_HTTP_WAF_TRUE) {
        ngx_http_waf_dp(r, "blocked ... return");
        v->not_found = 0;
        v->len = 4;
        v->data = (u_char*)"true";
    } else {
        ngx_http_waf_dp(r, "not blocked ... return");
        v->not_found = 0;
        v->len = 5;
        v->data = (u_char*)"false";
    }

    ngx_http_waf_dp(r, "ngx_http_waf_blocked_get_handler() ... end");
    return NGX_OK;
}


ngx_int_t ngx_http_waf_rule_type_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp(r, "ngx_http_waf_rule_type_get_handler() ... start");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    v->valid = 1;
    v->no_cacheable = 1;

    if (ctx == NULL) {
        ngx_http_waf_dp(r, "no ctx ... return");
        v->not_found = 1;
        return NGX_OK;
    }

    v->not_found = 0;
    v->len = strlen((char*)ctx->rule_type);
    v->data = ngx_palloc(r->pool, sizeof(u_char) * ngx_max(v->len, 2));
    strcpy((char*)v->data, (char*)ctx->rule_type);
    ngx_http_waf_dpf(r, "$waf_rule_type=%s", (char*)v->data);

    ngx_http_waf_dp(r, "ngx_http_waf_rule_type_get_handler() ... end");
    return NGX_OK;
}


ngx_int_t ngx_http_waf_rule_deatils_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp(r, "ngx_http_waf_rule_deatils_handler() ... start");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    v->valid = 1;
    v->no_cacheable = 1;
    

    if (ctx == NULL) {
        ngx_http_waf_dp(r, "no ctx ... return");
        v->not_found = 1;
        return NGX_OK;
    }
    
    v->not_found = 0;
    v->len = strlen((char*)ctx->rule_deatils);
    v->data = ngx_palloc(r->pool, sizeof(u_char) * ngx_max(v->len, 2));
    strcpy((char*)v->data, (char*)ctx->rule_deatils);
    ngx_http_waf_dpf(r, "$waf_rule_details=%s", (char*)v->data);

    ngx_http_waf_dp(r, "ngx_http_waf_rule_deatils_handler() ... end");
    return NGX_OK;
}


ngx_int_t ngx_http_waf_spend_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp(r, "ngx_http_waf_spend_handler() ... start");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    v->valid = 1;
    v->no_cacheable = 1;
    

    if (ctx == NULL) {
        ngx_http_waf_dp(r, "no ctx ... return");
        v->not_found = 0;
        return NGX_OK;
    }


    u_char text[32] = { 0 };
    sprintf((char*)text, "%.5lf", ctx->spend);
    v->len = ngx_strlen(text);
    v->data = ngx_palloc(r->pool, sizeof(u_char) * v->len);
    strcpy((char*)v->data, (char*)text);
    ngx_http_waf_dpf(r, "$waf_spend=%s", (char*)v->data);

    ngx_http_waf_dp(r, "ngx_http_waf_spend_handler() ... end");
    return NGX_OK;
}