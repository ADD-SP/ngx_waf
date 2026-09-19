/**
 * @file ngx_http_waf_module.c
 * @brief The registration of the ngx_waf nginx module.
 *
 * The nginx glue is split by concern: this file registers the module, its
 * directives and its variables and provides the callbacks the Rust core
 * reaches back through; `ngx_http_waf_config.c` handles the configuration,
 * `ngx_http_waf_request.c` the request path, `ngx_http_waf_shm.c` the shared
 * memory zones, `ngx_http_waf_variables.c` the `$waf_*` variables and
 * `ngx_http_waf_fetch.c` the captcha provider request.  Every rule, action,
 * configuration semantic and protocol parse lives in `rust/`.
 */


#include "ngx_http_waf_module.h"

static ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t* cf);


static ngx_int_t ngx_http_waf_install_variables(ngx_conf_t* cf);


/*
 * The log callback of libmodsecurity.  The Rust core installs it on every
 * instance it creates, the symbol has to be visible (see `rust/src/modsec.rs`).
 */
void ngx_http_waf_modsecurity_log(void* log, const void* data);


void ngx_http_waf_modsecurity_log(void* log, const void* data) {
    if (log == NULL || data == NULL) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, (ngx_log_t*) log, 0,
        "ngx_waf: [ModSecurity][%s]", (const char*) data);
}


/*
 * Where the Rust core reports a panic it caught at the FFI boundary: without
 * this the request only answers 500 and the error log stays empty.  See
 * `rust/src/ffi.rs`.
 */
void ngx_http_waf_log_error(void* log, const char* message);


void ngx_http_waf_log_error(void* log, const char* message) {
    if (log == NULL || message == NULL) {
        return;
    }

    ngx_log_error(NGX_LOG_ERR, (ngx_log_t*) log, 0, "%s", message);
}


static ngx_command_t ngx_http_waf_commands[] = {

    { ngx_string("waf_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_zone_conf,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_rule_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_mode"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_cc_deny"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_cache"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_under_attack"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_captcha"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234|NGX_CONF_TAKE5|NGX_CONF_TAKE6|NGX_CONF_TAKE7,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_verify_bot"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234|NGX_CONF_TAKE5|NGX_CONF_TAKE6|NGX_CONF_TAKE7,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_priority"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_action"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234|NGX_CONF_TAKE5|NGX_CONF_TAKE6|NGX_CONF_TAKE7,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_block_page"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_modsecurity"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_modsecurity_transaction_id"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_waf_modsecurity_transaction_id_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_waf_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_waf_postconfiguration,         /* postconfiguration */

    ngx_http_waf_create_main_conf,          /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_waf_create_loc_conf,           /* create location configuration */
    ngx_http_waf_merge_loc_conf             /* merge location configuration */
};


ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,               /* module context */
    ngx_http_waf_commands,                  /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_waf_variables[] = {

    { ngx_string("waf_log"), NULL, ngx_http_waf_var_log, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_blocking_log"), NULL, ngx_http_waf_var_blocking_log, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_blocked"), NULL, ngx_http_waf_var_blocked, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_rule_type"), NULL, ngx_http_waf_var_rule_type, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_rule_details"), NULL, ngx_http_waf_var_rule_details, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_spend"), NULL, ngx_http_waf_var_spend, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_rate"), NULL, ngx_http_waf_var_rate, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t* cf) {
    ngx_http_handler_pt* h;
    ngx_http_core_main_conf_t* cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES,
            "ngx_waf: failed to install handler at NGX_HTTP_ACCESS_PHASE");
        return NGX_ERROR;
    }
    *h = ngx_http_waf_handler_access_phase;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES,
            "ngx_waf: failed to install handler at NGX_HTTP_LOG_PHASE");
        return NGX_ERROR;
    }
    *h = ngx_http_waf_handler_log_phase;

    if (ngx_http_waf_install_variables(cf) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES,
            "ngx_waf: failed to add embedded variables");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_install_variables(ngx_conf_t* cf) {
    ngx_http_variable_t* v;

    for (v = ngx_http_waf_variables; v->name.len; v++) {
        ngx_http_variable_t* var = ngx_http_add_variable(cf, &v->name,
            NGX_HTTP_VAR_NOCACHEABLE);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}
