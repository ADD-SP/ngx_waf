#include <ngx_http_waf_module_var.h>

#define _init(r, v)                                     \
    ngx_http_waf_ctx_t* ctx = NULL;                     \
    ngx_http_waf_get_ctx_and_conf((r), NULL, &ctx);     \
    (v)->valid = 1;                                     \
    (v)->no_cacheable = 1;                              \
    if (ctx == NULL) {                                  \
        ngx_http_waf_dp(r, "no ctx ... return");        \
        v->not_found = 1;                               \
        return NGX_OK;                                  \
}


/**
 * @brief 当读取 waf_log 变量时的回调函数，这个变量当启动检查时不为空，反之为空字符串。
*/
ngx_int_t _waf_ssl_greased(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);

/**
 * @brief 当读取 waf_log 变量时的回调函数，这个变量当启动检查时不为空，反之为空字符串。
*/
ngx_int_t _waf_ssl_fingerprint(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);

/**
 * @brief 当读取 waf_log 变量时的回调函数，这个变量当启动检查时不为空，反之为空字符串。
*/
ngx_int_t _waf_ssl_fingerprint_hash(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);

/**
 * @brief 当读取 waf_log 变量时的回调函数，这个变量当启动检查时不为空，反之为空字符串。
*/
ngx_int_t _waf_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_blocking_log 变量时的回调函数，这个变量当拦截时不为空，反之为空字符串。
*/
ngx_int_t _waf_blocking_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_blocked 变量时的回调函数，这个变量当请求被拦截的时候是 "true"，反之是 "false"。
*/
ngx_int_t _waf_blocked_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_rule_type 变量时的回调函数，这个变量会显示触发了的规则类型。
*/
ngx_int_t _waf_rule_type_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_rule_deatils 变量时的回调函数，这个变量会显示触发了的规则的细节。
*/
ngx_int_t _waf_rule_deatils_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_spend 变量时的回调函数，这个变量表示本次检查花费的时间（毫秒）。
*/
ngx_int_t _waf_spend_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_rate 变量时的回调函数，这个变量表示当前统计周期内当前客户端 IP 的访问次数。
*/
ngx_int_t _waf_rate_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


ngx_int_t ngx_http_waf_install_add_var(ngx_conf_t* cf) {
#define _install_var(name, handler) {                                                           \
    ngx_str_t _name = ngx_string((name));                                                       \
    ngx_http_variable_t* var = ngx_http_add_variable(cf, &_name, NGX_HTTP_VAR_NOCACHEABLE);     \
    if (var == NULL) {                                                                          \
        return NGX_HTTP_WAF_FAIL;                                                               \
    }                                                                                           \
    var->get_handler = (handler);                                                               \
    var->set_handler = NULL;                                                                    \
}

    _install_var("waf_log", _waf_log_get_handler);
    _install_var("waf_blocking_log", _waf_blocking_log_get_handler);
    _install_var("waf_blocked", _waf_blocked_get_handler);
    _install_var("waf_rule_type", _waf_rule_type_get_handler);
    _install_var("waf_rule_details", _waf_rule_deatils_handler);
    _install_var("waf_spend", _waf_spend_handler);
    _install_var("waf_rate", _waf_rate_handler);
    _install_var("waf_ssl_greased", _waf_ssl_greased);
    _install_var("waf_ssl_ja3", _waf_ssl_fingerprint);
    _install_var("waf_ssl_ja3_hash", _waf_ssl_fingerprint_hash);

#undef _install_var

    return NGX_HTTP_WAF_SUCCESS;
}

ngx_int_t _waf_ssl_greased(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_http_waf_dp_func_start(r);

	_init(r, v);

	if (!ctx->checked) {
		ngx_http_waf_dp(r, "not checked ... return");
		v->not_found = 1;
		return NGX_OK;
	}
	if (r->connection == NULL)
	{
		ngx_http_waf_dp(r, "not checked ... return");
		return NGX_OK;
	}

	if (r->connection->ssl == NULL)
	{
		ngx_http_waf_dp(r, "not checked ... return");
		return NGX_OK;
	}

	ngx_http_waf_dp(r, "checked ... return");
	v->len = 1;
	v->data = (u_char*)(r->connection->ssl->fp_tls_greased ? "1" : "0");

	v->valid = 1;
	v->no_cacheable = 1;
	v->not_found = 0;

	ngx_http_waf_dp_func_end(r);
	return NGX_OK;
}

ngx_int_t _waf_ssl_fingerprint(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_http_waf_dp_func_start(r);

	_init(r, v);

	if (!ctx->checked) {
		ngx_http_waf_dp(r, "not checked ... return");
		v->not_found = 1;
		return NGX_OK;
	}
	if (r->connection == NULL)
	{
		ngx_http_waf_dp(r, "not checked ... return");
		return NGX_OK;
	}

	if (r->connection->ssl == NULL)
	{
		ngx_http_waf_dp(r, "not checked ... return");
		return NGX_OK;
	}

	if (r->connection->ssl->fp_ja3_str.data == NULL) {
		ngx_http_waf_dp(r, "not checked ... return");
		return NGX_OK;
	}

	ngx_http_waf_dp(r, "checked ... return");
	v->data = r->connection->ssl->fp_ja3_str.data;
	v->len = r->connection->ssl->fp_ja3_str.len;
	v->valid = 1;
	v->no_cacheable = 1;
	v->not_found = 0;

	ngx_http_waf_dp_func_end(r);
	return NGX_OK;
}

ngx_int_t _waf_ssl_fingerprint_hash(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_http_waf_dp_func_start(r);

	_init(r, v);

	if (!ctx->checked) {
		ngx_http_waf_dp(r, "not checked ... return");
		v->not_found = 1;
		return NGX_OK;
	}

	if (r->connection == NULL)
	{
		ngx_http_waf_dp(r, "not checked ... return");
		return NGX_OK;
	}

	if (r->connection->ssl == NULL)
	{
		ngx_http_waf_dp(r, "not checked ... return");
		return NGX_OK;
	}

	if (r->connection->ssl->fp_ja3_md5.data == NULL) {
		ngx_http_waf_dp(r, "not checked ... return");
		return NGX_OK;
	}

	ngx_http_waf_dp(r, "checked ... return");
	v->data = r->connection->ssl->fp_ja3_md5.data;
	v->len = r->connection->ssl->fp_ja3_md5.len;
	v->valid = 1;
	v->no_cacheable = 1;
	v->not_found = 0;

	ngx_http_waf_dp_func_end(r);
	return NGX_OK;
}

ngx_int_t _waf_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp_func_start(r);

    _init(r, v);

    if (!ctx->checked) {
        ngx_http_waf_dp(r, "not checked ... return");
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_http_waf_dp(r, "checked ... return");
    v->not_found = 0;
    v->data = (u_char*)"true";
    v->len = 4;

    ngx_http_waf_dp_func_end(r);
    return NGX_OK;
}


ngx_int_t _waf_blocking_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp_func_start(r);

    _init(r, v);

    if (!ctx->blocked) {
        ngx_http_waf_dp(r, "not blocked ... return");
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_http_waf_dp(r, "blocked ... return");
    v->not_found = 0;
    v->data = (u_char*)"true";
    v->len = 4;

    ngx_http_waf_dp_func_end(r);
    return NGX_OK;
}


ngx_int_t _waf_blocked_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp_func_start(r);

    _init(r, v);
    
    if (ctx->blocked) {
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

    ngx_http_waf_dp_func_end(r);
    return NGX_OK;
}


ngx_int_t _waf_rule_type_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp_func_start(r);

    _init(r, v);

    v->not_found = 0;
    v->data = ctx->rule_type.data;
    v->len = ctx->rule_type.len;
    ngx_http_waf_dpf(r, "$waf_rule_type=%V", &ctx->rule_type);

    ngx_http_waf_dp_func_end(r);
    return NGX_OK;
}


ngx_int_t _waf_rule_deatils_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp_func_start(r);

    _init(r, v);
    
    v->not_found = 0;
    v->data = ctx->rule_deatils.data;
    v->len = ctx->rule_deatils.len;
    ngx_http_waf_dpf(r, "$waf_rule_details=%V", &ctx->rule_deatils);

    ngx_http_waf_dp_func_end(r);
    return NGX_OK;
}


ngx_int_t _waf_spend_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp_func_start(r);

    _init(r, v);

    u_char text[32] = { 0 };
    sprintf((char*)text, "%.5lf", ctx->spend);
    v->len = ngx_strlen(text);
    v->data = ngx_palloc(r->pool, sizeof(u_char) * v->len);
    strcpy((char*)v->data, (char*)text);
    ngx_http_waf_dpf(r, "$waf_spend=%s", (char*)v->data);

    ngx_http_waf_dp_func_end(r);
    return NGX_OK;
}


ngx_int_t _waf_rate_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_dp_func_start(r);

    _init(r, v);

    u_char* buf = ngx_pcalloc(r->pool, NGX_INT_T_LEN + sizeof(u_char));
    v->len = ngx_sprintf(buf, "%i", ctx->rate) - buf;
    v->data = buf;
    ngx_http_waf_dpf(r, "$waf_rate=%s", (char*)v->data);

    ngx_http_waf_dp_func_end(r);
    return NGX_OK;
}


#undef _init
