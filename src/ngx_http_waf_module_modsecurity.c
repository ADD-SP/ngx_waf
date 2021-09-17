/**
 * 本源代码文件中有部分源码参考自 https://github.com/SpiderLabs/ModSecurity-nginx
*/


#include <ngx_http_waf_module_modsecurity.h>

extern ngx_module_t ngx_http_waf_module;


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;


static ngx_http_output_body_filter_pt ngx_http_next_body_filter;


static ngx_int_t _init_ctx(ngx_http_request_t* r);


static ngx_int_t _process_connection(ngx_http_request_t* r, ngx_int_t* out_http_status);


static ngx_int_t _process_uri(ngx_http_request_t* r, ngx_int_t* out_http_status);


static ngx_int_t _process_request_header(ngx_http_request_t* r, ngx_int_t* out_http_status);


static ngx_int_t _process_request_body(ngx_http_request_t* r, ngx_int_t* out_http_status);


static ngx_int_t _process_response_header(ngx_http_request_t* r, ngx_int_t* out_http_status);


static ngx_int_t _process_response_body(ngx_http_request_t* r, ngx_chain_t *in, ngx_int_t* out_http_status);


static ngx_int_t _process_intervention(ngx_http_request_t* r, ngx_int_t* out_http_status);


void ngx_http_waf_header_filter_init() {
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_waf_header_filter;
}


void ngx_http_waf_body_filter_init() {
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_waf_body_filter;
}


void ngx_http_waf_modsecurity_handler_log(void* log, const void* data) {
    const char *msg;
    if (log == NULL) {
        return;
    }
    msg = (const char *) data;

    ngx_log_error(NGX_LOG_INFO, (ngx_log_t*)log, 0, "ngx_waf: [ModSecurity][%s]", msg);
}


ngx_int_t ngx_http_waf_handler_modsecurity(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (loc_conf->waf_modsecurity == 0 || loc_conf->waf_modsecurity == NGX_CONF_UNSET) {
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    if (_init_ctx(r) != NGX_HTTP_WAF_SUCCESS) {
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }

    if (_process_connection(r, out_http_status) == NGX_HTTP_WAF_MATCHED) {
        return NGX_HTTP_WAF_MATCHED;
    }

    if (_process_uri(r, out_http_status) == NGX_HTTP_WAF_MATCHED) {
        return NGX_HTTP_WAF_MATCHED;
    }

    if (_process_request_header(r, out_http_status) == NGX_HTTP_WAF_MATCHED) {
        return NGX_HTTP_WAF_MATCHED;
    }

    if (_process_request_body(r, out_http_status) == NGX_HTTP_WAF_MATCHED) {
        return NGX_HTTP_WAF_MATCHED;
    }

    return NGX_DECLINED;
}


ngx_int_t ngx_http_waf_header_filter(ngx_http_request_t *r) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (loc_conf->waf_modsecurity == 0 || loc_conf->waf_modsecurity == NGX_CONF_UNSET) {
        return ngx_http_next_header_filter(r);
    }

    if (ctx == NULL) {
        return ngx_http_next_header_filter(r);
    }

    if (ctx->modsecurity_transaction == NULL) {
        return ngx_http_next_header_filter(r);
    }

    ngx_int_t out_http_status = NGX_DECLINED;
    switch (_process_response_header(r, &out_http_status)) {
        case NGX_HTTP_WAF_MATCHED:
            return out_http_status;
        case NGX_HTTP_WAF_NEXT_FILTER:
            return ngx_http_next_header_filter(r);
        default:
            break;
    }

    return ngx_http_next_header_filter(r);
}


ngx_int_t ngx_http_waf_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (loc_conf->waf_modsecurity == 0 || loc_conf->waf_modsecurity == NGX_CONF_UNSET) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->modsecurity_transaction == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }
    
    ngx_int_t out_http_status = NGX_DECLINED;
    if (_process_response_body(r, in, &out_http_status) == NGX_HTTP_WAF_MATCHED) {
        return out_http_status;
    }

    return ngx_http_next_body_filter(r, in);
}


static ngx_int_t _init_ctx(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ModSecurity* instance = loc_conf->modsecurity_instance;
    void* rules = loc_conf->modsecurity_rules;
    ngx_http_complex_value_t* transaction_id = loc_conf->waf_modsecurity_transaction_id;

    ctx->modsecurity_transaction = NULL;

    if (transaction_id != NULL && transaction_id != NGX_CONF_UNSET_PTR) {
        ngx_str_t current_transaction_id;
        ngx_str_null(&current_transaction_id);
        if (ngx_http_complex_value(r, transaction_id, &current_transaction_id) != NGX_OK) {
            return NGX_HTTP_WAF_FAIL;
        }
        ctx->modsecurity_transaction = msc_new_transaction_with_id(instance, rules, 
            (char*)current_transaction_id.data, r->connection->log);
    } else {
        ctx->modsecurity_transaction = msc_new_transaction(instance, rules, r->connection->log);
    }

    if (ctx->modsecurity_transaction == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _process_connection(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    Transaction *transaction = ctx->modsecurity_transaction;
    ngx_connection_t* connection = r->connection;
    ngx_str_t* client_addr_str = &connection->addr_text;
    ngx_str_t server_addr_str;
    u_char server_addr_c_str[NGX_SOCKADDR_STRLEN];
    server_addr_str.len = NGX_SOCKADDR_STRLEN;
    server_addr_str.data = server_addr_c_str;
    int client_port = ngx_inet_get_port(connection->sockaddr);
    int server_port = ngx_inet_get_port(connection->local_sockaddr);

    if (ngx_connection_local_sockaddr(r->connection, &server_addr_str, 0) != NGX_OK) {
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }

    char* client_addr_c_str = ngx_http_waf_c_str(client_addr_str, r->pool);
    if (client_addr_c_str == NULL) {
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }


    if (msc_process_connection(transaction, client_addr_c_str, client_port, (char*)server_addr_c_str, server_port) != 1) {
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }

    return _process_intervention(r, out_http_status);
}


static ngx_int_t _process_uri(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    Transaction *transaction = ctx->modsecurity_transaction;
    char* uri = ngx_http_waf_c_str(&r->unparsed_uri, r->pool);
    char* method = ngx_http_waf_c_str(&r->method_name, r->pool);

    if (uri == NULL || method == NULL) {
        ngx_http_waf_dp(r, "no uri");
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }

    if (method == NULL) {
        ngx_http_waf_dp(r, "no method name");
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }

    char* http_version = NULL;
    switch(r->http_version) {
        case NGX_HTTP_VERSION_9:
            http_version = "0.9";
            break;
        case NGX_HTTP_VERSION_10:
            http_version = "1.0";
            break;
#if (defined(nginx_version) && nginx_version >= 1009005)
        case NGX_HTTP_VERSION_11:
            http_version = "1.1";
            break;
#endif
        case NGX_HTTP_VERSION_20:
            http_version = "2.0";
            break;
        default:
            http_version = "1.0";
            break;
    }

    
    if (msc_process_uri(transaction, uri, method, http_version) != 1) {
        ngx_http_waf_dp(r, "msc_process_uri failed");
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }

    return _process_intervention(r, out_http_status);
}


static ngx_int_t _process_request_header(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    Transaction *transaction = ctx->modsecurity_transaction;
    ngx_list_part_t *headers = &r->headers_in.headers.part;
    ngx_table_elt_t *header = headers->elts;
    ngx_uint_t i = 0;
    while (headers != NULL) {
        if (i >= headers->nelts) {
            headers = headers->next;
            i = 0;
        } else {
            ngx_http_waf_dp(r, "adding request header: %.*s with valuse %.*s", 
                (int)header[i].key.len, header[i].key.data, (int)header[i].value.len, header[i].value.data);
            if (msc_add_n_request_header(transaction,
                (const u_char*) header[i].key.data,
                header[i].key.len,
                (const u_char*) header[i].value.data,
                header[i].value.len) != 1) {
                ngx_http_waf_dp(r, "msc_add_n_request_header failed");
                *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return NGX_HTTP_WAF_MATCHED;
            }
            ++i;
        }
    }

    if (msc_process_request_headers(transaction) != 1) {
        ngx_http_waf_dp(r, "msc_process_request_headers failed");
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }

    return _process_intervention(r, out_http_status);
}


static ngx_int_t _process_request_body(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    Transaction *transaction = ctx->modsecurity_transaction;

    if (ctx->has_req_body == NGX_HTTP_WAF_FALSE) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    if (msc_append_request_body(transaction, ctx->req_body.pos, ctx->req_body.last - ctx->req_body.last) != 1) {
        ngx_http_waf_dp(r, "msc_append_request_body failed");
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }


    if (msc_process_request_body(transaction) != 1) {
        ngx_http_waf_dp(r, "msc_process_request_body failed");
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }


    return _process_intervention(r, out_http_status);
}


static ngx_int_t _process_response_header(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    Transaction *transaction = ctx->modsecurity_transaction;
    ngx_list_part_t *headers = &r->headers_out.headers.part;
    ngx_table_elt_t *header = headers->elts;
    ngx_uint_t i = 0;
    while (headers != NULL) {
        if (i >= headers->nelts) {
            headers = headers->next;
            i = 0;
        } else {
            ngx_http_waf_dp(r, "adding response header: %.*s with valuse %.*s", 
                (int)header[i].key.len, header[i].key.data, (int)header[i].value.len, header[i].value.data);
            if (msc_add_n_response_header(transaction,
                (const u_char*) header[i].key.data,
                header[i].key.len,
                (const u_char*) header[i].value.data,
                header[i].value.len) != 1) {
                ngx_http_waf_dp(r, "msc_add_n_response_header failed");
                *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return NGX_HTTP_WAF_MATCHED;
            }
            ++i;
        }
    }

    int status;

    if (r->err_status) {
        status = r->err_status;
    } else {
        status = r->headers_out.status;
    }

    char* http_response_ver = "HTTP 1.1";
    #if (NGX_HTTP_V2)
        if (r->stream) {
            http_response_ver = "HTTP 2.0";
        }
    #endif

    if (msc_process_response_headers(transaction, status, http_response_ver) != 1) {
        ngx_http_waf_dp(r, "msc_process_response_headers failed");
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }

    ngx_int_t ret = _process_intervention(r, out_http_status);

    if (r->error_page) {
        return NGX_HTTP_WAF_NEXT_FILTER;
    }

    if (ret > 0) {
        return NGX_HTTP_WAF_MATCHED;
    }

    return NGX_HTTP_WAF_NOT_MATCHED;
}


static ngx_int_t _process_response_body(ngx_http_request_t* r, ngx_chain_t *in, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    Transaction *transaction = ctx->modsecurity_transaction;
    ngx_chain_t* chain = in;

    if (chain == NULL) {
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    while (chain != NULL) {
        u_char* data = chain->buf->pos;

        if (msc_append_response_body(transaction, data, chain->buf->last - data) != 1) {
            ngx_http_waf_dp(r, "msc_append_response_body failed");
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }

        if (_process_intervention(r, out_http_status) == NGX_HTTP_WAF_MATCHED) {
            return NGX_HTTP_WAF_MATCHED;
        }

        if (msc_process_response_body(transaction) != 1) {
            ngx_http_waf_dp(r, "msc_process_response_body failed");
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }

        if (_process_intervention(r, out_http_status) == NGX_HTTP_WAF_MATCHED) {
            return NGX_HTTP_WAF_MATCHED;
        }

        chain = chain->next;
    }

    return NGX_HTTP_WAF_NOT_MATCHED;
}


static ngx_int_t _process_intervention(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    Transaction *transaction = ctx->modsecurity_transaction;

    ModSecurityIntervention intervention;
    ngx_memzero(&intervention, sizeof(ModSecurityIntervention));
    intervention.status = 200;

    if (msc_intervention(transaction, &intervention) == 0) {
        ngx_http_waf_dp(r, "nothing to do");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    if (intervention.log != NULL) {
        ctx->gernal_logged = NGX_HTTP_WAF_TRUE;
        ngx_strcpy(ctx->rule_type, "ModSecurity");
        ngx_strcpy(ctx->rule_deatils, intervention.log);
        free(intervention.log);
    }

    
    if (intervention.url != NULL) {
        ngx_http_waf_dp(r, "intervention -- redirecting to %s with status code %d", intervention.url, intervention.status);

        if (r->header_sent) {
            ngx_http_waf_dp(r, "headers are already sent. Cannot perform the redirection at this point");
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }

        ngx_http_clear_location(r);
        ngx_table_elt_t *location = ngx_list_push(&r->headers_out.headers);
        if (location == NULL) {
            ngx_http_waf_dp(r, "header 'Location' generation failed");
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }

        r->headers_out.location = location;
        ngx_str_set(&location->key, "Location");
        location->lowcase_key = (u_char*)"location";
        location->value.data = (u_char*)intervention.url;
        location->value.len = strlen(intervention.url);
        location->hash = 0;

        *out_http_status = intervention.status;
        return NGX_HTTP_WAF_MATCHED;
    }


    if (intervention.status != 200)
    {
        msc_update_status_code(transaction, intervention.status);

        if (r->header_sent)
        {
            ngx_http_waf_dp(r, "headers are already sent. Cannot perform the redirection at this point");
            return -1;
        }

        ngx_http_waf_dp(r, "intervention -- returning code: %d", intervention.status);
        *out_http_status = intervention.status;
        return NGX_HTTP_WAF_MATCHED;
    }

    return NGX_HTTP_WAF_NOT_MATCHED;
}