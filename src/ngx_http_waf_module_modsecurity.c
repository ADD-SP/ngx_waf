/**
 * 本源代码文件中有部分源码参考自 https://github.com/SpiderLabs/ModSecurity-nginx
*/


#include <ngx_http_waf_module_modsecurity.h>


extern ngx_module_t ngx_http_waf_module;


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;


static ngx_http_output_body_filter_pt ngx_http_next_body_filter;


static ngx_int_t _process_request(ngx_http_request_t* r, ngx_int_t* out_http_status);


static ngx_int_t _init_ctx(ngx_http_request_t* r);


static ngx_int_t _process_connection(ngx_http_request_t* r, ngx_int_t* out_http_status);


static ngx_int_t _process_uri(ngx_http_request_t* r, ngx_int_t* out_http_status);


static ngx_int_t _process_request_header(ngx_http_request_t* r, ngx_int_t* out_http_status);


static ngx_int_t _process_request_body(ngx_http_request_t* r, ngx_int_t* out_http_status);


static ngx_int_t _process_response_header(ngx_http_request_t* r, ngx_int_t* out_http_status);


static ngx_int_t _process_response_body(ngx_http_request_t* r, ngx_chain_t *in, ngx_int_t* out_http_status);


static ngx_int_t _process_intervention(ngx_http_request_t* r, ngx_int_t* out_http_status);

#if (NGX_THREADS) && (NGX_HTTP_WAF_ASYNC_MODSECURITY)

static void _invoke(void* data, ngx_log_t* log); 


static void _completion(ngx_event_t* event);

#endif


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
    msg = (const char *)data;

    ngx_log_error(NGX_LOG_INFO, (ngx_log_t*)log, 0, "ngx_waf: [ModSecurity][%s]", msg);
}


ngx_int_t ngx_http_waf_handler_modsecurity(ngx_http_request_t* r) {

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf)) {
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_modsecurity)) {
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, r->method)) {
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    action_t* action = NULL;
    ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_modsecurity);
    

#if (NGX_THREADS) && (NGX_HTTP_WAF_ASYNC_MODSECURITY)
    ngx_thread_task_t* task = ngx_thread_task_alloc(r->pool, sizeof(ngx_http_request_t));
    if (task == NULL) {
        return NGX_ERROR;
    }
    task->ctx = r;
    task->handler = _invoke;
    task->event.handler = _completion;
    task->event.data = r;

    if (ngx_thread_task_post(loc_conf->thread_pool, task) != NGX_OK) {
        return _process_request(r, out_http_status);
    }

    *out_http_status = NGX_DONE;
    return NGX_HTTP_WAF_MATCHED;
#else

    ngx_int_t http_status = NGX_DECLINED;
    ngx_int_t ret = _process_request(r, &http_status);
    if (ret == NGX_HTTP_WAF_MATCHED) {
        if (http_status >= 400 && http_status < 600) {
            if (ngx_http_waf_check_flag(action->flag, ACTION_FLAG_FOLLOW)) {
                ngx_http_waf_append_action_return(r, http_status, ACTION_FLAG_FROM_MODSECURITY);

            } else {
                ngx_http_waf_append_action_chain(r, action);
            }

        } else {
            ngx_http_waf_append_action_return(r, http_status, ACTION_FLAG_FROM_MODSECURITY);
        }
    }

    return ret;

#endif
}


ngx_int_t ngx_http_waf_header_filter(ngx_http_request_t *r) {

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf)) {
        return ngx_http_next_header_filter(r); 
    }

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_modsecurity)) {
        return ngx_http_next_header_filter(r);
    }

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, r->method)) {
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

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf)) {
        return ngx_http_next_body_filter(r, in); 
    }

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_modsecurity)) {
        return ngx_http_next_body_filter(r, in);
    }

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, r->method)) {
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


static ngx_int_t _process_request(ngx_http_request_t* r, ngx_int_t* out_http_status) {

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

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

    return NGX_HTTP_WAF_NOT_MATCHED;
}


static ngx_int_t _init_ctx(ngx_http_request_t* r) {

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ModSecurity* instance = loc_conf->modsecurity_instance;
    void* rules = loc_conf->modsecurity_rules;
    ngx_http_complex_value_t* transaction_id = loc_conf->waf_modsecurity_transaction_id;

    if (ctx->modsecurity_transaction != NULL) {
        msc_transaction_cleanup(ctx->modsecurity_transaction);
    }
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
    server_addr_c_str[server_addr_str.len] = '\0';

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
    if (uri == NULL) {
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }

    char* method = ngx_http_waf_c_str(&r->method_name, r->pool);
    if (method == NULL) {
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

            if (headers == NULL) {
                break;
            }
            header = headers->elts;
            
            i = 0;
        } else {
            if (msc_add_n_request_header(transaction,
                (const u_char*) header[i].key.data,
                header[i].key.len,
                (const u_char*) header[i].value.data,
                header[i].value.len) != 1) {
                *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return NGX_HTTP_WAF_MATCHED;
            }
            ++i;
        }
    }

    if (msc_process_request_headers(transaction) != 1) {
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

    if (ctx->has_req_body) {
        ngx_str_t body;
        body.data = ctx->req_body.pos;
        body.len = ctx->req_body.last - ctx->req_body.pos;
        if (msc_append_request_body(transaction, body.data, body.len) != 1) {
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }
    }

    if (msc_process_request_body(transaction) != 1) {
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
            if (msc_add_n_response_header(transaction,
                (const u_char*) header[i].key.data,
                header[i].key.len,
                (const u_char*) header[i].value.data,
                header[i].value.len) != 1) {
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
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }

    ngx_int_t ret = _process_intervention(r, out_http_status);

    if (r->error_page) {
        return NGX_HTTP_WAF_NEXT_FILTER;
    }

    if (ret == NGX_HTTP_WAF_MATCHED) {
    }

    return ret;
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
        ngx_str_t body;
        body.data = chain->buf->pos;
        body.len = chain->buf->last - chain->buf->pos;

        if (msc_append_response_body(transaction, body.data, body.len) != 1) {
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }

        if (_process_intervention(r, out_http_status) == NGX_HTTP_WAF_MATCHED) {
            return NGX_HTTP_WAF_MATCHED;
        }

        if (msc_process_response_body(transaction) != 1) {
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

    if (msc_intervention(transaction, &intervention) <= 0) {
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    char* log = "(no log message was specified)";
    if (intervention.log != NULL) {
        ctx->gernal_logged = NGX_HTTP_WAF_TRUE;
        log = intervention.log;
        ngx_http_waf_set_rule_info(r, "ModSecurity", log, NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
    }
    if (intervention.log != NULL) {
        free(intervention.log);
    }

    if (intervention.disruptive) {
        ctx->blocked = NGX_HTTP_WAF_TRUE;
    }

    if (intervention.url != NULL) {

        if (r->header_sent) {
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }

        ngx_http_clear_location(r);
        ngx_table_elt_t *location = ngx_list_push(&r->headers_out.headers);
        if (location == NULL) {
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }

        r->headers_out.location = location;
        ngx_str_set(&location->key, "Location");
        location->lowcase_key = (u_char*)"location";
        location->value.data = (u_char*)intervention.url;
        location->value.len = ngx_strlen(intervention.url);
        location->hash = 0;

        *out_http_status = intervention.status;
        return NGX_HTTP_WAF_MATCHED;
    }

    if (intervention.status != 200)
    {   
        if (msc_update_status_code(transaction, intervention.status) != 1) {
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }

        if (r->header_sent)
        {
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }

        *out_http_status = intervention.status;
        return NGX_HTTP_WAF_MATCHED;
    }

    return NGX_HTTP_WAF_NOT_MATCHED;
}

#if (NGX_THREADS) && (NGX_HTTP_WAF_ASYNC_MODSECURITY)
static void _invoke(void* data, ngx_log_t* log) {
    ngx_http_request_t* r = data;

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (loc_conf->waf == 0 || loc_conf->waf == NGX_CONF_UNSET) {
        ctx->modsecurity_triggered = NGX_HTTP_WAF_FALSE;
        return;
    }    

    if (loc_conf->waf_modsecurity == 0 || loc_conf->waf_modsecurity == NGX_CONF_UNSET) {
        ctx->modsecurity_triggered = NGX_HTTP_WAF_FALSE;
        return;
    }

    if (_process_request(r, &ctx->modsecurity_status) == NGX_HTTP_WAF_MATCHED) {
        ctx->modsecurity_triggered = NGX_HTTP_WAF_TRUE;
        return;
    }


    ctx->modsecurity_triggered = NGX_HTTP_WAF_FALSE;
    return;
}
#endif

#if (NGX_THREADS) && (NGX_HTTP_WAF_ASYNC_MODSECURITY)
static void _completion(ngx_event_t* event) {
    ngx_http_request_t* r = event->data;

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    ctx->start_from_thread = NGX_HTTP_WAF_TRUE;

    ngx_http_core_run_phases(r);
    
}
#endif