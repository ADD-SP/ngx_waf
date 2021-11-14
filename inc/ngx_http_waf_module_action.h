#ifndef __NGX_HTTP_WAF_MODULE_ACTION_H__

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_captcha.h>

#define ngx_conf_merge_action_vaule(conf, prev, default) {      \
    if ((conf).flag == ACTION_FLAG_UNSET) {                     \
        (conf) = (prev);                                        \
                                                                \
    } else {                                                    \
        (conf) = (default);                                     \
    }                                                           \
}


#define ngx_http_waf_append_action(r, action) {                 \
    ngx_http_waf_ctx_t* ctx = NULL;                             \
    ngx_http_waf_get_ctx_and_conf((r), NULL, &ctx);             \
    DL_APPEND(ctx->action_chain, (action));                     \
}


#define ngx_http_waf_append_action_chain(r, chain) {            \
    ngx_http_waf_ctx_t* ctx = NULL;                             \
    ngx_http_waf_get_ctx_and_conf((r), NULL, &ctx);             \
    DL_CONCAT(ctx->action_chain, (chain));                      \
}


#define ngx_http_waf_set_action_decline(action, ex_flag) {       \
    action_t* head = NULL;                                      \
    (action)->flag = ACTION_FLAG_DECLINE | (ex_flag);             \
    (action)->next = NULL;                                      \
    (action)->prev = NULL;                                      \
    DL_APPEND(head, (action));                                  \
    (action) = head;                                            \
}


#define ngx_http_waf_set_action_follow(action, ex_flag) {         \
    action_t* head = NULL;                                      \
    (action)->flag = ACTION_FLAG_FOLLOW | (ex_flag);               \
    (action)->next = NULL;                                      \
    (action)->prev = NULL;                                      \
    DL_APPEND(head, (action));                                  \
    (action) = head;                                            \
}


#define ngx_http_waf_set_action_return(action, status, ex_flag) {  \
    action_t* head = NULL;                                      \
    (action)->flag = ACTION_FLAG_RETURN | (ex_flag);               \
    (action)->extra.http_status = (status);                     \
    (action)->next = NULL;                                      \
    (action)->prev = NULL;                                      \
    DL_APPEND(head, (action));                                  \
    (action) = head;                                            \
}


#define ngx_http_waf_set_action_str(action, _str, _len, status, ex_flag) {     \
    action_t* head = NULL;                                                  \
    (action)->flag = ACTION_FLAG_STR | (ex_flag);                              \
    (action)->extra.extra_str.http_status = (status);                       \
    (action)->extra.extra_str.str.data = (u_char*)(_str);                   \
    (action)->extra.extra_str.str.len = (_len);                             \
    (action)->next = NULL;                                                  \
    (action)->prev = NULL;                                                  \
    DL_APPEND(head, (action));                                              \
    (action) = head;                                                        \
}


#define ngx_http_waf_set_action_html(action, _html, _len, status, ex_flag) {   \
    action_t* head = NULL;                                                  \
    (action)->flag = ACTION_FLAG_HTML | (ex_flag);                             \
    (action)->extra.extra_html.http_status = (status);                      \
    (action)->extra.extra_html.html.data = (u_char*)(_html);                \
    (action)->extra.extra_html.html.len = (_len);                           \
    (action)->next = NULL;                                                  \
    (action)->prev = NULL;                                                  \
    DL_APPEND(head, (action));                                              \
    (action) = head;                                                        \
}


#define ngx_http_waf_set_action_reg_content(action, ex_flag) {                 \
    action_t* head = NULL;                                                  \
    (action)->flag = ACTION_FLAG_REG_CONTENT | (ex_flag);                      \
    (action)->next = NULL;                                                  \
    (action)->prev = NULL;                                                  \
    DL_APPEND(head, (action));                                              \
    (action) = head;                                                        \
}


#define ngx_http_waf_set_action_expand_captcha(action, ex_flag) {              \
    action_t* head = NULL;                                                  \
    (action)->flag = ACTION_FLAG_EXPAND_CAPTCHA | (ex_flag);                   \
    (action)->next = NULL;                                                  \
    (action)->prev = NULL;                                                  \
    DL_APPEND(head, (action));                                              \
    (action) = head;                                                        \
}


#define ngx_http_waf_set_action_expand_under_attack(action, ex_flag) {         \
    action_t* head = NULL;                                                  \
    (action)->flag = ACTION_FLAG_EXPAND_UNDER_ATTACK | (ex_flag);              \
    (action)->next = NULL;                                                  \
    (action)->prev = NULL;                                                  \
    DL_APPEND(head, (action));                                              \
    (action) = head;                                                        \
}


#define ngx_http_waf_copy_action_chain(pool, dst, src) {                    \
    dst = NULL;                                                             \
    action_t* _dst = NULL;                                                  \
    action_t* elt = NULL;                                                   \
    DL_FOREACH(src, elt) {                                                  \
        if (_dst == NULL) {                                                 \
            _dst = ngx_pcalloc(pool, sizeof(action_t));                     \
        } else {                                                            \
            _dst->next = ngx_pcalloc(pool, sizeof(action_t));               \
            _dst = _dst->next;                                              \
        }                                                                   \
        ngx_memcpy(_dst, elt, sizeof(action_t));                            \
        _dst->next = NULL;                                                  \
        _dst->prev = NULL;                                                  \
        DL_APPEND(dst, _dst);                                               \
    }                                                                       \
}


#define ngx_http_waf_make_action_chain_captcha(pool, head, ex_flag, html, len) {        \
    head = NULL;                                                                        \
    action_t* tmp = ngx_pcalloc((pool), sizeof(action_t));                              \
    ngx_http_waf_set_action_reg_content(tmp, (ex_flag | ACTION_FLAG_EXPAND_CAPTCHA));   \
    DL_APPEND(head, tmp);                                                           \
    tmp = ngx_pcalloc((pool), sizeof(action_t));                                    \
    ngx_http_waf_set_action_decline(tmp, (ex_flag) | ACTION_FLAG_EXPAND_CAPTCHA);   \
    DL_APPEND(head, tmp);                                                           \
    tmp = ngx_pcalloc((pool), sizeof(action_t));                                    \
    ngx_http_waf_set_action_html(tmp,                                               \
        (html),                                                                     \
        (len),                                                                      \
        NGX_HTTP_SERVICE_UNAVAILABLE,                                               \
        (ex_flag) | ACTION_FLAG_EXPAND_CAPTCHA);                                    \
    DL_APPEND(head, tmp);                                                           \
}


#define ngx_http_waf_make_action_chain_under_attack(pool, head, ex_flag, html, len) {  \
    head = NULL;                                                                    \
    action_t* tmp = ngx_pcalloc((pool), sizeof(action_t));                          \
    ngx_http_waf_set_action_reg_content(tmp, (ex_flag));                               \
    DL_APPEND(head, tmp);                                                           \
    tmp = ngx_pcalloc((pool), sizeof(action_t));                                    \
    ngx_http_waf_set_action_decline(tmp, (ex_flag));                                   \
    DL_APPEND(head, tmp);                                                           \
    tmp = ngx_pcalloc((pool), sizeof(action_t));                                    \
    ngx_http_waf_set_action_html(tmp,                                               \
        (html),                                                                     \
        (len),                                                                      \
        NGX_HTTP_SERVICE_UNAVAILABLE,                                               \
        (ex_flag));                                                                    \
    DL_APPEND(head, tmp);                                                           \
}


#define ngx_http_waf_append_action_return(r, status, ex_flag) {    \
    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));  \
    ngx_http_waf_set_action_return(action, (status), (ex_flag));   \
    ngx_http_waf_append_action(r, action);                      \
}


#define ngx_http_waf_append_action_decline(r, ex_flag) {           \
    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));  \
    ngx_http_waf_set_action_decline(action, (ex_flag));            \
    ngx_http_waf_append_action(r, action);                      \
}


#define ngx_http_waf_append_action_reg_content(r, ex_flag) {       \
    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));  \
    ngx_http_waf_set_action_reg_content(action, (ex_flag));        \
    ngx_http_waf_append_action(r, action);                      \
}


#define ngx_http_waf_append_action_str(r, _str, _len, status, ex_flag) {           \
    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));                  \
    ngx_http_waf_set_action_str(action, (_str), (_len), (status), (ex_flag));      \
    ngx_http_waf_append_action_reg_content((r), (ex_flag));                        \
    ngx_http_waf_append_action_decline((r), (ex_flag));                            \
    ngx_http_waf_append_action(r, action);                                      \
}


#define ngx_http_waf_append_action_html(r, _html, _len, status, flag) {         \
    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));                  \
    ngx_http_waf_set_action_str(action, (_html), (_len), (status), (ex_flag));     \
    ngx_http_waf_append_action_reg_content((r), (ex_flag));                        \
    ngx_http_waf_append_action_decline((r), (ex_flag));                            \
    ngx_http_waf_append_action(r, action);                                      \
}


#define ngx_http_waf_append_action_under_attack(r, ex_flag) {      \
    ngx_http_waf_loc_conf_t* conf = NULL;                       \
    ngx_http_waf_get_ctx_and_conf(r, &conf, NULL);              \
    action_t* head = NULL;                                      \
    ngx_http_waf_make_action_chain_under_attack(r->pool,        \
        head,                                                   \
        (ex_flag),                                                 \
        loc_conf->waf_under_attack_html.data,                   \
        loc_conf->waf_under_attack_html.len);                   \
    ngx_http_waf_append_action_chain(r, head);                  \
}


#define ngx_http_waf_append_action_captcha(r, ex_flag) {           \
    ngx_http_waf_loc_conf_t* conf = NULL;                       \
    ngx_http_waf_get_ctx_and_conf(r, &conf, NULL);              \
    action_t* head = NULL;                                      \
    ngx_http_waf_make_action_chain_captcha(r->pool,             \
        head,                                                   \
        (ex_flag),                                                 \
        loc_conf->waf_captcha_html.data,                        \
        loc_conf->waf_captcha_html.len);                        \
    ngx_http_waf_append_action_chain(r, head);                  \
}



ngx_int_t ngx_http_waf_perform_action_at_access_start(ngx_http_request_t* r);


ngx_int_t ngx_http_waf_perform_action_at_access_end(ngx_http_request_t* r);


ngx_int_t ngx_http_waf_perform_action_at_content(ngx_http_request_t* r);


#endif