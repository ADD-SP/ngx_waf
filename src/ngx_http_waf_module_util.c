#include <ngx_http_waf_module_util.h>


extern ngx_module_t ngx_http_waf_module; /**< 模块详情 */


extern ngx_int_t ngx_http_waf_handler_precontent_phase(ngx_http_request_t* r);


extern void ngx_http_waf_handler_cleanup(void *data);


static size_t _curl_handler_write(void *contents, size_t size, size_t nmemb, void *userp);


static int _curl_handler_debug(CURL* handle, curl_infotype type, char* data, size_t size, void* userp);



ngx_int_t ngx_http_waf_parse_ipv4(ngx_str_t text, ipv4_t* ipv4) {
    uint32_t prefix = 0;
    uint32_t suffix = UINT32_MAX;
    uint32_t suffix_num = 0;

    if (ipv4 == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    ngx_memcpy(ipv4->text, text.data, text.len);
    ipv4->text[text.len] = '\0';

    u_char* c = ipv4->text;
    ngx_uint_t prefix_len = 0;
    while (*c !='\0' && *c != '/') {
        ++prefix_len;
        ++c;
    }

    char prefix_text[32];
    struct in_addr addr4;
    if (*c =='\0' && prefix_len == text.len) {
        ngx_memcpy(prefix_text, ipv4->text, prefix_len);
        prefix_text[prefix_len] = '\0';
    } 
    else if (*c == '/' && prefix_len >= 7) {
        /* 0.0.0.0 的长度刚好是 7 */
        ngx_memcpy(prefix_text, ipv4->text, prefix_len);
        prefix_text[prefix_len] = '\0';
    } 
    else {
        return NGX_HTTP_WAF_FAIL;
    }

    if (inet_pton(AF_INET, prefix_text, &addr4) != 1) {
        return NGX_HTTP_WAF_FAIL;
    }
    prefix = addr4.s_addr;

    if (*c == '/') {
        ++c;
    }
    while (*c != '\0') {
        if (suffix == UINT32_MAX) {
            suffix = 0;
        }
        suffix = suffix * 10 + (*c - '0');
        ++c;
    }
    if (suffix == UINT32_MAX) {
        suffix = 32;
    }

    suffix_num = suffix;

    uint8_t temp_suffix[4] = { 0 };
    for (int i = 0; i < 4; i++) {
        uint8_t temp = 0;
        if (suffix >= 8) {
            suffix -=8;
            temp = ~0;
        } 
        else {
            for (uint32_t j = 0; j < suffix; j++) {
                temp |= 0x80 >> j;
            }
            suffix = 0;
        }
        temp_suffix[i] = temp;
    }

    suffix = 0;
    for (int i = 0; i < 4; i++) {
        suffix |= ((uint32_t)temp_suffix[i]) << (i * 8);
    }

    ipv4->prefix = prefix & suffix;
    ipv4->suffix = suffix;
    ipv4->suffix_num = suffix_num;

    return NGX_HTTP_WAF_SUCCESS;
}

#if (NGX_HAVE_INET6)
ngx_int_t ngx_http_waf_parse_ipv6(ngx_str_t text, ipv6_t* ipv6) {
    uint8_t prefix[16] = { 0 };
    uint8_t suffix[16] = { 0 };
    uint32_t suffix_num = 0;

    if (ipv6 == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }
    
    ngx_memcpy(ipv6->text, text.data, text.len);

    ipv6->text[text.len] = '\0';

    u_char* c = ipv6->text;
    ngx_uint_t prefix_len = 0;
    while (*c !='\0' && *c != '/') {
        ++prefix_len;
        ++c;
    }

    char prefix_text[64];
    struct in6_addr addr6;
    if (*c =='\0' && prefix_len == text.len) {
        ngx_memcpy(prefix_text, ipv6->text, prefix_len);
        prefix_text[prefix_len] = '\0';
    } 
    else if (*c == '/' && prefix_len >= 2) {
        /* :: 的长度刚好是 2，此 IPV6 地址代表全零 */
        ngx_memcpy(prefix_text, ipv6->text, prefix_len);
        prefix_text[prefix_len] = '\0';
    } 
    else {
        return NGX_HTTP_WAF_FAIL;
    }

    if (inet_pton(AF_INET6, prefix_text, &addr6) != 1) {
        return NGX_HTTP_WAF_FAIL;
    }
    ngx_memcpy(prefix, &addr6.s6_addr, 16);

    uint32_t temp_suffix = UINT32_MAX;
    if (*c == '/') {
        ++c;
    }
    while (*c != '\0') {
        if (temp_suffix == UINT32_MAX) {
            temp_suffix = 0;
        }
        temp_suffix = temp_suffix * 10 + (*c - '0');
        ++c;
    }
    if (temp_suffix == UINT32_MAX) {
        temp_suffix = 128;
    }

    suffix_num = temp_suffix;
    for (int i = 0; i < 16; i++) {
        uint8_t temp = 0;
        if (temp_suffix >= 8) {
            temp_suffix -=8;
            temp = ~0;
        } 
        else {
            for (uint32_t j = 0; j < temp_suffix; j++) {
                temp |= 0x80 >> j;
            }
            temp_suffix = 0;
        }
        suffix[i] = temp;
    }

    for (int i = 0; i < 16; i++) {
        prefix[i] &= suffix[i];
    }

    ngx_memcpy(ipv6->prefix, prefix, 16);
    ngx_memcpy(ipv6->suffix, suffix, 16);
    ipv6->suffix_num = suffix_num;

    return NGX_HTTP_WAF_SUCCESS;
}
#endif


ngx_int_t ngx_http_waf_parse_time(u_char* str) {
    ngx_int_t ret = 0;
    size_t len = ngx_strlen(str);
    
    if (len == 1) {
        switch (str[0]) {
            case 's': return 1; break;
            case 'm': return 1 * 60; break;
            case 'h': return 1 * 60 * 60; break;
            case 'd': return 1 * 60 * 60 * 24; break;
            default: return NGX_ERROR; break;
        }
    }

    if (len < 2) {
        return NGX_ERROR;
    }

    ret = ngx_atoi(str, len - 1);
    if (ret == NGX_ERROR || ret <= 0) {
        return NGX_ERROR;
    }

    switch (str[len - 1]) {
        case 's': ret *= 1; break;
        case 'm': ret *= 1 * 60; break;
        case 'h': ret *= 1 * 60 * 60; break;
        case 'd': ret *= 1 * 60 * 60 * 24; break;
        default: return NGX_ERROR; break;
    }

    return ret;
}


ngx_int_t ngx_http_waf_parse_size(u_char* str) {
    ngx_int_t ret = 0;
    size_t len = ngx_strlen(str);
    if (len < 2) {
        return NGX_ERROR;
    }

    ret = ngx_atoi(str, len - 1);
    if (ret == NGX_ERROR || ret <= 0) {
        return NGX_ERROR;
    }

    switch (str[len - 1]) {
        case 'k': ret *= 1 * 1024; break;
        case 'm': ret *= 1 * 1024 * 1024; break;
        case 'g': ret *= 1 * 1024 * 1024 * 1024; break;
        default: return NGX_ERROR; break;
    }

    return ret;
}


ngx_int_t ngx_http_waf_parse_cookie(ngx_str_t* native_cookie, UT_array** array) {
    if (array == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    UT_icd icd = ngx_http_waf_make_utarray_ngx_str_icd();
    utarray_new(*array, &icd);

    if (native_cookie == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }


    UT_array* cookies = NULL;
    utarray_new(cookies, &icd);

    ngx_http_waf_str_split(native_cookie, ';', native_cookie->len, &cookies);
    ngx_str_t* p = NULL;

    while (p = (ngx_str_t*)utarray_next(cookies, p), p != NULL) {
        UT_array* key_and_value = NULL;
        ngx_str_t temp;
        temp.data = p->data;
        temp.len = p->len;
        if (p->data[0] == ' ') {
            temp.data += 1;
            temp.len -= 1;
        }

        ngx_http_waf_str_split(&temp, '=', native_cookie->len, &key_and_value);

        if (utarray_len(key_and_value) != 2) {
            return NGX_HTTP_WAF_FAIL;
        }

        ngx_str_t* key = NULL;
        ngx_str_t* value = NULL;


        key = (ngx_str_t*)utarray_next(key_and_value, NULL);
        value = (ngx_str_t*)utarray_next(key_and_value, key);


        utarray_push_back(*array, key);
        utarray_push_back(*array, value);
        utarray_free(key_and_value);
    }

    utarray_free(cookies);

    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t ngx_http_waf_parse_query_string(ngx_str_t* native_query_string, key_value_t** hash_head) {
    if (hash_head == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (native_query_string == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }


    UT_array* kvs = NULL;

    ngx_http_waf_str_split(native_query_string, '&', native_query_string->len, &kvs);
    ngx_str_t* p = NULL;

    while (p = (ngx_str_t*)utarray_next(kvs, p), p != NULL) {
        UT_array* key_and_value = NULL;
        ngx_str_t temp;
        temp.data = p->data;
        temp.len = p->len;

        ngx_http_waf_str_split(&temp, '=', native_query_string->len, &key_and_value);

        if (utarray_len(key_and_value) > 2 && utarray_len(key_and_value) < 1) {
            return NGX_HTTP_WAF_FAIL;
        }

        ngx_str_t* key = NULL;
        ngx_str_t* value = NULL;


        key = (ngx_str_t*)utarray_next(key_and_value, NULL);
        value = (ngx_str_t*)utarray_next(key_and_value, key);

        key_value_t* qs = malloc(sizeof(key_value_t));
        ngx_memzero(qs, sizeof(key_value_t));
        qs->key.data = ngx_strdup(key->data);
        qs->key.len = key->len;

        if (value != NULL) {
            qs->value.data = ngx_strdup(value->data);
            qs->value.len = value->len;
        }

        HASH_ADD_KEYPTR(hh, *hash_head, qs->key.data, qs->key.len * sizeof(u_char), qs);

        utarray_free(key_and_value);
    }

    utarray_free(kvs);
    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t ngx_http_waf_parse_form_string(ngx_str_t* raw, key_value_t** hash_head) {
    return ngx_http_waf_parse_query_string(raw, hash_head);
}


// ngx_int_t ngx_http_waf_parse_header(ngx_list_t* native_header, key_value_t** hash_head) {
//     if (native_header == NULL || hash_head == NULL) {
//         return NGX_HTTP_WAF_FALSE;
//     }

//     ngx_list_part_t* part = &(native_header->part);
//     ngx_table_elt_t* value = part->elts;

//     for (size_t i = 0; ; i++) {
//         if (i >= part->nelts) {
//             if (part->next == NULL) {
//                 break;
//             }

//             part = part->next;
//             value = part->elts;
//             i = 0;
//         }

//         key_value_t* temp = malloc(sizeof(key_value_t));
//         ngx_memzero(temp, sizeof(key_value_t));
//         temp->key.data = ngx_strdup(value[i].key.data);
//         temp->key.len = value[i].key.len;
//         ngx_strlow(temp->key.data, temp->key.data, temp->key.len);
//         temp->value.data = ngx_strdup(value[i].value.data);
//         temp->value.len = value[i].value.len;
//         HASH_ADD_KEYPTR(hh, *hash_head, temp->key.data, temp->key.len * sizeof(u_char), temp);

//     }

//     return NGX_HTTP_WAF_TRUE;
// }


// ngx_int_t ngx_http_waf_ipv4_netcmp(uint32_t ip, const ipv4_t* ipv4) {
//     size_t prefix = ip & ipv4->suffix;

//     if (prefix == ipv4->prefix) {
//         return NGX_HTTP_WAF_MATCHED;
//     }

//     return NGX_HTTP_WAF_NOT_MATCHED;
// }


#if (NGX_HAVE_INET6)
// ngx_int_t ngx_http_waf_ipv6_netcmp(uint8_t ip[16], const ipv6_t* ipv6) {
//     uint8_t temp_ip[16];

//     memcpy(temp_ip, ip, 16);

//     for (int i = 0; i < 16; i++) {
//         temp_ip[i] &= ipv6->suffix[i];
//     }

//     if (memcmp(temp_ip, ipv6->prefix, sizeof(uint8_t) * 16) != 0) {
//         return NGX_HTTP_WAF_NOT_MATCHED;
//     }

//     return NGX_HTTP_WAF_MATCHED;
// }
#endif


ngx_int_t ngx_http_waf_str_split(ngx_str_t* str, u_char sep, size_t max_len, UT_array** array) {
    if (array == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    UT_icd icd = ngx_http_waf_make_utarray_ngx_str_icd();
    utarray_new(*array,&icd);

    if (str == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    ngx_str_t temp_str;
    temp_str.data = malloc(sizeof(u_char) * (max_len + 1));
    ngx_memzero(temp_str.data, sizeof(u_char) * (max_len + 1));
    size_t str_index = 0;

    for (size_t i = 0; i < str->len; i++) {
        u_char c = str->data[i];
        if (c != sep) {
            if (str_index >= max_len) {
                free(temp_str.data);
                return NGX_HTTP_WAF_FAIL;
            }
            temp_str.data[str_index++] = c;
        } else {
            temp_str.data[str_index] = '\0';
            temp_str.len = str_index;
            utarray_push_back(*array, &temp_str);
            str_index = 0;
        }
    }

    if (str_index != 0) {
        temp_str.data[str_index] = '\0';
        temp_str.len = str_index;
        utarray_push_back(*array, &temp_str);
        str_index = 0;
    }

    free(temp_str.data);

    return NGX_HTTP_WAF_SUCCESS;
}


// ngx_int_t str_split(u_char* str, u_char sep, size_t max_len, UT_array** array) {
//     if (str == NULL || array == NULL) {
//         return NGX_HTTP_WAF_FAIL;
//     }

//     UT_icd icd = ngx_http_waf_make_utarray_ngx_str_icd();

//     utarray_new(*array,&icd);
//     ngx_str_t temp_str;
//     temp_str.data = malloc(sizeof(u_char) * max_len);
//     ngx_memzero(temp_str.data, sizeof(u_char) * max_len);
//     size_t str_index = 0;

//     for (size_t i = 0; str[i] != '\0'; i++) {
//         u_char c = str[i];
//         if (c != sep) {
//             if (str_index + 1 >= max_len) {
//                 return NGX_HTTP_WAF_FAIL;
//             }
//             temp_str.data[str_index++] = c;
//         } else {
//             temp_str.data[str_index] = '\0';
//             temp_str.len = str_index;
//             utarray_push_back(*array, &temp_str);
//             str_index = 0;
//         }
//     }

//     if (str_index != 0) {
//         temp_str.data[str_index] = '\0';
//         temp_str.len = str_index;
//         utarray_push_back(*array, &temp_str);
//         str_index = 0;
//     }

//     free(temp_str.data);

//     return NGX_HTTP_WAF_SUCCESS;
// }


char* ngx_http_waf_to_c_str(u_char* destination, ngx_str_t ngx_str) {
    if (ngx_str.len > NGX_HTTP_WAF_RULE_MAX_LEN) {
        return NULL;
    }
    ngx_memcpy(destination, ngx_str.data, ngx_str.len);
    destination[ngx_str.len] = '\0';
    return (char*)destination + ngx_str.len;
}


ngx_int_t ngx_http_waf_rand_str(u_char* dest, size_t len) {
    if (dest == NULL || len == 0) {
        return NGX_HTTP_WAF_FAIL;
    }

    for (size_t i = 0; i < len; i++) {
        uint32_t num = randombytes_uniform(52);
        if (num < 26) {
            dest[i] = (unsigned char)'A' + (unsigned char)num;
        } else {
            dest[i] = (unsigned char)'a' + (unsigned char)(num - 26);
        }
    }

    dest[len] = '\0';

    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t ngx_http_waf_sha256(u_char* dst, size_t dst_len, const void* buf, size_t buf_len) {
    if (dst == NULL  || dst_len < crypto_hash_sha256_BYTES * 2 + 1 || buf == NULL || buf_len == 0) {
        return NGX_HTTP_WAF_FAIL;
    }

    unsigned char* out = malloc(crypto_hash_sha256_BYTES);
    ngx_memzero(out, crypto_hash_sha256_BYTES);

    crypto_hash_sha256(out, buf, buf_len);
    sodium_bin2hex((char*)dst, dst_len, out, crypto_hash_sha256_BYTES);

    free(out);
    
    return NGX_HTTP_WAF_SUCCESS;
}


void ngx_http_waf_get_ctx_and_conf(ngx_http_request_t* r, ngx_http_waf_loc_conf_t** conf, ngx_http_waf_ctx_t** ctx) {
    ngx_http_waf_dp_func_start(r);

    if (ctx != NULL) {
        *ctx = NULL;
        *ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
        if (*ctx == NULL) {
            ngx_http_cleanup_t* cln = NULL;
            for (cln = r->cleanup; cln != NULL; cln = cln->next) {
                if (cln->handler == ngx_http_waf_handler_cleanup) {
                    *ctx = cln->data;
                }
            }
        }
    }
    
    if (conf != NULL) {
        *conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
        ngx_http_waf_loc_conf_t* parent = (*conf)->parent;
        ngx_http_waf_loc_conf_t* _conf = *conf;

        while (!ngx_http_waf_is_valid_ptr_value(_conf->ip_access_statistics)
               && parent != NULL) {
            _conf->ip_access_statistics = parent->ip_access_statistics;
            parent = parent->parent;
        }

        parent = (*conf)->parent;

        while (!ngx_http_waf_is_valid_ptr_value(_conf->action_cache_captcha)
               && parent != NULL) {
            _conf->action_cache_captcha = parent->action_cache_captcha;
            parent = parent->parent;
        }
    }

    ngx_http_waf_dp_func_end(r);
}


void ngx_http_waf_make_inx_addr(ngx_http_request_t* r, inx_addr_t* inx_addr) {
    ngx_memset(inx_addr, 0, sizeof(inx_addr_t));
    ngx_int_t ip_type = r->connection->sockaddr->sa_family;

    if (ip_type == AF_INET) {
        struct sockaddr_in* s_addr_in = (struct sockaddr_in*)(r->connection->sockaddr);
        ngx_memcpy(&(inx_addr->ipv4), &(s_addr_in->sin_addr), sizeof(struct in_addr));
    } 
#if (NGX_HAVE_INET6)
    else {
        struct sockaddr_in6* s_addr_in6 = (struct sockaddr_in6*)(r->connection->sockaddr);
        ngx_memcpy(&(inx_addr->ipv6), &(s_addr_in6->sin6_addr), sizeof(struct in6_addr));
    }
#endif
}


void ngx_http_waf_set_rule_info(ngx_http_request_t* r, char* type, char* details) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    ngx_http_waf_dpf(r, "type: %s, details: %s", type, details);

    size_t type_len = ngx_strlen(type);
    size_t details_len = ngx_strlen(details);

    ctx->rule_type.data = ngx_pcalloc(r->pool, type_len);
    ctx->rule_type.len = type_len;
    ngx_memcpy(ctx->rule_type.data, type, type_len);

    ctx->rule_deatils.data = ngx_pcalloc(r->pool, details_len);
    ctx->rule_deatils.len = details_len;
    ngx_memcpy(ctx->rule_deatils.data, details, details_len);

    ngx_http_waf_dp_func_end(r);
}


ngx_int_t ngx_http_waf_http_post(ngx_http_request_t* r, const char* url, char* in, char** out) {
    ngx_http_waf_dp_func_start(r);

#define _error_without_msg() {                      \
    ngx_http_waf_dp(r, "failed ... return");        \
    *out = NULL;                                    \
    return NGX_HTTP_WAF_FAIL;                       \
}


#define _set_opt(handler, option, value) {                                  \
    ngx_http_waf_dpf(r, "Setting curl option %s", #option);  \
    CURLcode res = curl_easy_setopt((handler), (option), (value));          \
    if (res != CURLE_OK) {                                                  \
        _error_without_msg();                                               \
    }                                                                       \
    ngx_http_waf_dp(r, "success");                                          \
}

    ngx_http_waf_dp(r, "initializing curl handle");
    CURL* curl_handle = curl_easy_init();
    if (curl_handle == NULL) {
        _error_without_msg();
    }
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dp(r, "initializing buf");
    struct {
        ngx_http_request_t* r;
        ngx_buf_t buf;
    } buf;
    buf.r = r;
    buf.buf.pos = malloc(1);
    buf.buf.last = buf.buf.pos;
    buf.buf.memory = 1;
    if (buf.buf.pos == NULL) {
        _error_without_msg();
    }
    ngx_http_waf_dp(r, "success");

    _set_opt(curl_handle, CURLOPT_URL, url);
    _set_opt(curl_handle, CURLOPT_TIMEOUT, 5L);
    _set_opt(curl_handle, CURLOPT_WRITEFUNCTION, _curl_handler_write);
    _set_opt(curl_handle, CURLOPT_POSTFIELDS, in);
    _set_opt(curl_handle, CURLOPT_WRITEDATA, (void *)&buf);
    _set_opt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");


    if (r->connection->log->log_level >= NGX_LOG_DEBUG) {
        _set_opt(curl_handle, CURLOPT_DEBUGFUNCTION, _curl_handler_debug);
        _set_opt(curl_handle, CURLOPT_DEBUGDATA, (void*)r);

        /* 启用此选项才能有调试信息 */
        _set_opt(curl_handle, CURLOPT_VERBOSE, 1L);
    }

    ngx_http_waf_dpf(r, "request body is %s", in);
    ngx_http_waf_dp(r, "performing request");
    CURLcode res = curl_easy_perform(curl_handle);
    if (res != CURLE_OK) {
        ngx_http_waf_dp(r, "failed ... return");
        *out = malloc(1024);
        if (*out != NULL) {
            sprintf(*out, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        free(buf.buf.pos);
        return NGX_HTTP_WAF_FAIL;
    }
    *out = (char*)buf.buf.pos;
    ngx_http_waf_dp(r, "success");
    ngx_http_waf_dpf(r, "response body is %s", *out);

    curl_easy_cleanup(curl_handle);

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_SUCCESS;

#undef _error_without_msg
#undef _set_opt
}


ngx_int_t ngx_http_waf_make_regexp(ngx_pool_t* pool, ngx_str_t str, ngx_regex_elt_t* elt) {
    ngx_regex_compile_t   regex_compile;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];

    if (pool == NULL || elt == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    ngx_memzero(&regex_compile, sizeof(ngx_regex_compile_t));
    regex_compile.pattern = str;
    regex_compile.pool = pool;
    regex_compile.err.len = NGX_MAX_CONF_ERRSTR;
    regex_compile.err.data = errstr;
    if (ngx_regex_compile(&regex_compile) != NGX_OK) {
        return NGX_HTTP_WAF_FAIL;
    }
    elt->name = ngx_pnalloc(pool, str.len + 1);
    ngx_memcpy(elt->name, str.data, str.len);
    elt->name[str.len] = '\0';
    elt->regex = regex_compile.regex;

    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t ngx_http_waf_make_regexp_from_array(ngx_pool_t* pool, char** strv, ngx_array_t* array) {
    for (int i = 0; strv[i] != NULL; i++) {
        ngx_str_t str;
        str.data = (u_char*)strv[i];
        str.len = ngx_strlen(strv[i]);
        ngx_regex_elt_t* elt = ngx_array_push(array);
        if (ngx_http_waf_make_regexp(pool, str, elt) != NGX_HTTP_WAF_SUCCESS) {
            return NGX_HTTP_WAF_FAIL;
        }
    }

    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t ngx_http_waf_gen_no_cache_header(ngx_http_request_t* r) {
    ngx_table_elt_t* header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        return NGX_HTTP_WAF_FAIL; 
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"cache-control";
    ngx_str_set(&header->key, "Cache-control");
    ngx_str_set(&header->value, "no-store");
    return NGX_HTTP_WAF_SUCCESS;
}


void ngx_http_waf_register_content_handler(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);
    
    ctx->register_content_handler = NGX_HTTP_WAF_TRUE;
    r->content_handler = ngx_http_waf_handler_precontent_phase;
    ngx_http_waf_dp_func_end(r);
}


char* ngx_http_waf_c_str(ngx_str_t* str, ngx_pool_t* pool) {
    char* ret = NULL;

    if (str->data == NULL || str->len == 0) {
        return NULL;
    }

    ret = ngx_pnalloc(pool, str->len + 1);
    ngx_memcpy(ret, str->data, str->len);
    ret[str->len] = '\0';

    return ret;
}


static size_t _curl_handler_write(void *contents, size_t size, size_t nmemb, void *userp)
{
    struct {
        ngx_http_request_t* r;
        ngx_buf_t buf;
    } *p = userp;
    ngx_http_request_t* r = p->r;
    ngx_buf_t* buf = &p->buf;
    size_t realsize = size * nmemb;
    size_t offset = buf->last - buf->pos;
    
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_dp(r, "reallocing");
    char *ptr = realloc(buf->pos, buf->last - buf->pos + realsize + 1);
    assert(ptr != NULL);
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dp(r, "copying response");
    buf->pos = (u_char*)ptr;
    buf->last = buf->pos + offset;
    ngx_memcpy(buf->last, contents, realsize);
    buf->last += realsize;
    *(buf->last) = 0;
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dpf(r, "current response is %s", buf->pos);
    
    ngx_http_waf_dp_func_end(r);
    return realsize;
}


static int _curl_handler_debug(CURL* handle, curl_infotype type, char* data, size_t size, void* userp) {
    ngx_http_request_t* r = userp;
    ngx_http_waf_dp_func_start(r);

    char* type_str = "";
    int is_ssl = NGX_HTTP_WAF_FALSE;
    switch (type) {
        case CURLINFO_TEXT:
            type_str = "Text";
            break;
        case CURLINFO_HEADER_OUT:
            type_str = "Header Out";
            break;
        case CURLINFO_DATA_OUT:
            type_str = "Data Out";
            break;
        case CURLINFO_SSL_DATA_OUT:
            is_ssl = NGX_HTTP_WAF_TRUE;
            type_str = "SSL Data Out";
            break;
        case CURLINFO_HEADER_IN:
            type_str = "Header In";
            break;
        case CURLINFO_DATA_IN :
            type_str = "Data In";
            break;
        case CURLINFO_SSL_DATA_IN:
            is_ssl = NGX_HTTP_WAF_TRUE;
            type_str = "SSL Data In";
            break;
        case CURLINFO_END:
            type_str = "End";
            break;
    }

    ngx_str_t tmp;
    tmp.data = (u_char*)data;
    tmp.len = size / sizeof(u_char);

    if (is_ssl == NGX_HTTP_WAF_TRUE) {
        ngx_http_waf_dpf(r, "curl_debug - %s - Encrypted Data", type_str);
    } else {
        ngx_http_waf_dpf(r, "curl_debug - %s - %V", type_str, &tmp);
    }

    ngx_http_waf_dp_func_end(r);
    return CURLE_OK;
}


void ngx_http_waf_utarray_ngx_str_ctor(void *dst, const void *src) {
    ngx_str_t* _dst = (ngx_str_t*)dst;
    const ngx_str_t* _src = (const ngx_str_t*)src;

    _dst->data = malloc(sizeof(u_char) * (_src->len + 1));
    ngx_memcpy(_dst->data, _src->data, sizeof(u_char) * _src->len);
    _dst->data[_src->len] = '\0';
    _dst->len = _src->len;
}


void ngx_http_waf_utarray_ngx_str_dtor(void* elt) {
    ngx_str_t* _elt = (ngx_str_t*)elt;
    free(_elt->data);
}