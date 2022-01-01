#include <ngx_http_waf_module_config.h>

extern ngx_module_t ngx_http_waf_module;


#define _streq(s1, s2) ( ngx_strcmp(s1, s2) == 0 )

#define _strneq(s1, s2, n) { ngx_strncmp(s1, s2, n) == 0 }

#define _strcaseeq(s1, s2) ( ngx_strcasecmp((u_char*)(s1), (u_char*)(s2)) == 0 )

#define _strncaseeq(s1, s2) ( ngx_strncasecmp((u_char*)(s1), (u_char*)(s2), n) == 0 )

#if !(NGX_PCRE2)
extern void *(*pcre_malloc)(size_t);

extern void  (*pcre_free)(void *);
#endif


#if !(NGX_PCRE2)
static ngx_pool_t* _modsecurity_pcre_pool;

static void* _old_modsecurity_pcre_malloc;

static void* _old_modsecurity_pcre_free;
#endif


static void _cleanup(void* data);


static ngx_int_t _init_rule_containers(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf);


// static ngx_int_t _free_rule_containers(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf);


static ngx_int_t _load_into_container(ngx_conf_t* cf, const char* file_name, void* container, ngx_int_t mode);


static ngx_int_t _load_all_rule(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf);


static ngx_int_t _init_lru_cache(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf);


static void _cleanup_lru_cache(void* data);


static ngx_int_t _shm_handler_init(shm_t* shm, void* data, void* old_data);


static ngx_int_t _shm_handler_gc(shm_t* shm, void* data, ngx_int_t* low_memory);

#if !(NGX_PCRE2)
static ngx_pool_t* _change_modsecurity_pcre_callback(ngx_pool_t* pool);


static void _recover_modsecurity_pcre_callback(ngx_pool_t* old_pool);


static void* _modsecurity_pcre_malloc(size_t size);


static void _modsecurity_pcre_free(void* ptr);
#endif


char* ngx_http_waf_zone_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_main_conf_t* main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    ngx_str_t* p_str = cf->args->elts;

    ngx_str_t zone_name;
    size_t zone_size = 0;
    ngx_str_null(&zone_name);

    for (size_t i = 1; i < cf->args->nelts; i++) {

        UT_array* array = NULL;

        if (ngx_http_waf_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, NULL);

        if (_streq(p->data, "name")) {
            p = (ngx_str_t*)utarray_next(array, p);

            zone_name.data = ngx_pstrdup(cf->pool, p);
            zone_name.len = p->len;

        } else if (_streq(p->data, "size")) {
            p = (ngx_str_t*)utarray_next(array, p);

            ssize_t temp = ngx_parse_size(p);

            if (temp == NGX_ERROR
                || temp <= 0) {
                goto error;
            }

            zone_size = ngx_max(temp, NGX_HTTP_WAF_ZONE_SIZE_MIN);
            
        } else {
            goto error;
        }

        utarray_free(array);
    }

    if (ngx_http_waf_shm_get(&zone_name) != NULL) {
        goto duplicate_zone_name;
    }

    shm_t* shm = ngx_array_push(main_conf->shms);
    
    if (shm == NULL) {
        goto unexpected_error;
    }

    if (ngx_http_waf_shm_init(shm, cf, &zone_name, zone_size) != NGX_HTTP_WAF_SUCCESS) {
        goto unexpected_error;
    }



    return NGX_CONF_OK;

unexpected_error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: unexpected error");
    return NGX_CONF_ERROR;

duplicate_zone_name:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: duplicate zone names");
    return NGX_CONF_ERROR;

error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    if (p_str[1].len == 3 && ngx_memcmp(p_str[1].data, "off", 3) == 0) {
        loc_conf->waf = 0;
        return NGX_CONF_OK;
    }

    if (p_str[1].len == 2 && ngx_memcmp(p_str[1].data, "on", 2) == 0) {
        loc_conf->waf = 1;

        if (_init_rule_containers(cf, loc_conf) != NGX_HTTP_WAF_SUCCESS) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    if (p_str[1].len == 6 && ngx_memcmp(p_str[1].data, "bypass", 6) == 0) {
        loc_conf->waf = 2;

        if (_init_rule_containers(cf, loc_conf) != NGX_HTTP_WAF_SUCCESS) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    return NGX_CONF_ERROR;
}


char* ngx_http_waf_rule_path_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    if (ngx_conf_set_str_slot(cf, cmd, conf) != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_waf: %s", "the path of the rule files is not specified");
        return NGX_CONF_ERROR;
    }

    if (_init_rule_containers(cf, loc_conf) != NGX_HTTP_WAF_SUCCESS) {
        return NGX_CONF_ERROR;
    }

    if (_load_all_rule(cf, loc_conf) != NGX_HTTP_WAF_SUCCESS) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char* ngx_http_waf_mode_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = (ngx_http_waf_loc_conf_t*)conf;
    ngx_str_t* modes = cf->args->elts;
    size_t i;


    for (i = 1; i < cf->args->nelts && modes != NULL; i++) {
        #define _parse_mode(mode_str, not_mode_str, mode_bit) {                     \
            if (ngx_strncasecmp(modes[i].data,                                                  \
                (u_char*)(mode_str),                                                            \
                ngx_min(modes[i].len, sizeof((mode_str)) - 1)) == 0                             \
                && modes[i].len == sizeof((mode_str)) - 1) {                                    \
                loc_conf->waf_mode |= mode_bit;                                                 \
                continue;                                                                       \
            } else if (ngx_strncasecmp(modes[i].data,                                           \
                                      (u_char*)(not_mode_str),                                  \
                                      ngx_min(modes[i].len, sizeof((not_mode_str)) - 1)) == 0   \
                && modes[i].len == sizeof((not_mode_str)) - 1) {                                \
                loc_conf->waf_mode &= ~mode_bit;                                                \
                continue;                                                                       \
            }                                                                                   \
        }

        _parse_mode("GET", "!GET", NGX_HTTP_WAF_MODE_INSPECT_GET);
        _parse_mode("HEAD", "!HEAD", NGX_HTTP_WAF_MODE_INSPECT_HEAD);
        _parse_mode("POST", "!POST", NGX_HTTP_WAF_MODE_INSPECT_POST);
        _parse_mode("PUT", "!PUT", NGX_HTTP_WAF_MODE_INSPECT_PUT);
        _parse_mode("DELETE", "!DELETE", NGX_HTTP_WAF_MODE_INSPECT_DELETE);
        _parse_mode("MKCOL", "!MKCOL", NGX_HTTP_WAF_MODE_INSPECT_MKCOL);
        _parse_mode("COPY", "!COPY", NGX_HTTP_WAF_MODE_INSPECT_COPY);
        _parse_mode("MOVE", "!MOVE", NGX_HTTP_WAF_MODE_INSPECT_MOVE);
        _parse_mode("OPTIONS", "!OPTIONS", NGX_HTTP_WAF_MODE_INSPECT_OPTIONS);
        _parse_mode("PROPFIND", "!PROPFIND", NGX_HTTP_WAF_MODE_INSPECT_PROPFIND);
        _parse_mode("PROPPATCH", "!PROPPATCH", NGX_HTTP_WAF_MODE_INSPECT_PROPPATCH);
        _parse_mode("LOCK", "!LOCK", NGX_HTTP_WAF_MODE_INSPECT_LOCK);
        _parse_mode("UNLOCK", "!UNLOCK", NGX_HTTP_WAF_MODE_INSPECT_UNLOCK);
        _parse_mode("PATCH", "!PATCH", NGX_HTTP_WAF_MODE_INSPECT_PATCH);
        _parse_mode("TRACE", "!TRACE", NGX_HTTP_WAF_MODE_INSPECT_TRACE);
        _parse_mode("CMN-METH", "!CMN-METH", NGX_HTTP_WAF_MODE_CMN_METH);
        _parse_mode("ALL-METH", "!ALL-METH", NGX_HTTP_WAF_MODE_ALL_METH);
        _parse_mode("IP", "!IP", NGX_HTTP_WAF_MODE_INSPECT_IP);
        _parse_mode("URL", "!URL", NGX_HTTP_WAF_MODE_INSPECT_URL);
        _parse_mode("RBODY", "!RBODY", NGX_HTTP_WAF_MODE_INSPECT_RB);
        _parse_mode("ARGS", "!ARGS", NGX_HTTP_WAF_MODE_INSPECT_ARGS);
        _parse_mode("UA", "!UA", NGX_HTTP_WAF_MODE_INSPECT_UA);
        _parse_mode("COOKIE", "!COOKIE", NGX_HTTP_WAF_MODE_INSPECT_COOKIE);
        _parse_mode("REFERER", "!REFERER", NGX_HTTP_WAF_MODE_INSPECT_REFERER);
        _parse_mode("STD", "!STD", NGX_HTTP_WAF_MODE_STD);
        _parse_mode("STATIC", "!STATIC", NGX_HTTP_WAF_MODE_STATIC);
        _parse_mode("DYNAMIC", "!DYNAMIC", NGX_HTTP_WAF_MODE_DYNAMIC);
        _parse_mode("FULL", "!FULL", NGX_HTTP_WAF_MODE_FULL);

        #undef _parse_mode

#ifndef NGX_HTTP_WAF_NO_EASTER_EGG

        if (modes[i].len == sizeof("NICO") - 1
            && ngx_memcmp(modes[i].data, "NICO", sizeof("NICO") - 1) == 0) {
            fprintf(stderr, 
                "\n\n↓↓↓ Say cheese! ↓↓↓\n%s\n↑↑↑ Say cheese! ↑↑↑\n\n",
                ngx_http_waf_data_ascii_art_nico);
            
            continue;
        }

#endif

        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
            "ngx_waf: invalid value.");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char* ngx_http_waf_cc_deny_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    /* 默认封禁 60 分钟 */
    loc_conf->waf_cc_deny_duration = 1 * 60 * 60;

    if (ngx_strncmp(p_str[1].data, "on", ngx_min(p_str[1].len, 2)) == 0) {
        loc_conf->waf_cc_deny = 1;

    } else if (ngx_strncmp(p_str[1].data, "off", ngx_min(p_str[1].len, sizeof("off") - 1)) == 0) {
        loc_conf->waf_cc_deny = 0;

    } else {
        goto error;
    }

    if (loc_conf->waf_cc_deny == 0) {
        return NGX_CONF_OK;
    }

    for (size_t i = 2; i < cf->args->nelts; i++) {

        UT_array* array = NULL;
        if (ngx_http_waf_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, NULL);

        if (_streq(p->data, "rate")) {
            p = (ngx_str_t*)utarray_next(array, p);

            UT_array* temp = NULL;
            if (ngx_http_waf_str_split(p, '/', 256, &temp) != NGX_HTTP_WAF_SUCCESS) {
                goto error;
            }

            if (utarray_len(temp) != 2) {
                goto error;
            }

            ngx_str_t* q = NULL;
            q = (ngx_str_t*)utarray_next(temp, q);
            loc_conf->waf_cc_deny_limit = ngx_atoi(q->data, q->len - 1);
            if (loc_conf->waf_cc_deny_limit == NGX_ERROR || loc_conf->waf_cc_deny_limit <= 0) {
                goto error;
            }
            if (q->data[q->len - 1] != 'r') {
                goto error;
            }

            q = (ngx_str_t*)utarray_next(temp, q);
            loc_conf->waf_cc_deny_cycle = ngx_http_waf_parse_time(q->data);
            if (loc_conf->waf_cc_deny_cycle == NGX_ERROR || loc_conf->waf_cc_deny_cycle <= 0) {
                goto error;
            }
            utarray_free(temp);

        } else if (_streq(p->data, "duration")) {
            p = (ngx_str_t*)utarray_next(array, p);

            loc_conf->waf_cc_deny_duration = ngx_http_waf_parse_time(p->data);
            if (loc_conf->waf_cc_deny_duration == NGX_ERROR) {
                goto error;
            }

        } else if (_streq(p->data, "zone")) {
            p = (ngx_str_t*)utarray_next(array, p);

            UT_array* temp = NULL;
            if (ngx_http_waf_str_split(p, ':', 256, &temp) != NGX_HTTP_WAF_SUCCESS) {
                goto error;
            }

            if (utarray_len(temp) != 2) {
                goto error;
            }

            ngx_str_t* zone_name = NULL;
            ngx_str_t* zone_tag = NULL;
            zone_name = (ngx_str_t*)utarray_next(temp, NULL);
            zone_tag = (ngx_str_t*)utarray_next(temp, zone_name);

            ngx_str_t tag;
            tag.data = ngx_pcalloc(cf->pool, zone_tag->len + sizeof("cc_deny"));
            tag.len = zone_tag->len + sizeof("cc_deny") - 1;
            ngx_sprintf(tag.data, "%s%s", zone_tag->data, "cc_deny");
            zone_tag = &tag;

            shm_t* shm = ngx_http_waf_shm_get(zone_name);

            if (shm == NULL) {
                goto no_zone;
            }

            if (ngx_http_waf_shm_tag_is_used(zone_name, zone_tag) == NGX_HTTP_WAF_TRUE) {
                goto reused_tag;
            }

            loc_conf->shm_zone_cc_deny = shm->zone;

            shm_init_t* init = ngx_http_waf_shm_init_handler_add(shm);
            
            if (init == NULL) {
                goto unexpected_error;
            }

            

            init->data = &loc_conf->ip_access_statistics;
            init->tag = tag;
            init->init_handler = _shm_handler_init;
            init->gc_handler = _shm_handler_gc;

            utarray_free(temp);
            
        } else {
            goto error;
        }

        utarray_free(array);
    }

    if (loc_conf->waf_cc_deny_limit == NGX_CONF_UNSET) {
        goto error;
    }

    return NGX_CONF_OK;

unexpected_error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: unexpected error");
    return NGX_CONF_ERROR;

reused_tag:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: each tag of a zone can only be used once");
    return NGX_CONF_ERROR;

no_zone:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: zone name does not exists");
    return NGX_CONF_ERROR;

error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_cache_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    loc_conf->waf_cache_capacity = 50;

    if (ngx_strncmp(p_str[1].data, "on", ngx_min(p_str[1].len, 2)) == 0) {
        loc_conf->waf_cache = 1;

    } else if (ngx_strncmp(p_str[1].data, "off", ngx_min(p_str[1].len, 3)) == 0) {
        loc_conf->waf_cache = 0;

    } else {
        goto error;
    }

    if (loc_conf->waf_cache == 0) {
        return NGX_CONF_OK;
    }

    for (size_t i = 2; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_http_waf_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (_streq(p->data, "capacity")) {
            p = (ngx_str_t*)utarray_next(array, p);

            loc_conf->waf_cache_capacity = ngx_atoi(p->data, p->len);

            if (loc_conf->waf_cache_capacity == NGX_ERROR
                || loc_conf->waf_cache_capacity <= 0) {
                goto error;
            }
            
        } else {
            goto error;
        }

        utarray_free(array);
    }

    if (_init_lru_cache(cf, loc_conf) != NGX_HTTP_WAF_SUCCESS) {
        goto error;
    }

    return NGX_CONF_OK;

error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_under_attack_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    loc_conf->waf_under_attack = NGX_CONF_UNSET;

    if (ngx_strncmp(p_str[1].data, "on", ngx_min(p_str[1].len, 2)) == 0) {
        loc_conf->waf_under_attack = 1;

    } else if (ngx_strncmp(p_str[1].data, "off", ngx_min(p_str[1].len, 3)) == 0){
        loc_conf->waf_under_attack = 0;

    } else {
        goto error;
    }

    if (loc_conf->waf_under_attack == 0) {
        return NGX_CONF_OK;
    }

    for (size_t i = 2; i < cf->args->nelts; i++) {
        UT_array* array = NULL;

        if (ngx_http_waf_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (_streq(p->data, "file")) {
            p = (ngx_str_t*)utarray_next(array, p);

            if (p == NULL || p->data == NULL || p->len == 0) {
                goto error;
            }

            FILE* fp = fopen((char*)p->data, "r");

            if (fp == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOENT, 
                    "ngx_waf: Unable to open file %s.", p->data);
                return NGX_CONF_ERROR;
            }

            fseek(fp, 0, SEEK_END);
            size_t file_size = ftell(fp);
            loc_conf->waf_under_attack_html.len = file_size;
            loc_conf->waf_under_attack_html.data = ngx_pcalloc(cf->pool, file_size + sizeof(u_char));

            fseek(fp, 0, SEEK_SET);
            if (fread(loc_conf->waf_under_attack_html.data, sizeof(u_char), file_size, fp) != file_size) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EPERM, 
                    "ngx_waf: Failed to read file %s completely..", p->data);
                return NGX_CONF_ERROR;
            }

            fclose(fp);

        } else {
            goto error;
        }

        utarray_free(array);
    }

    if (loc_conf->waf_under_attack_html.data == NULL) {
        ngx_str_set(&loc_conf->waf_under_attack_html, ngx_http_waf_data_html_under_attack);
    }

    return NGX_CONF_OK;

error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_captcha_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    ngx_str_t default_html_template = ngx_null_string;
    ngx_str_t sitekey = ngx_null_string;

    loc_conf->waf_captcha = NGX_CONF_UNSET;
    loc_conf->waf_captcha_expire = 60 * 30;
    loc_conf->waf_captcha_reCAPTCHAv3_score = 0.5;
    ngx_str_set(&loc_conf->waf_captcha_verify_url, "/captcha");

    if (ngx_strncmp(p_str[1].data, "on", ngx_min(p_str[1].len, 2)) == 0) {
        loc_conf->waf_captcha = 1;

    } else if (ngx_strncmp(p_str[1].data, "off", ngx_min(p_str[1].len, 3)) == 0) {
        loc_conf->waf_captcha = 0;

    } else {
        goto error;
    }

    for (size_t i = 2; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_http_waf_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (_streq(p->data, "file")) {
            p = (ngx_str_t*)utarray_next(array, p);

            if (p == NULL || p->data == NULL || p->len == 0) {
                goto error;
            }

            FILE* fp = fopen((char*)p->data, "r");

            if (fp == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOENT, 
                    "ngx_waf: Unable to open file %s.", p->data);
                return NGX_CONF_ERROR;
            }

            fseek(fp, 0, SEEK_END);
            size_t file_size = ftell(fp);
            loc_conf->waf_captcha_html.len = file_size;
            loc_conf->waf_captcha_html.data = ngx_pcalloc(cf->pool, file_size + sizeof(u_char));

            fseek(fp, 0, SEEK_SET);
            if (fread(loc_conf->waf_captcha_html.data, sizeof(u_char), file_size, fp) != file_size) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EPERM, 
                    "ngx_waf: Failed to read file %s completely..", p->data);
                return NGX_CONF_ERROR;
            }

            fclose(fp);

        } else if (_streq(p->data, "prov")) {
            p = (ngx_str_t*)utarray_next(array, p);

            if (p == NULL || p->data == NULL || p->len == 0) {
                goto error;
            }
            
            if (_strcaseeq(p->data, "hCaptcha")) {
                loc_conf->waf_captcha_type = NGX_HTTP_WAF_HCAPTCHA;
                ngx_str_set(&default_html_template, ngx_http_waf_data_html_template_hCaptcha);

            } else if (_strcaseeq(p->data, "reCAPTCHAv2:checkbox")) {
                loc_conf->waf_captcha_type = NGX_HTTP_WAF_RECAPTCHA_V2_CHECKBOX;
                ngx_str_set(&default_html_template, ngx_http_waf_data_html_template_reCAPTCHAv2_checkbox);

            } else if (_strcaseeq(p->data, "reCAPTCHAv2:invisible")) {
                loc_conf->waf_captcha_type = NGX_HTTP_WAF_RECAPTCHA_V2_INVISIBLE;
                ngx_str_set(&default_html_template, ngx_http_waf_data_html_template_reCAPTCHAv2_invisible);

            } else if (_strcaseeq(p->data, "reCAPTCHAv3")) {
                loc_conf->waf_captcha_type = NGX_HTTP_WAF_RECAPTCHA_V3;
                ngx_str_set(&default_html_template, ngx_http_waf_data_html_template_reCAPTCHAv3);

            } else {
                goto error;
            }

        } else if (_streq(p->data, "secret")) {
            p = (ngx_str_t*)utarray_next(array, p);

            if (p == NULL || p->data == NULL || p->len == 0) {
                goto error;
            }

            loc_conf->waf_captcha_hCaptcha_secret.data = ngx_pcalloc(cf->pool, p->len + 1);
            ngx_memcpy(loc_conf->waf_captcha_hCaptcha_secret.data, p->data, p->len);
            loc_conf->waf_captcha_hCaptcha_secret.len = p->len;

            ngx_memcpy(&loc_conf->waf_captcha_reCAPTCHAv2_secret, &loc_conf->waf_captcha_hCaptcha_secret, sizeof(ngx_str_t));
            ngx_memcpy(&loc_conf->waf_captcha_reCAPTCHAv3_secret, &loc_conf->waf_captcha_hCaptcha_secret, sizeof(ngx_str_t));

        }  else if (_streq(p->data, "sitekey")) {
            p = (ngx_str_t*)utarray_next(array, p);

            if (p == NULL || p->data == NULL || p->len == 0) {
                goto error;
            }

            sitekey.data = ngx_pstrdup(cf->pool, p);
            sitekey.len = p->len;
            

        } else if (_streq(p->data, "expire")) {
            p = (ngx_str_t*)utarray_next(array, p);

            loc_conf->waf_captcha_expire = ngx_http_waf_parse_time(p->data);

            if (loc_conf->waf_captcha_expire == NGX_ERROR) {
                goto error;
            }

        } else if (_streq(p->data, "score")) {
            p = (ngx_str_t*)utarray_next(array, p);

            loc_conf->waf_captcha_reCAPTCHAv3_score = atof((char*)p->data);

            if (loc_conf->waf_captcha_reCAPTCHAv3_score < 0.0 && loc_conf->waf_captcha_reCAPTCHAv3_score > 1.0) {
                goto error;
            }

        } else if (_streq(p->data, "api")) {
            p = (ngx_str_t*)utarray_next(array, p);

            loc_conf->waf_captcha_api.data = ngx_pcalloc(cf->pool, p->len + 1);
            ngx_memcpy(loc_conf->waf_captcha_api.data, p->data, p->len);
            loc_conf->waf_captcha_api.len = p->len;

        } else if (_streq(p->data, "verfiy")) {
            p = (ngx_str_t*)utarray_next(array, p);

            loc_conf->waf_captcha_verify_url.data = ngx_pcalloc(cf->pool, p->len + 1);
            ngx_memcpy(loc_conf->waf_captcha_verify_url.data, p->data, p->len);
            loc_conf->waf_captcha_verify_url.len = p->len;

        }  else if (_streq(p->data, "max_fails")) {
            p = (ngx_str_t*)utarray_next(array, p);

            UT_array* temp = NULL;
            if (ngx_http_waf_str_split(p, ':', 256, &temp) != NGX_HTTP_WAF_SUCCESS) {
                goto error;
            }

            if (utarray_len(temp) != 2) {
                goto error;
            }

            ngx_str_t* max_fails = NULL;
            ngx_str_t* duration = NULL;

            max_fails = (ngx_str_t*)utarray_next(temp, NULL);
            duration = (ngx_str_t*)utarray_next(temp, max_fails);

            loc_conf->waf_captcha_max_fails = ngx_atoi(max_fails->data, max_fails->len);

            if (loc_conf->waf_captcha_max_fails == NGX_ERROR
                || loc_conf->waf_captcha_max_fails <= 0) {
                goto error;
            }

            loc_conf->waf_captcha_duration = ngx_http_waf_parse_time(duration->data);

            if (loc_conf->waf_captcha_duration == NGX_ERROR) {
                goto error;
            }

        }  else if (_streq(p->data, "zone")) {
            p = (ngx_str_t*)utarray_next(array, p);

            UT_array* temp = NULL;
            if (ngx_http_waf_str_split(p, ':', 256, &temp) != NGX_HTTP_WAF_SUCCESS) {
                goto error;
            }

            if (utarray_len(temp) != 2) {
                goto error;
            }

            ngx_str_t* zone_name = NULL;
            ngx_str_t* zone_tag = NULL;
            zone_name = (ngx_str_t*)utarray_next(temp, NULL);
            zone_tag = (ngx_str_t*)utarray_next(temp, zone_name);

            ngx_str_t tag;
            tag.data = ngx_pcalloc(cf->pool, zone_tag->len + sizeof("captcha"));
            tag.len = zone_tag->len + sizeof("captcha") - 1;
            ngx_sprintf(tag.data, "%s%s", zone_tag->data, "captcha");
            zone_tag = &tag;

            shm_t* shm = ngx_http_waf_shm_get(zone_name);

            if (shm == NULL) {
                goto no_zone;
            }

            if (ngx_http_waf_shm_tag_is_used(zone_name, zone_tag) == NGX_HTTP_WAF_TRUE) {
                goto reused_tag;
            }

            loc_conf->waf_captcha_shm_zone = shm->zone;

            shm_init_t* init = ngx_http_waf_shm_init_handler_add(shm);
            
            if (init == NULL) {
                goto unexpected_error;
            }

            init->data = &loc_conf->waf_captcha_cache;
            init->tag = tag;
            init->init_handler = _shm_handler_init;
            init->gc_handler = _shm_handler_gc;

            utarray_free(temp);
            
        } else {
            goto error;
        }

        utarray_free(array);
    }

    if (loc_conf->waf_captcha == NGX_CONF_UNSET) {
        goto no_prov;
    }

    if (!ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_captcha_max_fails)
        || !ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_captcha_duration)) {

        if (!ngx_http_waf_is_valid_ptr_value(loc_conf->waf_captcha_shm_zone)) {
            goto max_fails_with_zone;
        }
    }

    if (ngx_is_null_str(&loc_conf->waf_captcha_html)) {

        if (ngx_is_null_str(&sitekey)) {
            goto no_sitekey;
        }

        u_char* buf = ngx_pcalloc(cf->pool, default_html_template.len + sitekey.len + 1);
        size_t len = ngx_sprintf(buf, (const char*)default_html_template.data, &sitekey) - buf;
        loc_conf->waf_captcha_html.data = buf;
        loc_conf->waf_captcha_html.len = len;
    }

    if (ngx_is_null_str(&loc_conf->waf_captcha_hCaptcha_secret)
        || ngx_is_null_str(&loc_conf->waf_captcha_reCAPTCHAv2_secret)
        || ngx_is_null_str(&loc_conf->waf_captcha_reCAPTCHAv3_secret)) {
        
        goto no_secret;
    }

    if (ngx_is_null_str(&loc_conf->waf_captcha_api)) {
        switch (loc_conf->waf_captcha_type) {
            case NGX_HTTP_WAF_HCAPTCHA:
                ngx_str_set(&loc_conf->waf_captcha_api, "https://hcaptcha.com/siteverify");
                break;
            case NGX_HTTP_WAF_RECAPTCHA_V2_CHECKBOX:
                ngx_str_set(&loc_conf->waf_captcha_api, "https://www.recaptcha.net/recaptcha/api/siteverify");
                break;
            case NGX_HTTP_WAF_RECAPTCHA_V2_INVISIBLE:
                ngx_str_set(&loc_conf->waf_captcha_api, "https://www.recaptcha.net/recaptcha/api/siteverify");
                break;
            case NGX_HTTP_WAF_RECAPTCHA_V3:
                ngx_str_set(&loc_conf->waf_captcha_api, "https://www.recaptcha.net/recaptcha/api/siteverify");
                break;
            default:
                break;
        }
    }

    return NGX_CONF_OK;

no_prov:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
        "ngx_waf: you must set the parameter [prov]");
    return NGX_CONF_ERROR;

no_secret:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
        "ngx_waf: you must set the parameter [secret]");
    return NGX_CONF_ERROR;


max_fails_with_zone:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
        "ngx_waf: If you set the parameter [max_fails], you must set the parameter [zone]");
    return NGX_CONF_ERROR;

unexpected_error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: unexpected error");
    return NGX_CONF_ERROR;

reused_tag:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: each tag of a zone can only be used once");
    return NGX_CONF_ERROR;

no_zone:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: zone name does not exists");
    return NGX_CONF_ERROR;

no_sitekey:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
        "ngx_waf: you must set the parameter [sitekey]");
    return NGX_CONF_ERROR;

error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_priority_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;
    // u_char error_str[256];

    loc_conf->is_custom_priority = NGX_HTTP_WAF_TRUE;

    UT_array* array = NULL;
    if (ngx_http_waf_str_split(p_str + 1, ' ', 20, &array) != NGX_HTTP_WAF_SUCCESS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
            "ngx_waf: invalid value");
        return NGX_CONF_ERROR;
    }


    if (utarray_len(array) != 15) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
            "ngx_waf: you must specify the priority of all inspections");
        return NGX_CONF_ERROR;
    }


    ngx_str_t* p = NULL;
    size_t proc_index = 1;
    while ((p = (ngx_str_t*)utarray_next(array, p))) {
        #define _parse_priority(str, pt) {          \
            if (strcasecmp((str), (char*)(p->data)) == 0) {     \
                loc_conf->check_proc[proc_index++] = pt;        \
                continue;                                       \
            }                                                   \
        }

        _parse_priority("CC", ngx_http_waf_handler_check_cc);
        _parse_priority("W-IP", ngx_http_waf_handler_check_white_ip);
        _parse_priority("IP", ngx_http_waf_handler_check_black_ip);
        _parse_priority("W-URL", ngx_http_waf_handler_check_white_url);
        _parse_priority("URL", ngx_http_waf_handler_check_black_url);
        _parse_priority("ARGS", ngx_http_waf_handler_check_black_args);
        _parse_priority("UA", ngx_http_waf_handler_check_black_user_agent);
        _parse_priority("W-REFERER", ngx_http_waf_handler_check_white_referer);
        _parse_priority("REFERER", ngx_http_waf_handler_check_black_referer);
        _parse_priority("COOKIE", ngx_http_waf_handler_check_black_cookie);
        _parse_priority("UNDER-ATTACK", ngx_http_waf_handler_under_attack);
        _parse_priority("POST", ngx_http_waf_handler_check_black_post);
        _parse_priority("CAPTCHA", ngx_http_waf_handler_captcha);
        _parse_priority("VERIFY-BOT", ngx_http_waf_handler_verify_bot);
        _parse_priority("MODSECURITY", ngx_http_waf_handler_modsecurity);

        #undef _parse_priority

        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
                          "ngx_waf: ngx_waf: invalid value [%s]", p->data);
        return NGX_CONF_ERROR;
    }

    utarray_free(array);

    return NGX_CONF_OK;
}


char* ngx_http_waf_verify_bot_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    static char* s_google_bot_ua_regexp[] = {
        "Googlebot",
        "Google Favicon",
        "Googlebot-News",
        "Googlebot-Image",
        "Googlebot-Video",
        "Google-Read-Aloud",
        "AdsBot-Google",
        "AdsBot-Google-Mobile",
        "AdsBot-Google-Mobile-Apps",
        "APIs-Google",
        "googleweblight",
        "Storebot-Google",
        "DuplexWeb-Google",
        // "FeedFetcher-Google",
        "Mediapartners-Google",
        NULL
    };

    static char* s_google_bot_domain_regexp[] = {
        "googlebot\\.com$",
        "google\\.com$",
        NULL
    };

    static char* s_bing_bot_ua_regexp[] = {
        "bingbot",
        "adidxbot",
        "BingPreview",
        NULL
    };

    static char* s_bing_bot_domain_regexp[] = {
        "search\\.msn\\.com$",
        NULL
    };

    static char* s_baidu_spider_ua_regexp[] = {
        "Baiduspider",
        "Baiduspider-ads",
        "Baiduspider-cpro",
        "Baiduspider-favo",
        "Baiduspider-news",
        "Baiduspider-video",
        "Baiduspider-image",
        NULL
    };

    static char* s_baidu_spider_domain_regexp[] = {
        "baidu\\.com$",
        "baidu\\.jp$",
        NULL
    };

    static char* s_yandex_bot_ua_regexp[] = {
        "YandexBot",
        "YandexRCA",
        "YandexNews",
        "YandexAdNet",
        "YandexMedia",
        "YandexBlogs",
        "YandexTurbo",
        "YandexVideo",
        "YandexDirect",
        "YandexVertis",
        "YandexMarket",
        "YandexOntoDB",
        "YandexImages",
        "YandexTracker",
        "YandexMetrika",
        "YandexPartner",
        "YandexSpravBot",
        "YandexCalendar",
        "YandexFavicons",
        "YandexMobileBot",
        "YandexWebmaster",
        "YandexVerticals",
        "YandexOntoDBAPI",
        "YandexDirectDyn",
        "YandexSitelinks",
        "YaDirectFetcher",
        "YandexForDomain",
        "YandexSearchShop",
        "YandexVideoParser",
        "YandexPagechecker",
        "YandexImageResizer",
        "YandexAccessibilityBot",
        "YandexMobileScreenShotBot",
        NULL
    };

    static char* s_yandex_bot_domain_regexp[] = {
        "yandex\\.com$",
        "yandex\\.net$",
        "yandex\\.ru$",
        NULL
    };

    static char* s_sogou_spider_ua_regexp[] = {
        "Sogou.*spider",
        NULL
    };

    static char* s_sogou_spider_domain_regexp[] = {
        "sogou\\.com$",
        NULL
    };

    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    loc_conf->waf_verify_bot = NGX_CONF_UNSET;
    loc_conf->waf_verify_bot_type = BOT_TYPE_UNSET;

    if (ngx_strncmp(p_str[1].data, "on", ngx_min(p_str[1].len, 2)) == 0) {
        loc_conf->waf_verify_bot = 1;

    } else if (ngx_strncmp(p_str[1].data, "strict", ngx_min(p_str[1].len, 6)) == 0) {
        loc_conf->waf_verify_bot = 2;

    } else if (ngx_strncmp(p_str[1].data, "off", ngx_min(p_str[1].len, 3)) == 0) {
        loc_conf->waf_verify_bot = 0;

    } else {
        goto error;
    }

    if (loc_conf->waf_verify_bot == 0) {
        return NGX_CONF_OK;
    }

#define _make_regexp_array(regexps, array) {                                \
    (array) = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));       \
    if (ngx_http_waf_make_regexp_from_array(cf->pool, (regexps), (array))   \
            != NGX_HTTP_WAF_SUCCESS) {                                      \
        return NGX_CONF_ERROR;                                              \
    }                                                                       \
}

    _make_regexp_array(s_google_bot_ua_regexp, loc_conf->waf_verify_bot_google_ua_regexp);
    _make_regexp_array(s_google_bot_domain_regexp, loc_conf->waf_verify_bot_google_domain_regexp);
    _make_regexp_array(s_bing_bot_ua_regexp, loc_conf->waf_verify_bot_bing_ua_regexp);
    _make_regexp_array(s_bing_bot_domain_regexp, loc_conf->waf_verify_bot_bing_domain_regexp);
    _make_regexp_array(s_baidu_spider_ua_regexp, loc_conf->waf_verify_bot_baidu_ua_regexp);
    _make_regexp_array(s_baidu_spider_domain_regexp, loc_conf->waf_verify_bot_baidu_domain_regexp);
    _make_regexp_array(s_yandex_bot_ua_regexp, loc_conf->waf_verify_bot_yandex_ua_regexp);
    _make_regexp_array(s_yandex_bot_domain_regexp, loc_conf->waf_verify_bot_yandex_domain_regexp);
    _make_regexp_array(s_sogou_spider_ua_regexp, loc_conf->waf_verify_bot_sogou_ua_regexp);
    _make_regexp_array(s_sogou_spider_domain_regexp, loc_conf->waf_verify_bot_sogou_domain_regexp);



#undef _make_regexp_array
    

    for (size_t i = 2; i < cf->args->nelts; i++) {
        #define _parse_robot(str, flag)                                                               \
        if (ngx_strncasecmp(p_str[i].data, (u_char*)(str), ngx_min(p_str[i].len, sizeof(str) - 1)) == 0     \
        &&  p_str[i].len == sizeof(str) - 1) {                                                              \
            loc_conf->waf_verify_bot_type |= flag;                                                          \
            continue;                                                                                       \
        }                                                                                                   \

        _parse_robot("GoogleBot", BOT_TYPE_GOOGLE);
        _parse_robot("BingBot", BOT_TYPE_BING);
        _parse_robot("BaiduSpider", BOT_TYPE_BAIDU);
        _parse_robot("YandexBot", BOT_TYPE_YANDEX);
        _parse_robot("SogouSpider", BOT_TYPE_SOGOU);
        
        goto error;

        #undef _parse_robot
    }

    if (loc_conf->waf_verify_bot_type == BOT_TYPE_UNSET) {
        loc_conf->waf_verify_bot_type = BOT_TYPE_GOOGLE 
                                      | BOT_TYPE_BING 
                                      | BOT_TYPE_BAIDU 
                                      | BOT_TYPE_SOGOU
                                      | BOT_TYPE_YANDEX;
    }

    return NGX_CONF_OK;

error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_action_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    loc_conf->action_chain_blacklist = ngx_pcalloc(cf->pool, sizeof(action_t));
    loc_conf->action_chain_cc_deny = ngx_pcalloc(cf->pool, sizeof(action_t));
    loc_conf->action_chain_modsecurity = ngx_pcalloc(cf->pool, sizeof(action_t));
    loc_conf->action_chain_verify_bot = ngx_pcalloc(cf->pool, sizeof(action_t));

    ngx_http_waf_set_action_return(loc_conf->action_chain_blacklist, 
        NGX_HTTP_FORBIDDEN, 
        ACTION_FLAG_FROM_BLACK_LIST | ACTION_FLAG_UNSET);
    
    ngx_http_waf_set_action_return(loc_conf->action_chain_cc_deny, 
        NGX_HTTP_SERVICE_UNAVAILABLE, 
        ACTION_FLAG_FROM_CC_DENY | ACTION_FLAG_UNSET);

    ngx_http_waf_set_action_follow(loc_conf->action_chain_modsecurity, 
        ACTION_FLAG_FROM_MODSECURITY | ACTION_FLAG_UNSET);

    ngx_http_waf_set_action_return(loc_conf->action_chain_verify_bot, 
        NGX_HTTP_FORBIDDEN, 
        ACTION_FLAG_FROM_VERIFY_BOT | ACTION_FLAG_UNSET);


    for (size_t i = 1; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_http_waf_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (_streq(p->data, "blacklist")) {
            p = (ngx_str_t*)utarray_next(array, p);

            if (_strcaseeq(p->data, "CAPTCHA")) {
                ngx_http_waf_make_action_chain_captcha(cf->pool, 
                    loc_conf->action_chain_blacklist,
                    ACTION_FLAG_FROM_BLACK_LIST | ACTION_FLAG_CAPTCHA,
                    &loc_conf->waf_captcha_html);

            } else {
                ngx_int_t code = ngx_atoi(p->data, p->len);

                if (code == NGX_ERROR
                    || code < 300
                    || code >= 600) {
                    goto error;
                }

                ngx_http_waf_set_action_return(loc_conf->action_chain_blacklist, code, ACTION_FLAG_FROM_BLACK_LIST);

            }
            
        } else if (_streq(p->data, "cc_deny")) {
            p = (ngx_str_t*)utarray_next(array, p);

            if (_strcaseeq(p->data, "CAPTCHA")) {
                ngx_http_waf_make_action_chain_captcha(cf->pool, 
                    loc_conf->action_chain_cc_deny,
                    ACTION_FLAG_FROM_CC_DENY | ACTION_FLAG_CAPTCHA,
                    &loc_conf->waf_captcha_html);

            } else {
                ngx_int_t code = ngx_atoi(p->data, p->len);

                if (code == NGX_ERROR
                    || code < 300
                    || code >= 600) {
                    goto error;
                }

                ngx_http_waf_set_action_return(loc_conf->action_chain_cc_deny, code, ACTION_FLAG_FROM_CC_DENY);

            }

        } else if (_streq(p->data, "modsecurity")) {
            p = (ngx_str_t*)utarray_next(array, p);

            if (_strcaseeq(p->data, "CAPTCHA")) {
                ngx_http_waf_make_action_chain_captcha(cf->pool, 
                    loc_conf->action_chain_modsecurity,
                    ACTION_FLAG_FROM_MODSECURITY | ACTION_FLAG_CAPTCHA,
                    &loc_conf->waf_captcha_html);

            } else if (_strcaseeq(p->data, "FOLLOW")) {
                ngx_http_waf_set_action_follow(loc_conf->action_chain_modsecurity, ACTION_FLAG_FROM_MODSECURITY);

            } else {
                ngx_int_t code = ngx_atoi(p->data, p->len);

                if (code == NGX_ERROR
                    || code < 300
                    || code >= 600) {
                    goto error;
                }

                ngx_http_waf_set_action_return(loc_conf->action_chain_modsecurity, code, ACTION_FLAG_FROM_MODSECURITY);

            }

        }  else if (_streq(p->data, "verify_bot")) {
            p = (ngx_str_t*)utarray_next(array, p);

            if (_strcaseeq(p->data, "CAPTCHA")) {
                ngx_http_waf_make_action_chain_captcha(cf->pool, 
                    loc_conf->action_chain_verify_bot,
                    ACTION_FLAG_FROM_VERIFY_BOT | ACTION_FLAG_CAPTCHA,
                    &loc_conf->waf_captcha_html);

            } else {
                ngx_int_t code = ngx_atoi(p->data, p->len);

                if (code == NGX_ERROR
                    || code <= 0) {
                    goto error;
                }

                ngx_http_waf_set_action_return(loc_conf->action_chain_verify_bot, code, ACTION_FLAG_FROM_VERIFY_BOT);

            }

        } else if (_streq(p->data, "zone")) {
            p = (ngx_str_t*)utarray_next(array, p);

            UT_array* temp = NULL;
            if (ngx_http_waf_str_split(p, ':', 256, &temp) != NGX_HTTP_WAF_SUCCESS) {
                goto error;
            }

            if (utarray_len(temp) != 2) {
                goto error;
            }

            ngx_str_t* zone_name = NULL;
            ngx_str_t* zone_tag = NULL;
            zone_name = (ngx_str_t*)utarray_next(temp, NULL);
            zone_tag = (ngx_str_t*)utarray_next(temp, zone_name);

            ngx_str_t tag;
            tag.data = ngx_pcalloc(cf->pool, zone_tag->len + sizeof("action_captcha"));
            tag.len = zone_tag->len + sizeof("action_captcha") - 1;
            ngx_sprintf(tag.data, "%s%s", zone_tag->data, "action_captcha");
            zone_tag = &tag;

            shm_t* shm = ngx_http_waf_shm_get(zone_name);

            if (shm == NULL) {
                goto no_zone;
            }

            if (ngx_http_waf_shm_tag_is_used(zone_name, zone_tag) == NGX_HTTP_WAF_TRUE) {
                goto reused_tag;
            }

            loc_conf->action_zone_captcha = shm->zone;

            shm_init_t* init = ngx_http_waf_shm_init_handler_add(shm);
            
            if (init == NULL) {
                goto unexpected_error;
            }

            init->data = &loc_conf->action_cache_captcha;
            init->tag = tag;
            init->init_handler = _shm_handler_init;
            init->gc_handler = _shm_handler_gc;

            utarray_free(temp);
            
        } else {
            goto error;
        }

        utarray_free(array);
    }

    return NGX_CONF_OK;

unexpected_error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: unexpected error");
    return NGX_CONF_ERROR;

reused_tag:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: each tag of a zone can only be used once");
    return NGX_CONF_ERROR;

no_zone:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: zone name does not exists");
    return NGX_CONF_ERROR;

error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_block_page_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;

    ngx_str_t* _file = (ngx_str_t*)cf->args->elts + 1;

    char* file = ngx_http_waf_c_str(_file, cf->pool);

    if (_strcaseeq(file, "default")) {
        ngx_str_set(&loc_conf->waf_block_page, ngx_http_waf_data_html_block);
    } 

#ifndef NGX_HTTP_WAF_NO_EASTER_EGG
    else if (_strcaseeq(file, "SpongeBob")) {
        ngx_str_set(&loc_conf->waf_block_page, ngx_http_waf_data_html_sponge_bob);

    } 
#endif

    else {
        FILE* fp = fopen((char*)file, "r");

        if (fp == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOENT, 
                "ngx_waf: Unable to open file %s.", file);
            return NGX_CONF_ERROR;
        }

        fseek(fp, 0, SEEK_END);
        size_t file_size = ftell(fp);
        loc_conf->waf_block_page.len = file_size;
        loc_conf->waf_block_page.data = ngx_pcalloc(cf->pool, file_size + sizeof(u_char));

        fseek(fp, 0, SEEK_SET);
        if (fread(loc_conf->waf_block_page.data, sizeof(u_char), file_size, fp) != file_size) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EPERM, 
                "ngx_waf: Failed to read file %s completely..", file);
            return NGX_CONF_ERROR;
        }

        fclose(fp);
    }

    return NGX_CONF_OK;
}


char* ngx_http_waf_modsecurity_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
        ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    if (ngx_strncmp(p_str[1].data, "on", ngx_min(p_str[1].len, 2)) == 0) {
        loc_conf->waf_modsecurity = 1;

    } else if (ngx_strncmp(p_str[1].data, "off", ngx_min(p_str[1].len, 3)) == 0) {
        loc_conf->waf_modsecurity = 0;

    } else {
        goto error;
    }

    if (loc_conf->waf_modsecurity == 0) {
        return NGX_CONF_OK;
    }

    loc_conf->modsecurity_instance = msc_init();
    if (loc_conf->modsecurity_instance == NULL) {
        return "msc_init() failed";
    }

    msc_set_log_cb(loc_conf->modsecurity_instance, ngx_http_waf_modsecurity_handler_log);

    loc_conf->modsecurity_rules = msc_create_rules_set();
    if (loc_conf->modsecurity_rules == NULL) {
        return "msc_create_rules_set() failed";
    }

    for (size_t i = 2; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_http_waf_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (_streq(p->data, "file")) {    
            p = (ngx_str_t*)utarray_next(array, p);

            char* file = ngx_http_waf_c_str(p, cf->pool);
            const char* error;
            if (file == NULL) {
                goto no_memory;
            }
#if !(NGX_PCRE2)
            ngx_pool_t* old_pool = _change_modsecurity_pcre_callback(cf->pool);
#endif
            int rc = msc_rules_add_file(loc_conf->modsecurity_rules, file, &error);
            if (rc < 0) {
#if !(NGX_PCRE2)
                _recover_modsecurity_pcre_callback(old_pool);
#endif
                ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
                    "ngx_waf: %s", error);
                return NGX_CONF_ERROR;
            }
#if !(NGX_PCRE2)
            _recover_modsecurity_pcre_callback(old_pool);
#endif
            ngx_pfree(cf->pool, file);                                         
                                       
        } else if (_streq(p->data, "remote_key")) {
            p = (ngx_str_t*)utarray_next(array, p);

            loc_conf->waf_modsecurity_rules_remote_key.data = (u_char*)ngx_http_waf_c_str(p, cf->pool);
            loc_conf->waf_modsecurity_rules_remote_key.len = p->len;
            if (loc_conf->waf_modsecurity_rules_remote_key.data == NULL) {
                goto no_memory;
            }

        } else if (_streq(p->data, "remote_url")) {
            p = (ngx_str_t*)utarray_next(array, p);

            loc_conf->waf_modsecurity_rules_remote_url.data = (u_char*)ngx_http_waf_c_str(p, cf->pool);
            loc_conf->waf_modsecurity_rules_remote_url.len = p->len;
            if (loc_conf->waf_modsecurity_rules_remote_url.data == NULL) {
                goto no_memory;
            }

        } else {
            goto error;
        }

        utarray_free(array);
    }


    if (loc_conf->waf_modsecurity_rules_remote_key.data != NULL
     && loc_conf->waf_modsecurity_rules_remote_key.len != 0
     && loc_conf->waf_modsecurity_rules_remote_url.data != NULL
     && loc_conf->waf_modsecurity_rules_remote_url.len != 0) {
        const char* error;
#if !(NGX_PCRE2)
        ngx_pool_t* old_pool = _change_modsecurity_pcre_callback(cf->pool);
#endif
        if (msc_rules_add_remote(loc_conf->modsecurity_rules, 
            (char*)loc_conf->waf_modsecurity_rules_remote_key.data,
            (char*)loc_conf->waf_modsecurity_rules_remote_url.data, &error) < 0) {
#if !(NGX_PCRE2)
            _recover_modsecurity_pcre_callback(old_pool);
#endif
            ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
                "ngx_waf: %s", error);
            return NGX_CONF_ERROR;
        }
#if !(NGX_PCRE2)
        _recover_modsecurity_pcre_callback(old_pool);
#endif
    }

    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        goto no_memory;
    }
    cln->handler = _cleanup;
    cln->data = loc_conf;


    return NGX_CONF_OK;

no_memory:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: no memory");
    return NGX_CONF_ERROR;

error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_modsecurity_transaction_id_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_complex_value_t complex_value;
    ngx_http_compile_complex_value_t compile_complex_value;
    ngx_http_waf_loc_conf_t* loc_conf = conf;

    ngx_memzero(&compile_complex_value, sizeof(ngx_http_compile_complex_value_t));

    ngx_str_t* value = cf->args->elts;
    compile_complex_value.cf = cf;
    compile_complex_value.value = &value[1];
    compile_complex_value.complex_value = &complex_value;
    compile_complex_value.zero = 1;

    if (ngx_http_compile_complex_value(&compile_complex_value) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    loc_conf->waf_modsecurity_transaction_id = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (loc_conf->waf_modsecurity_transaction_id == NULL) {
        return NGX_CONF_ERROR;
    }

    *loc_conf->waf_modsecurity_transaction_id = complex_value;

    return NGX_CONF_OK;

}


void* ngx_http_waf_create_main_conf(ngx_conf_t* cf) {
    ngx_http_waf_main_conf_t* main_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_main_conf_t));

    if (main_conf == NULL) {
        return NULL;
    }

    main_conf->shms = ngx_array_create(cf->pool, 5, sizeof(shm_t));
    main_conf->local_caches = ngx_array_create(cf->pool, 20, sizeof(lru_cache_t*));

    if (main_conf->shms == NULL || main_conf->local_caches == NULL) {
        return NULL;
    }

    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(cf->pool, 0);
    cln->data = main_conf->local_caches;
    cln->handler = _cleanup_lru_cache;

    return main_conf;
}


void* ngx_http_waf_create_loc_conf(ngx_conf_t* cf) {
        static u_char s_rand_str[129] = { 0 };
#if (NGX_THREADS) && (NGX_HTTP_WAF_ASYNC_MODSECURITY)
    static ngx_str_t s_thread_pool_name;
    static ngx_thread_pool_t * s_thread_pool = NULL;
#endif
    if (s_rand_str[0] == '\0') {
        ngx_http_waf_rand_str(s_rand_str, 128);
    }

#if (NGX_THREADS) && (NGX_HTTP_WAF_ASYNC_MODSECURITY)
    ngx_str_set(&s_thread_pool_name, "ngx_waf");
    s_thread_pool = ngx_thread_pool_get(cf->cycle, &s_thread_pool_name);
    if (s_thread_pool == NULL) {
        s_thread_pool = ngx_thread_pool_add(cf, &s_thread_pool_name);
        if (s_thread_pool == NULL) {
            return NULL;
        }
    }
#endif

    ngx_http_waf_loc_conf_t* conf = NULL;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    ngx_strcpy(conf->random_str, s_rand_str);
    conf->is_alloc = NGX_HTTP_WAF_FALSE;

    conf->waf = NGX_CONF_UNSET;

    conf->waf_rule_path.len = NGX_CONF_UNSET_SIZE;

    conf->waf_mode = 0;

    conf->waf_verify_bot = NGX_CONF_UNSET;
    conf->waf_verify_bot_type = BOT_TYPE_UNSET;
    conf->waf_verify_bot_google_ua_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_bing_ua_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_baidu_ua_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_yandex_ua_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_sogou_ua_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_google_domain_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_bing_domain_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_baidu_domain_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_yandex_domain_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_sogou_domain_regexp = NGX_CONF_UNSET_PTR;

    conf->waf_under_attack = NGX_CONF_UNSET;
    ngx_str_null(&conf->waf_under_attack_html);

    conf->waf_captcha = NGX_CONF_UNSET;
    ngx_str_null(&conf->waf_captcha_html);
    conf->waf_captcha_type = NGX_CONF_UNSET;
    conf->waf_captcha_expire = NGX_CONF_UNSET;
    conf->waf_captcha_reCAPTCHAv3_score = NGX_CONF_UNSET;
    conf->waf_captcha_shm_zone = NGX_CONF_UNSET_PTR;
    conf->waf_captcha_max_fails = NGX_CONF_UNSET;
    conf->waf_captcha_duration = NGX_CONF_UNSET;

    conf->waf_cc_deny = NGX_CONF_UNSET;
    conf->waf_cc_deny_limit = NGX_CONF_UNSET;
    conf->waf_cc_deny_duration = NGX_CONF_UNSET;
    conf->waf_cc_deny_cycle = NGX_CONF_UNSET;
    conf->shm_zone_cc_deny = NGX_CONF_UNSET_PTR;
    conf->ip_access_statistics = NGX_CONF_UNSET_PTR;

    conf->waf_cache = NGX_CONF_UNSET;
    conf->waf_cache_capacity = NGX_CONF_UNSET;

    conf->waf_modsecurity = NGX_CONF_UNSET;
    conf->waf_modsecurity_transaction_id = NGX_CONF_UNSET_PTR;
    conf->modsecurity_instance = NGX_CONF_UNSET_PTR;
    conf->modsecurity_rules = NGX_CONF_UNSET_PTR;

    ngx_str_null(&conf->waf_block_page);

    conf->action_chain_blacklist = NGX_CONF_UNSET_PTR;
    conf->action_chain_cc_deny = NGX_CONF_UNSET_PTR;
    conf->action_chain_modsecurity = NGX_CONF_UNSET_PTR;
    conf->action_chain_verify_bot = NGX_CONF_UNSET_PTR;
    conf->action_zone_captcha = NGX_CONF_UNSET_PTR;
    conf->action_cache_captcha = NGX_CONF_UNSET_PTR;

    ngx_str_null(&conf->waf_modsecurity_rules_file);
    ngx_str_null(&conf->waf_modsecurity_rules_remote_key);
    ngx_str_null(&conf->waf_modsecurity_rules_remote_url);
    conf->ip_access_statistics = NULL;
#if (NGX_THREADS) && (NGX_HTTP_WAF_ASYNC_MODSECURITY)
    conf->thread_pool = s_thread_pool;
#endif
    conf->is_custom_priority = NGX_HTTP_WAF_FALSE;

    conf->black_url = NGX_CONF_UNSET_PTR;
    conf->black_args = NGX_CONF_UNSET_PTR;
    conf->black_ua = NGX_CONF_UNSET_PTR;
    conf->black_referer = NGX_CONF_UNSET_PTR;
    conf->black_cookie = NGX_CONF_UNSET_PTR;
    conf->black_post = NGX_CONF_UNSET_PTR;
    conf->white_url = NGX_CONF_UNSET_PTR;
    conf->white_referer = NGX_CONF_UNSET_PTR;
    conf->white_ipv4 = NGX_CONF_UNSET_PTR;
    conf->black_ipv4 = NGX_CONF_UNSET_PTR;
#if (NGX_HAVE_INET6)
    conf->white_ipv6 = NGX_CONF_UNSET_PTR;
    conf->black_ipv6 = NGX_CONF_UNSET_PTR;
#endif

    conf->black_url_inspection_cache = NGX_CONF_UNSET_PTR;
    conf->black_args_inspection_cache = NGX_CONF_UNSET_PTR;
    conf->black_cookie_inspection_cache = NGX_CONF_UNSET_PTR;
    conf->black_referer_inspection_cache = NGX_CONF_UNSET_PTR;
    conf->black_ua_inspection_cache = NGX_CONF_UNSET_PTR;
    conf->white_url_inspection_cache = NGX_CONF_UNSET_PTR;
    conf->white_referer_inspection_cache = NGX_CONF_UNSET_PTR;


    conf->check_proc[0] = ngx_http_waf_perform_action_at_access_start;
    conf->check_proc[1] = ngx_http_waf_handler_check_white_ip;
    conf->check_proc[2] = ngx_http_waf_handler_check_black_ip;
    conf->check_proc[3] = ngx_http_waf_handler_verify_bot;
    conf->check_proc[4] = ngx_http_waf_handler_check_cc;
    conf->check_proc[5] = ngx_http_waf_handler_captcha;
    conf->check_proc[6] = ngx_http_waf_handler_under_attack;
    conf->check_proc[7] = ngx_http_waf_handler_check_white_url;
    conf->check_proc[8] = ngx_http_waf_handler_check_black_url;
    conf->check_proc[9] = ngx_http_waf_handler_check_black_args;
    conf->check_proc[10] = ngx_http_waf_handler_check_black_user_agent;
    conf->check_proc[11] = ngx_http_waf_handler_check_white_referer;
    conf->check_proc[12] = ngx_http_waf_handler_check_black_referer;
    conf->check_proc[13] = ngx_http_waf_handler_check_black_cookie;
    conf->check_proc[14] = ngx_http_waf_handler_check_black_post;
    conf->check_proc[15] = ngx_http_waf_handler_modsecurity;

    return conf;
}


char* ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf) {
    ngx_http_waf_loc_conf_t* parent = prev;
    ngx_http_waf_loc_conf_t* child = conf;

    if (parent == NULL || child == NULL) {
        return NGX_CONF_OK;
    }

    child->parent = parent;

    ngx_conf_merge_value(child->waf, parent->waf, NGX_CONF_UNSET);

    ngx_conf_merge_ptr_value(child->white_ipv4, parent->white_ipv4, NULL);
    ngx_conf_merge_ptr_value(child->black_ipv4, parent->black_ipv4, NULL);
#if (NGX_HAVE_INET6)
    ngx_conf_merge_ptr_value(child->white_ipv6, parent->white_ipv6, NULL);
    ngx_conf_merge_ptr_value(child->black_ipv6, parent->black_ipv6, NULL);
#endif
    ngx_conf_merge_ptr_value(child->white_url, parent->white_url, NULL);
    ngx_conf_merge_ptr_value(child->white_referer, parent->white_referer, NULL);
    ngx_conf_merge_ptr_value(child->black_url, parent->black_url, NULL);
    ngx_conf_merge_ptr_value(child->black_args, parent->black_args, NULL);
    ngx_conf_merge_ptr_value(child->black_ua, parent->black_ua, NULL);
    ngx_conf_merge_ptr_value(child->black_post, parent->black_post, NULL);
    ngx_conf_merge_ptr_value(child->black_cookie, parent->black_cookie, NULL);
    ngx_conf_merge_ptr_value(child->black_referer, parent->black_referer, NULL);


    ngx_conf_merge_value(child->waf_cc_deny, parent->waf_cc_deny, NGX_CONF_UNSET);
    ngx_conf_merge_value(child->waf_cc_deny_limit, parent->waf_cc_deny_limit, NGX_CONF_UNSET);
    ngx_conf_merge_value(child->waf_cc_deny_cycle, parent->waf_cc_deny_cycle, NGX_CONF_UNSET);
    ngx_conf_merge_value(child->waf_cc_deny_duration, parent->waf_cc_deny_duration, NGX_CONF_UNSET);
    ngx_conf_merge_ptr_value(child->shm_zone_cc_deny, parent->shm_zone_cc_deny, NULL);
    

    ngx_conf_merge_value(child->waf_under_attack, parent->waf_under_attack, NGX_CONF_UNSET);

    if (child->waf_under_attack_html.data == NULL || child->waf_under_attack_html.len == 0) {
        ngx_memcpy(&(child->waf_under_attack_html), &(parent->waf_under_attack_html), sizeof(ngx_str_t));
    }
    
    ngx_conf_merge_value(child->waf_captcha, parent->waf_captcha, NGX_CONF_UNSET);
    ngx_conf_merge_value(child->waf_captcha_type, parent->waf_captcha_type, 0);
    ngx_conf_merge_value(child->waf_captcha_expire, parent->waf_captcha_expire, 60 * 30);
    ngx_conf_merge_value(child->waf_captcha_reCAPTCHAv3_score, parent->waf_captcha_reCAPTCHAv3_score, NGX_CONF_UNSET);
    ngx_conf_merge_value(child->waf_captcha_max_fails, parent->waf_captcha_max_fails, NGX_CONF_UNSET);
    ngx_conf_merge_value(child->waf_captcha_duration, parent->waf_captcha_duration, NGX_CONF_UNSET);
    ngx_conf_merge_ptr_value(child->waf_captcha_shm_zone, parent->waf_captcha_shm_zone, NULL);

    if (child->waf_captcha_html.data == NULL || child->waf_captcha_html.len == 0) {
        ngx_memcpy(&(child->waf_captcha_html), &(parent->waf_captcha_html), sizeof(ngx_str_t));
    }

    if (child->waf_captcha_hCaptcha_secret.data == NULL || child->waf_captcha_hCaptcha_secret.len == 0) {
        ngx_memcpy(&(child->waf_captcha_hCaptcha_secret), &(parent->waf_captcha_hCaptcha_secret), sizeof(ngx_str_t));
    }

    if (child->waf_captcha_reCAPTCHAv2_secret.data == NULL || child->waf_captcha_reCAPTCHAv2_secret.len == 0) {
        ngx_memcpy(&(child->waf_captcha_reCAPTCHAv2_secret), &(parent->waf_captcha_reCAPTCHAv2_secret), sizeof(ngx_str_t));
    }

    if (child->waf_captcha_reCAPTCHAv3_secret.data == NULL || child->waf_captcha_reCAPTCHAv3_secret.len == 0) {
        ngx_memcpy(&(child->waf_captcha_reCAPTCHAv3_secret), &(parent->waf_captcha_reCAPTCHAv3_secret), sizeof(ngx_str_t));
    }

    if (child->waf_captcha_api.data == NULL || child->waf_captcha_api.len == 0) {
        ngx_memcpy(&(child->waf_captcha_api), &(parent->waf_captcha_api), sizeof(ngx_str_t));
    }

    if (child->waf_captcha_verify_url.data == NULL || child->waf_captcha_verify_url.len == 0) {
        ngx_memcpy(&(child->waf_captcha_verify_url), &(parent->waf_captcha_verify_url), sizeof(ngx_str_t));
    }

    ngx_conf_merge_value(child->waf_verify_bot, parent->waf_verify_bot, NGX_CONF_UNSET);
    
    if (child->waf_verify_bot_type == BOT_TYPE_UNSET) {
        child->waf_verify_bot_type = parent->waf_verify_bot_type;
    }

    ngx_conf_merge_ptr_value(child->waf_verify_bot_google_ua_regexp, parent->waf_verify_bot_google_ua_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_bing_ua_regexp, parent->waf_verify_bot_bing_ua_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_baidu_ua_regexp, parent->waf_verify_bot_baidu_ua_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_yandex_ua_regexp, parent->waf_verify_bot_yandex_ua_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_sogou_ua_regexp, parent->waf_verify_bot_sogou_ua_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_google_domain_regexp, parent->waf_verify_bot_google_domain_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_bing_domain_regexp, parent->waf_verify_bot_bing_domain_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_baidu_domain_regexp, parent->waf_verify_bot_baidu_domain_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_yandex_domain_regexp, parent->waf_verify_bot_yandex_domain_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_sogou_domain_regexp, parent->waf_verify_bot_sogou_domain_regexp, NULL);


    if (child->waf_mode == 0) {
        child->waf_mode = parent->waf_mode;
    }
    
    ngx_conf_merge_value(child->waf_cache, parent->waf_cache, NGX_CONF_UNSET);
    ngx_conf_merge_value(child->waf_cache_capacity, parent->waf_cache_capacity, NGX_CONF_UNSET);
    ngx_conf_merge_ptr_value(child->black_url_inspection_cache, parent->black_url_inspection_cache, NULL);
    ngx_conf_merge_ptr_value(child->black_args_inspection_cache, parent->black_args_inspection_cache, NULL);
    ngx_conf_merge_ptr_value(child->black_ua_inspection_cache, parent->black_ua_inspection_cache, NULL);
    ngx_conf_merge_ptr_value(child->black_referer_inspection_cache, parent->black_referer_inspection_cache, NULL);
    ngx_conf_merge_ptr_value(child->black_cookie_inspection_cache, parent->black_cookie_inspection_cache, NULL);
    ngx_conf_merge_ptr_value(child->white_url_inspection_cache, parent->white_url_inspection_cache, NULL);
    ngx_conf_merge_ptr_value(child->white_referer_inspection_cache, parent->white_referer_inspection_cache, NULL);


    ngx_conf_merge_value(child->waf_modsecurity, parent->waf_modsecurity, NGX_CONF_UNSET);
    ngx_conf_merge_ptr_value(child->modsecurity_instance, parent->modsecurity_instance, NULL);
    ngx_conf_merge_ptr_value(child->modsecurity_rules, parent->modsecurity_rules, NULL);
    ngx_conf_merge_ptr_value(child->waf_modsecurity_transaction_id, parent->waf_modsecurity_transaction_id, NULL);
    
    if (child->waf_modsecurity_rules_file.data == NULL || child->waf_modsecurity_rules_file.len == 0) {
        ngx_memcpy(&(child->waf_modsecurity_rules_file), &(parent->waf_modsecurity_rules_file), sizeof(ngx_str_t));
    }

    if (child->waf_modsecurity_rules_remote_key.data == NULL || child->waf_modsecurity_rules_remote_key.len == 0) {
        ngx_memcpy(&(child->waf_modsecurity_rules_remote_key), &(parent->waf_modsecurity_rules_remote_key), sizeof(ngx_str_t));
    }

    if (child->waf_modsecurity_rules_remote_url.data == NULL || child->waf_modsecurity_rules_remote_url.len == 0) {
        ngx_memcpy(&(child->waf_modsecurity_rules_remote_url), &(parent->waf_modsecurity_rules_remote_url), sizeof(ngx_str_t));
    }


    if (parent->is_custom_priority == NGX_HTTP_WAF_TRUE
    &&  child->is_custom_priority == NGX_HTTP_WAF_FALSE) {
        ngx_memcpy(child->check_proc, parent->check_proc, sizeof(parent->check_proc));
    }

    ngx_conf_merge_ptr_value(child->action_zone_captcha, parent->action_zone_captcha, NULL);

    action_t* default_action = ngx_pcalloc(cf->pool, sizeof(action_t));

    if (!ngx_http_waf_is_valid_ptr_value(parent->action_chain_blacklist)) {
        parent->action_chain_blacklist = ngx_pcalloc(cf->pool, sizeof(action_t));
        ngx_http_waf_set_action_return(parent->action_chain_blacklist, NGX_HTTP_FORBIDDEN, ACTION_FLAG_FROM_BLACK_LIST);
    }

    if (!ngx_http_waf_is_valid_ptr_value(parent->action_chain_cc_deny)) {
        parent->action_chain_cc_deny = ngx_pcalloc(cf->pool, sizeof(action_t));
        ngx_http_waf_set_action_return(parent->action_chain_cc_deny, NGX_HTTP_SERVICE_UNAVAILABLE, ACTION_FLAG_FROM_CC_DENY);
    }

    if (!ngx_http_waf_is_valid_ptr_value(parent->action_chain_modsecurity)) {
        parent->action_chain_modsecurity = ngx_pcalloc(cf->pool, sizeof(action_t));
        ngx_http_waf_set_action_follow(parent->action_chain_modsecurity, ACTION_FLAG_FROM_MODSECURITY);
    }

    if (!ngx_http_waf_is_valid_ptr_value(parent->action_chain_verify_bot)) {
        parent->action_chain_verify_bot = ngx_pcalloc(cf->pool, sizeof(action_t));
        ngx_http_waf_set_action_return(parent->action_chain_verify_bot, NGX_HTTP_FORBIDDEN, ACTION_FLAG_FROM_VERIFY_BOT);
    }

    ngx_http_waf_set_action_return(default_action, NGX_HTTP_FORBIDDEN, ACTION_FLAG_FROM_BLACK_LIST);
    ngx_conf_merge_ptr_value(child->action_chain_blacklist, parent->action_chain_blacklist, default_action);

    ngx_http_waf_set_action_return(default_action, NGX_HTTP_SERVICE_UNAVAILABLE, ACTION_FLAG_FROM_CC_DENY);
    ngx_conf_merge_ptr_value(child->action_chain_cc_deny, parent->action_chain_cc_deny, default_action);

    ngx_http_waf_set_action_follow(default_action, ACTION_FLAG_FROM_MODSECURITY);
    ngx_conf_merge_ptr_value(child->action_chain_modsecurity, parent->action_chain_modsecurity, default_action);

    ngx_http_waf_set_action_return(default_action, NGX_HTTP_FORBIDDEN, ACTION_FLAG_FROM_VERIFY_BOT);
    ngx_conf_merge_ptr_value(child->action_chain_verify_bot, parent->action_chain_verify_bot, default_action);

    if (ngx_http_waf_check_flag(parent->action_chain_blacklist->flag, ACTION_FLAG_CAPTCHA)
        || ngx_http_waf_check_flag(parent->action_chain_cc_deny->flag, ACTION_FLAG_CAPTCHA)
        || ngx_http_waf_check_flag(parent->action_chain_modsecurity->flag, ACTION_FLAG_CAPTCHA)
        || ngx_http_waf_check_flag(parent->action_chain_verify_bot->flag, ACTION_FLAG_CAPTCHA)) {
        
        if (parent->waf_captcha_type == 0
            || ngx_is_null_str(&parent->waf_captcha_html)
            || ngx_is_null_str(&parent->waf_captcha_reCAPTCHAv2_secret)
            || ngx_is_null_str(&parent->waf_captcha_reCAPTCHAv3_secret)) {

            ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
                "ngx_waf: if you use the directive [waf_action xxx=CAPTCHA], "
                "you must set the parameters [prov], [sitekey] and [secret] of the directive [waf_captcha] "
                "in the current context or a higher context.\n"
                "e.g. [waf_captcha off prov=reCAPTCHAv3 secret=your_secret sitekey=you_site_key]");
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_http_waf_check_flag(child->action_chain_blacklist->flag, ACTION_FLAG_CAPTCHA)
        || ngx_http_waf_check_flag(child->action_chain_cc_deny->flag, ACTION_FLAG_CAPTCHA)
        || ngx_http_waf_check_flag(child->action_chain_modsecurity->flag, ACTION_FLAG_CAPTCHA)
        || ngx_http_waf_check_flag(child->action_chain_verify_bot->flag, ACTION_FLAG_CAPTCHA)) {
        
        if (child->waf_captcha_type == 0
            || ngx_is_null_str(&child->waf_captcha_html)
            || ngx_is_null_str(&child->waf_captcha_reCAPTCHAv2_secret)
            || ngx_is_null_str(&child->waf_captcha_reCAPTCHAv3_secret)) {

            ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
                "ngx_waf: if you use the directive [waf_action xxx=CAPTCHA], "
                "you must set the parameters [prov], [sitekey] and [secret] of the directive [waf_captcha] "
                "in the current context or a higher context.\n"
                "e.g. [waf_captcha off prov=reCAPTCHAv3 secret=your_secret sitekey=you_site_key]");
            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_merge_str_value(child->waf_block_page, parent->waf_block_page, "");

    if (!ngx_is_null_str(&parent->waf_block_page)) {
        if (ngx_http_waf_check_flag(parent->action_chain_blacklist->flag, ACTION_FLAG_RETURN)) {
            ngx_http_waf_make_action_chain_html(cf->pool, 
                parent->action_chain_blacklist,
                parent->action_chain_blacklist->extra.http_status,
                ACTION_FLAG_FROM_BLACK_LIST,
                &parent->waf_block_page);
        }

        if (ngx_http_waf_check_flag(parent->action_chain_cc_deny->flag, ACTION_FLAG_RETURN)) {
            ngx_http_waf_make_action_chain_html(cf->pool, 
                parent->action_chain_cc_deny,
                parent->action_chain_cc_deny->extra.http_status,
                ACTION_FLAG_FROM_CC_DENY,
                &parent->waf_block_page);
        }

        if (ngx_http_waf_check_flag(parent->action_chain_modsecurity->flag, ACTION_FLAG_RETURN)) {
            ngx_http_waf_make_action_chain_html(cf->pool, 
                parent->action_chain_modsecurity,
                parent->action_chain_modsecurity->extra.http_status,
                ACTION_FLAG_FROM_MODSECURITY,
                &parent->waf_block_page);
        }

        if (ngx_http_waf_check_flag(parent->action_chain_verify_bot->flag, ACTION_FLAG_RETURN)) {
            ngx_http_waf_make_action_chain_html(cf->pool, 
                parent->action_chain_verify_bot,
                parent->action_chain_verify_bot->extra.http_status,
                ACTION_FLAG_FROM_VERIFY_BOT,
                &parent->waf_block_page);
        }
    }

    if (!ngx_is_null_str(&child->waf_block_page)) {
        if (ngx_http_waf_check_flag(child->action_chain_blacklist->flag, ACTION_FLAG_RETURN)) {
            ngx_http_waf_make_action_chain_html(cf->pool, 
                child->action_chain_blacklist,
                child->action_chain_blacklist->extra.http_status,
                ACTION_FLAG_FROM_BLACK_LIST,
                &child->waf_block_page);
        }

        if (ngx_http_waf_check_flag(child->action_chain_cc_deny->flag, ACTION_FLAG_RETURN)) {
            ngx_http_waf_make_action_chain_html(cf->pool, 
                child->action_chain_cc_deny,
                child->action_chain_cc_deny->extra.http_status,
                ACTION_FLAG_FROM_CC_DENY,
                &child->waf_block_page);
        }

        if (ngx_http_waf_check_flag(child->action_chain_modsecurity->flag, ACTION_FLAG_RETURN)) {
            ngx_http_waf_make_action_chain_html(cf->pool, 
                child->action_chain_modsecurity,
                child->action_chain_modsecurity->extra.http_status,
                ACTION_FLAG_FROM_MODSECURITY,
                &child->waf_block_page);
        }

        if (ngx_http_waf_check_flag(child->action_chain_verify_bot->flag, ACTION_FLAG_RETURN)) {
            ngx_http_waf_make_action_chain_html(cf->pool, 
                child->action_chain_verify_bot,
                child->action_chain_verify_bot->extra.http_status,
                ACTION_FLAG_FROM_VERIFY_BOT,
                &child->waf_block_page);
        }
    }

    return NGX_CONF_OK;
}


ngx_int_t ngx_http_waf_preconfiguration(ngx_conf_t* cf) {
    ngx_http_waf_shm_clear_inner_data();
    return NGX_OK;
}


ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t* cf) {
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

    ngx_http_waf_header_filter_init();
    ngx_http_waf_body_filter_init();

    if (ngx_http_waf_install_add_var(cf) != NGX_HTTP_WAF_SUCCESS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
            "ngx_waf: failed to add embedded variables");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t _shm_handler_init(shm_t* shm, void* data, void* old_data) {
    lru_cache_t** cache = data;
    lru_cache_t** old_cache = old_data;

    if (old_cache != NULL) {
        *cache = *old_cache;

    } else {
        lru_cache_init(cache, SIZE_MAX, shm->pool);
    }

    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _shm_handler_gc(shm_t* shm, void* data, ngx_int_t* low_memory) {
    lru_cache_t** cache = data;

    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)shm->zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    if ((*cache)->no_memory) {
        (*cache)->no_memory = 0;
        *low_memory = NGX_HTTP_WAF_TRUE;
    }

    if (*low_memory == NGX_HTTP_WAF_TRUE) {
        lru_cache_eliminate(*cache, 5);
        
    } else {
        lru_cache_eliminate_expire(*cache, 5);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _load_into_container(ngx_conf_t* cf, const char* file_name, void* container, ngx_int_t mode) {
    FILE* fp = fopen(file_name, "r");
    ngx_int_t line_number = 0;
    ngx_str_t line;
    char* str = ngx_palloc(cf->pool, sizeof(char) * NGX_HTTP_WAF_RULE_MAX_LEN);
    if (fp == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (mode == 3) {

    } else {
        while (fgets(str, NGX_HTTP_WAF_RULE_MAX_LEN - 16, fp) != NULL) {
            ngx_regex_compile_t   regex_compile;
            u_char                errstr[NGX_MAX_CONF_ERRSTR];
            ngx_regex_elt_t* ngx_regex_elt;
            ipv4_t ipv4;
            inx_addr_t inx_addr;
#if (NGX_HAVE_INET6)
            ipv6_t ipv6;
#endif
            ip_trie_node_t* ip_trie_node = NULL;
            ++line_number;
            line.data = (u_char*)str;
            #ifdef __STDC_LIB_EXT1__
                line.len = strnlen_s((char*)str. sizeof(char) * NGX_HTTP_WAF_RULE_MAX_LEN);
            #else
            line.len = ngx_strlen(str);
            #endif

            memset(&ipv4, 0, sizeof(ipv4_t));
            memset(&inx_addr, 0, sizeof(inx_addr_t));
#if (NGX_HAVE_INET6)
            memset(&ipv6, 0, sizeof(ipv6_t));
#endif

            if (line.len <= 0) {
                continue;
            }

            if (line.data[line.len - 1] == '\n') {
                line.data[line.len - 1] = '\0';
                --(line.len);
                if (line.len <= 0) {
                    continue;
                }
                if (line.data[line.len - 1] == '\r') {
                    line.data[line.len - 1] = '\0';
                    --(line.len);
                }
            }

            if (line.len <= 0) {
                continue;
            }

            switch (mode) {
            case 0:
                ngx_memzero(&regex_compile, sizeof(ngx_regex_compile_t));
                regex_compile.pattern = line;
                regex_compile.pool = cf->pool;
                regex_compile.err.len = NGX_MAX_CONF_ERRSTR;
                regex_compile.err.data = errstr;
                if (ngx_regex_compile(&regex_compile) != NGX_OK) {
                    char temp[NGX_HTTP_WAF_RULE_MAX_LEN] = { 0 };
                    ngx_http_waf_to_c_str((u_char*)temp, line);
                    ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                        "ngx_waf: In %s:%d, [%s] is not a valid regex string.", file_name, line_number, temp);
                    return NGX_HTTP_WAF_FAIL;
                }
                ngx_regex_elt = ngx_array_push((ngx_array_t*)container);
                ngx_regex_elt->name = ngx_palloc(cf->pool, sizeof(u_char) * NGX_HTTP_WAF_RULE_MAX_LEN);
                ngx_http_waf_to_c_str(ngx_regex_elt->name, line);
                ngx_regex_elt->regex = regex_compile.regex;
                break;
            case 1:
                if (ngx_http_waf_parse_ipv4(line, &ipv4) != NGX_HTTP_WAF_SUCCESS) {
                    ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                        "ngx_waf: In %s:%d, [%s] is not a valid IPV4 string.", file_name, line_number, ipv4.text);
                    return NGX_HTTP_WAF_FAIL;
                }
                inx_addr.ipv4.s_addr = ipv4.prefix;
                if (ip_trie_add((ip_trie_t*)container, &inx_addr, ipv4.suffix_num, ipv4.text, 32) != NGX_HTTP_WAF_SUCCESS) {
                    if (ip_trie_find((ip_trie_t*)container, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
                        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                            "ngx_waf: In %s:%d, the two address blocks [%s] and [%s] have overlapping parts.", 
                            file_name, line_number, ipv4.text, ip_trie_node->data);
                    } else {
                        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                            "ngx_waf: In %s:%d, [%s] cannot be stored because the memory allocation failed.", 
                            file_name, line_number, ipv4.text);
                            return NGX_HTTP_WAF_FAIL;
                    }
                }
                break;
#if (NGX_HAVE_INET6)
            case 2:
                if (ngx_http_waf_parse_ipv6(line, &ipv6) != NGX_HTTP_WAF_SUCCESS) {
                    ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                        "ngx_waf: In %s:%d, [%s] is not a valid IPV6 string.", file_name, line_number, ipv6.text);
                    return NGX_HTTP_WAF_FAIL;
                }
                ngx_memcpy(inx_addr.ipv6.s6_addr, ipv6.prefix, 16);
                if (ip_trie_add((ip_trie_t*)container, &inx_addr, ipv6.suffix_num, ipv6.text, 64) != NGX_HTTP_WAF_SUCCESS) {
                    if (ip_trie_find((ip_trie_t*)container, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
                        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                            "ngx_waf: In %s:%d, the two address blocks [%s] and [%s] have overlapping parts.", 
                            file_name, line_number, ipv6.text, ip_trie_node->data);
                    } else {
                        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                            "ngx_waf: In %s:%d, [%s] cannot be stored because the memory allocation failed.", 
                            file_name, line_number, ipv6.text);
                            return NGX_HTTP_WAF_FAIL;
                    }
                }
                break;
#endif
            }
        }
    }

    
    fclose(fp);
    ngx_pfree(cf->pool, str);
    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _init_lru_cache(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf) {
    ngx_http_waf_main_conf_t* main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);

    conf->black_url_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));
    conf->black_args_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));
    conf->black_ua_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));
    conf->black_referer_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));
    conf->black_cookie_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));
    conf->white_url_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));
    conf->white_referer_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));

    mem_pool_t* pool = calloc(1, sizeof(mem_pool_t));
    mem_pool_init(pool, MEM_POOL_FLAG_STDC, NULL);

    lru_cache_init(&conf->black_url_inspection_cache, 
                    conf->waf_cache_capacity, pool);

    lru_cache_t** p = ngx_array_push(main_conf->local_caches);
    *p = conf->black_url_inspection_cache;

    lru_cache_init(&conf->black_args_inspection_cache, 
                    conf->waf_cache_capacity, pool);
    
    p = ngx_array_push(main_conf->local_caches);
    *p = conf->black_args_inspection_cache;

    lru_cache_init(&conf->black_ua_inspection_cache, 
                    conf->waf_cache_capacity, pool);

    p = ngx_array_push(main_conf->local_caches);
    *p = conf->black_ua_inspection_cache;

    lru_cache_init(&conf->black_referer_inspection_cache, 
                    conf->waf_cache_capacity, pool);

    p = ngx_array_push(main_conf->local_caches);
    *p = conf->black_referer_inspection_cache;

    lru_cache_init(&conf->black_cookie_inspection_cache, 
                    conf->waf_cache_capacity, pool);

    p = ngx_array_push(main_conf->local_caches);
    *p = conf->black_cookie_inspection_cache;

    lru_cache_init(&conf->white_url_inspection_cache, 
                    conf->waf_cache_capacity, pool);

    p = ngx_array_push(main_conf->local_caches);
    *p = conf->white_url_inspection_cache;
    
    lru_cache_init(&conf->white_referer_inspection_cache, 
                    conf->waf_cache_capacity, pool);

    p = ngx_array_push(main_conf->local_caches);
    *p = conf->white_referer_inspection_cache;

    return NGX_HTTP_WAF_SUCCESS;
}


static void _cleanup_lru_cache(void* data) {
    ngx_array_t* caches = (ngx_array_t*)data;

    for (ngx_uint_t i = 0; i < caches->nelts; i++) {
        lru_cache_t* cache = ((lru_cache_t**)caches->elts)[i];
        lru_cache_destroy(cache);
    }
}


static ngx_int_t _load_all_rule(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf) {
    char* full_path = ngx_palloc(cf->pool, sizeof(char) * NGX_HTTP_WAF_RULE_MAX_LEN);
    char* end = ngx_http_waf_to_c_str((u_char*)full_path, conf->waf_rule_path);

#define ngx_http_waf_check_and_load_conf(cf, folder, end, filename, container, mode) {                          \
    strcat((folder), (filename));                                                                               \
    if (access((folder), R_OK) != 0) {                                                                          \
        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, "ngx_waf: %s: %s", (folder), "No such file or directory");     \
        return NGX_HTTP_WAF_FAIL;                                                                               \
    }                                                                                                           \
    if (_load_into_container((cf), (folder), (container), (mode)) == NGX_HTTP_WAF_FAIL) {                       \
        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, "ngx_waf: %s: %s", (folder), "Cannot read configuration.");    \
        return NGX_HTTP_WAF_FAIL;                                                                               \
    }                                                                                                           \
    *(end) = '\0';                                                                                              \
}

    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_IPV4_FILE, conf->black_ipv4, 1);
#if (NGX_HAVE_INET6)
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_IPV6_FILE, conf->black_ipv6, 2);
#endif
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_URL_FILE, conf->black_url, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_ARGS_FILE, conf->black_args, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_UA_FILE, conf->black_ua, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_REFERER_FILE, conf->black_referer, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_COOKIE_FILE, conf->black_cookie, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_POST_FILE, conf->black_post, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_WHITE_IPV4_FILE, conf->white_ipv4, 1);
#if (NGX_HAVE_INET6)
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_WHITE_IPV6_FILE, conf->white_ipv6, 2);
#endif
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_WHITE_URL_FILE, conf->white_url, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_WHITE_REFERER_FILE, conf->white_referer, 0);
    
#undef ngx_http_waf_check_and_load_conf

    ngx_pfree(cf->pool, full_path);

    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _init_rule_containers(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf) {
    if (conf->is_alloc == NGX_HTTP_WAF_SUCCESS) {
        return NGX_HTTP_WAF_SUCCESS;
    }

    conf->black_url = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->black_args = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->black_ua = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->black_referer = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->black_cookie = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->black_post = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->white_url = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->white_referer = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->white_ipv4 = ngx_pcalloc(cf->pool, sizeof(ip_trie_t));
    conf->black_ipv4 = ngx_pcalloc(cf->pool, sizeof(ip_trie_t));
#if (NGX_HAVE_INET6)
    conf->white_ipv6 = ngx_pcalloc(cf->pool, sizeof(ip_trie_t));
    conf->black_ipv6 = ngx_pcalloc(cf->pool, sizeof(ip_trie_t));
#endif

    if (conf->black_url == NULL
    ||  conf->black_args == NULL
    ||  conf->black_ua == NULL
    ||  conf->black_referer == NULL
    ||  conf->black_cookie == NULL
    ||  conf->black_post == NULL
    ||  conf->white_url == NULL
    ||  conf->white_referer == NULL
    ||  conf->white_ipv4 == NULL
    ||  conf->black_ipv4 == NULL
#if (NGX_HAVE_INET6)
    ||  conf->white_ipv6 == NULL
    ||  conf->black_ipv6 == NULL
#endif
        ) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NGX_HTTP_WAF_FAIL;
    }

    mem_pool_t* pool = ngx_pcalloc(cf->pool, sizeof(mem_pool_t));

    if (pool == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    mem_pool_init(pool, MEM_POOL_FLAG_NGX, cf->pool);


    if (ip_trie_init(conf->white_ipv4, pool, AF_INET) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NGX_HTTP_WAF_FAIL;
    }

    if (ip_trie_init(conf->black_ipv4, pool, AF_INET) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NGX_HTTP_WAF_FAIL;
    }

#if (NGX_HAVE_INET6)
    if (ip_trie_init(conf->white_ipv6, pool, AF_INET6) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NGX_HTTP_WAF_FAIL;
    }

    if (ip_trie_init(conf->black_ipv6, pool, AF_INET6) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NGX_HTTP_WAF_FAIL;
    }
#endif

    conf->is_alloc = NGX_HTTP_WAF_TRUE;

    return NGX_HTTP_WAF_SUCCESS;
}


// static ngx_int_t _free_rule_containers(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf) {
//     if (conf->is_alloc == NGX_HTTP_WAF_TRUE) {
//         ngx_pfree(cf->pool, conf->black_url);
//         ngx_pfree(cf->pool, conf->black_args);
//         ngx_pfree(cf->pool, conf->black_ua);
//         ngx_pfree(cf->pool, conf->black_referer);
//         ngx_pfree(cf->pool, conf->black_cookie);
//         ngx_pfree(cf->pool, conf->black_post);
//         ngx_pfree(cf->pool, conf->white_url);
//         ngx_pfree(cf->pool, conf->white_referer);
//         ngx_pfree(cf->pool, conf->white_ipv4);
//         ngx_pfree(cf->pool, conf->black_ipv4);
// #if (NGX_HAVE_INET6)
//         ngx_pfree(cf->pool, conf->white_ipv6);
//         ngx_pfree(cf->pool, conf->black_ipv6);
// #endif

//         conf->black_url = NGX_CONF_UNSET_PTR;
//         conf->black_args = NGX_CONF_UNSET_PTR;
//         conf->black_ua = NGX_CONF_UNSET_PTR;
//         conf->black_referer = NGX_CONF_UNSET_PTR;
//         conf->black_cookie = NGX_CONF_UNSET_PTR;
//         conf->black_post = NGX_CONF_UNSET_PTR;
//         conf->white_url = NGX_CONF_UNSET_PTR;
//         conf->white_referer = NGX_CONF_UNSET_PTR;
//         conf->white_ipv4 = NGX_CONF_UNSET_PTR;
//         conf->black_ipv4 = NGX_CONF_UNSET_PTR;
// #if (NGX_HAVE_INET6)
//         conf->white_ipv6 = NGX_CONF_UNSET_PTR;
//         conf->black_ipv6 = NGX_CONF_UNSET_PTR;
// #endif

//         conf->is_alloc = NGX_HTTP_WAF_FALSE;
//     }

//     return NGX_HTTP_WAF_SUCCESS;
// }


static void _cleanup(void* data) {
    ngx_http_waf_loc_conf_t* loc_conf = data;
    msc_rules_cleanup(loc_conf->modsecurity_rules);
    msc_cleanup(loc_conf->modsecurity_instance);
}


#if !(NGX_PCRE2)
static ngx_pool_t* _change_modsecurity_pcre_callback(ngx_pool_t* pool) {
    ngx_pool_t* old_pool = NULL;

    if (pcre_malloc != _modsecurity_pcre_malloc) {
        _modsecurity_pcre_pool = pool;

        _old_modsecurity_pcre_malloc = pcre_malloc;
        _old_modsecurity_pcre_free = pcre_free;

        pcre_malloc = _modsecurity_pcre_malloc;
        pcre_free = _modsecurity_pcre_free;

        return NULL;
    }

    old_pool = _modsecurity_pcre_pool;
    _modsecurity_pcre_pool = pool;

    return old_pool;
}


static void _recover_modsecurity_pcre_callback(ngx_pool_t* old_pool) {
    _modsecurity_pcre_pool = old_pool;

    if (old_pool == NULL) {
        pcre_malloc = _old_modsecurity_pcre_malloc;
        pcre_free = _old_modsecurity_pcre_free;
    }
}


static void* _modsecurity_pcre_malloc(size_t size) {
    return ngx_palloc(_modsecurity_pcre_pool, size);
}


static void _modsecurity_pcre_free(void* ptr) {
    ngx_pfree(_modsecurity_pcre_pool, ptr);
}
#endif



#undef _streq

#undef _strneq

#undef _strcaseeq

#undef _strncaseeq