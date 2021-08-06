#include <ngx_http_waf_module_vm.h>

ngx_int_t ngx_http_waf_vm_exec(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    static ngx_str_t s_empty_str = ngx_string("");
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_ctx_t* ctx = NULL; 
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);
    
    ngx_int_t ret = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_check_flag(loc_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_ADV | r->method) == NGX_HTTP_WAF_FALSE) {
        return ret;
    }

    if (utarray_len(loc_conf->advanced_rule) == 0) {
        return ret;
    }

    // ipv4_t client_ipv4;

    ngx_str_t* url = &(r->uri);
    if (url->len == 0 || url->data == NULL) {
        url = &s_empty_str;
    }

    ngx_str_t* user_agent = &s_empty_str;
    if (r->headers_in.user_agent != NULL && r->headers_in.user_agent->value.len != 0 && r->headers_in.user_agent->value.data != NULL) {
        user_agent = &(r->headers_in.user_agent->value);
    }

    ngx_str_t* referer = &s_empty_str;
    if (r->headers_in.referer != NULL && r->headers_in.referer->value.len != 0 && r->headers_in.referer->value.data != NULL) {
        referer = &(r->headers_in.referer->value);
    }

    key_value_t* query_string = NULL;
    ngx_http_waf_parse_query_string(&(r->args), &query_string);

    key_value_t* header_in = NULL;
    ngx_http_waf_parse_header(&(r->headers_in.headers), &header_in);

    

    vm_stack_arg_t* stack = NULL;
    vm_code_t* code = NULL;

    while (code = (vm_code_t*)utarray_next(loc_conf->advanced_rule, code), code != NULL) {
        vm_stack_arg_t* argv = &(code->argv);
        switch (code->type) {
            case VM_CODE_PUSH_INT:
                break;
            
            case VM_CODE_PUSH_STR:
            {
                vm_stack_arg_t* temp = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                temp->type[0] = VM_DATA_STR;
                temp->argc = 1;
                temp->value[0].str_val.data = ngx_pcalloc(r->pool, sizeof(u_char) * (argv->value[0].str_val.len + 1));
                temp->value[0].str_val.len = argv->value[0].str_val.len;
                ngx_memcpy(temp->value[0].str_val.data, argv->value[0].str_val.data, sizeof(u_char) * argv->value[0].str_val.len);
                STACK_PUSH2(stack, temp, utstack_handle);
                break;
            }

            case VM_CODE_PUSH_CLIENT_IP:
            {
                vm_stack_arg_t* temp = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));

                if (r->connection->sockaddr->sa_family == AF_INET) {
                    struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
                    temp->type[0] = VM_DATA_IPV4;
                    ngx_memcpy(&(temp->value[0].inx_addr_val.ipv4), &(sin->sin_addr), sizeof(struct in_addr));
                } 
#if (NGX_HAVE_INET6)
                else if (r->connection->sockaddr->sa_family == AF_INET6) {
                    struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
                    temp->type[0] = VM_DATA_IPV6;
                    ngx_memcpy(&(temp->value[0].inx_addr_val.ipv6), &(sin6->sin6_addr), sizeof(struct in_addr));
                }
#endif
                temp->argc = 1;
                STACK_PUSH2(stack, temp, utstack_handle);
                break;
            }

            case VM_CODE_PUSH_URL:
            {
                vm_stack_arg_t* temp = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                temp->type[0] = VM_DATA_STR;
                temp->argc = 1;
                temp->value[0].str_val.data = ngx_pcalloc(r->pool, sizeof(u_char) * (url->len + 1));
                temp->value[0].str_val.len = url->len;
                ngx_memcpy(temp->value[0].str_val.data, url->data, sizeof(u_char) * url->len);
                STACK_PUSH2(stack, temp, utstack_handle);
                break;
            }

            case VM_CODE_PUSH_USER_AGENT:
            {
                vm_stack_arg_t* temp = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                temp->type[0] = VM_DATA_STR;
                temp->argc = 1;
                temp->value[0].str_val.data = ngx_pcalloc(r->pool, sizeof(u_char) * (user_agent->len + 1));
                temp->value[0].str_val.len = user_agent->len;
                ngx_memcpy(temp->value[0].str_val.data, user_agent->data, sizeof(u_char) * user_agent->len);
                STACK_PUSH2(stack, temp, utstack_handle);
                break;
            }

            case VM_CODE_PUSH_REFERER:
            {
                vm_stack_arg_t* temp = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                temp->type[0] = VM_DATA_STR;
                temp->argc = 1;
                temp->value[0].str_val.data = ngx_pcalloc(r->pool, sizeof(u_char) * (referer->len + 1));
                temp->value[0].str_val.len = referer->len;
                ngx_memcpy(temp->value[0].str_val.data, referer->data, sizeof(u_char) * referer->len);
                STACK_PUSH2(stack, temp, utstack_handle);
                break;
            }

            case VM_CODE_PUSH_QUERY_STRING:
            {
                vm_stack_arg_t* result = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                result->type[0] = VM_DATA_STR;
                result->argc = 1;
                key_value_t* temp = NULL;
                HASH_FIND(hh, query_string, argv->value[0].str_val.data, argv->value[0].str_val.len * sizeof(u_char), temp);
                if (temp != NULL) {
                    result->value[0].str_val.data = ngx_pcalloc(r->pool, sizeof(u_char) * (temp->value.len + 1));
                    ngx_memcpy(result->value[0].str_val.data, temp->value.data, sizeof(u_char) * temp->value.len);
                    result->value[0].str_val.len = temp->value.len;
                } else {
                    result->value[0].str_val.data = ngx_pcalloc(r->pool, 1);
                    result->value[0].str_val.len = 0;
                }
                STACK_PUSH2(stack, result, utstack_handle);
                break;
            }

            case VM_CODE_PUSH_HEADER_IN:
            {
                ngx_str_t header_key;
                header_key.data = ngx_strdup(argv->value[0].str_val.data);
                header_key.len = argv->value[0].str_val.len;
                ngx_strlow(header_key.data, header_key.data, header_key.len);

                key_value_t* temp = NULL;
                HASH_FIND(hh, header_in, header_key.data, header_key.len * sizeof(u_char), temp);

                free(header_key.data);
                header_key.len = 0;

                vm_stack_arg_t* result = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                result->type[0] = VM_DATA_STR;
                result->argc = 1;
                
                if (temp != NULL) {
                    result->value[0].str_val.data = ngx_pcalloc(r->pool, sizeof(u_char) * (temp->value.len + 1));
                    ngx_memcpy(result->value[0].str_val.data, temp->value.data, sizeof(u_char) * temp->value.len);
                    result->value[0].str_val.len = temp->value.len;
                } else {
                    result->value[0].str_val.data = ngx_pcalloc(r->pool, sizeof(u_char));
                    result->value[0].str_val.len = 0;
                }
                STACK_PUSH2(stack, result, utstack_handle);
                break;
            }
            
            case VM_CODE_OP_NOT:
            {
                vm_stack_arg_t* temp = NULL;
                STACK_POP2(stack, temp, utstack_handle);
                temp->value[0].bool_val = !temp->value[0].bool_val;
                STACK_PUSH2(stack, temp, utstack_handle);
                break;
            }

            case VM_CODE_OP_AND:
            case VM_CODE_OP_OR:
            {
                vm_stack_arg_t *left = NULL, *right = NULL, *result = NULL;
                STACK_POP2(stack, left, utstack_handle);
                STACK_POP2(stack, right, utstack_handle);
                result = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                result->type[0] = VM_DATA_BOOL;
                result->argc = 1;
                if (code->type == VM_CODE_OP_AND) {
                    result->value[0].bool_val = left->value[0].bool_val && right->value[0].bool_val;
                } else {
                    result->value[0].bool_val = left->value[0].bool_val || right->value[0].bool_val;
                }
                STACK_PUSH2(stack, result, utstack_handle);
                break;
            }
            
            case VM_CODE_OP_BELONG_TO:
            {
                vm_stack_arg_t *left = NULL, *right = NULL, *result = NULL;
                STACK_POP2(stack, left, utstack_handle);
                STACK_POP2(stack, right, utstack_handle);
                result = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                result->type[0] = VM_DATA_BOOL;
                result->argc = 1;

                if (left->type[0] == VM_DATA_IPV4 && right->type[0] == VM_DATA_STR) {
                    ipv4_t ipv4;
                    if (ngx_http_waf_parse_ipv4(right->value[0].str_val, &ipv4) == NGX_HTTP_WAF_SUCCESS) {
                        if (ngx_http_waf_ipv4_netcmp(left->value[0].inx_addr_val.ipv4.s_addr, &ipv4) == NGX_HTTP_WAF_MATCHED) {
                            result->value[0].bool_val = 1;
                        } else {
                            result->value[0].bool_val = 0;
                        }
                    } else {
                        result->value[0].bool_val = 0;
                    }
                    
                } 
#if (NGX_HAVE_INET6)
                else if (left->type[0] == VM_DATA_IPV6 && right->type[0] == VM_DATA_STR) {
                    ipv6_t ipv6;
                    if (ngx_http_waf_parse_ipv6(right->value[0].str_val, &ipv6) == NGX_HTTP_WAF_SUCCESS) {
                        if (ngx_http_waf_ipv6_netcmp(left->value[0].inx_addr_val.ipv6.s6_addr, &ipv6) == NGX_HTTP_WAF_MATCHED) {
                            result->value[0].bool_val = 1;
                        } else {
                            result->value[0].bool_val = 0;
                        }
                    } else {
                        result->value[0].bool_val = 0;
                    }
                } 
#endif
                else {
                    result->value[0].bool_val = 0;
                }
                STACK_PUSH2(stack, result, utstack_handle);
                break;
            }

            case VM_CODE_OP_EQUALS:
            {
                vm_stack_arg_t *left = NULL, *right = NULL, *result = NULL;
                STACK_POP2(stack, left, utstack_handle);
                STACK_POP2(stack, right, utstack_handle);
                result = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                result->type[0] = VM_DATA_BOOL;
                result->argc = 1;
                if (left->type[0] == VM_DATA_STR && right->type[0] == VM_DATA_STR) {
                    if (ngx_strcmp(left->value[0].str_val.data, right->value[0].str_val.data) == 0) {
                        result->value[0].bool_val = 1;
                    } else {
                        result->value[0].bool_val = 0;
                    }
                } else if (left->type[0] == VM_DATA_IPV4 && right->type[0] == VM_DATA_STR) {
                    struct in_addr addr4;
                    if (inet_pton(AF_INET, (char*)right->value[0].str_val.data, &addr4) != 1) {
                        result->value[0].bool_val = 0;
                    } else {
                        result->value[0].bool_val = ngx_memcmp(&(left->value[0].inx_addr_val.ipv4), 
                                                               &addr4, 
                                                                sizeof(struct in_addr));
                    }
                    
                } 
#if (NGX_HAVE_INET6)
                else if (left->type[0] == VM_DATA_IPV6 && right->type[0] == VM_DATA_STR) {
                    struct in6_addr addr6;
                    if (inet_pton(AF_INET6, (char*)right->value[0].str_val.data, &addr6) != 1) {
                        result->value[0].bool_val = 0;
                    } else {
                        result->value[0].bool_val = ngx_memcmp(&(left->value[0].inx_addr_val.ipv6), 
                                                               &addr6, 
                                                                sizeof(struct in6_addr));
                    }
                } 
#endif
                else {
                    result->value[0].bool_val = 0;
                }

                STACK_PUSH2(stack, result, utstack_handle);
                break;
            }

            case VM_CODE_OP_CONTAINS:
            {
                vm_stack_arg_t *left = NULL, *right = NULL, *result = NULL;
                STACK_POP2(stack, left, utstack_handle);
                STACK_POP2(stack, right, utstack_handle);
                result = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                result->type[0] = VM_DATA_BOOL;
                result->argc = 1;
                if (ngx_strstr(left->value[0].str_val.data, right->value[0].str_val.data) != NULL) {
                    result->value[0].bool_val = 1;
                } else {
                    result->value[0].bool_val = 0;
                }
                STACK_PUSH2(stack, result, utstack_handle);
                break;
            }

            case VM_CODE_OP_MATCHES:
            {
                vm_stack_arg_t *left = NULL, *right = NULL, *result = NULL;
                STACK_POP2(stack, left, utstack_handle);
                STACK_POP2(stack, right, utstack_handle);

                result = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                result->type[0] = VM_DATA_BOOL;
                result->argc = 1;

                ngx_regex_compile_t   regex_compile;
                u_char errstr[NGX_MAX_CONF_ERRSTR];
                ngx_regex_elt_t* ngx_regex_elt = ngx_pcalloc(r->pool, sizeof(ngx_regex_elt_t));
                ngx_memzero(&regex_compile, sizeof(ngx_regex_compile_t));
                ngx_memcpy(&(regex_compile.pattern), &(right->value[0].str_val), sizeof(ngx_str_t));
                regex_compile.pool = r->pool;
                regex_compile.err.len = NGX_MAX_CONF_ERRSTR;
                regex_compile.err.data = errstr;

                if (ngx_regex_compile(&regex_compile) != NGX_OK) {
                    result->value[0].bool_val = 0;
                } else {
                     ngx_regex_elt->regex = regex_compile.regex;
                     ngx_int_t rc = ngx_regex_exec(ngx_regex_elt->regex, &(left->value[0].str_val), NULL, 0);
                    if (rc >= 0) {
                        result->value[0].bool_val = 1;
                    } else {
                        result->value[0].bool_val = 0;
                    }
                }
                
                STACK_PUSH2(stack, result, utstack_handle);
                break;
            }

            case VM_CODE_OP_SQLI_DETN:
            {
                vm_stack_arg_t *operand = NULL, *result = NULL;
                STACK_POP2(stack, operand, utstack_handle);
                result = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                result->type[0] = VM_DATA_BOOL;
                result->argc = 1;
                
                sfilter sf;
                libinjection_sqli_init(&sf, 
                                        (char*)(operand->value[0].str_val.data), 
                                        operand->value[0].str_val.len,
                                        FLAG_NONE | 
                                        FLAG_QUOTE_NONE | 
                                        FLAG_QUOTE_SINGLE | 
                                        FLAG_QUOTE_DOUBLE | 
                                        FLAG_SQL_ANSI | 
                                        FLAG_SQL_MYSQL);

                if (libinjection_is_sqli(&sf) == 1) {
                    result->value[0].bool_val = 1;
                } else {
                    result->value[0].bool_val = 0;
                }

                STACK_PUSH2(stack, result, utstack_handle);
                break;
            }

            case VM_CODE_OP_XSS_DETN:
            {
                vm_stack_arg_t *operand = NULL, *result = NULL;
                STACK_POP2(stack, operand, utstack_handle);
                result = ngx_pcalloc(r->pool, sizeof(vm_stack_arg_t));
                result->type[0] = VM_DATA_BOOL;
                result->argc = 1;
                
                if (libinjection_xss((char*)(operand->value[0].str_val.data), operand->value[0].str_val.len) == 1) {
                    result->value[0].bool_val = 1;
                } else {
                    result->value[0].bool_val = 0;
                }

                STACK_PUSH2(stack, result, utstack_handle);
                break;
            }

            case VM_CODE_ACT_RETURN:
            {
                vm_stack_arg_t *bool_val = NULL, *id = NULL;
                STACK_POP2(stack, bool_val, utstack_handle);
                STACK_POP2(stack, id, utstack_handle);
                if (bool_val->value->bool_val) {
                    ctx->blocked = NGX_HTTP_WAF_TRUE;
                    ctx->checked = NGX_HTTP_WAF_TRUE;
                    *out_http_status = argv->value[0].int_val;
                    ngx_strcpy(ctx->rule_type, "ADVANCED");
                    ngx_strcpy(ctx->rule_deatils, id->value[0].str_val.data);
                    ret = NGX_HTTP_WAF_MATCHED;
                    goto RELEASE;
                }
                break;
            }

            case VM_CODE_ACT_ALLOW:
            {
                vm_stack_arg_t *bool_val = NULL, *id = NULL;
                STACK_POP2(stack, bool_val, utstack_handle);
                STACK_POP2(stack, id, utstack_handle);
                if (bool_val->value->bool_val) {
                    ctx->blocked = NGX_HTTP_WAF_FALSE;
                    ctx->checked = NGX_HTTP_WAF_TRUE;
                    *out_http_status = NGX_DECLINED;
                    ngx_strcpy(ctx->rule_type, "ADVANCED");
                    ngx_strcpy(ctx->rule_deatils, id->value[0].str_val.data);
                    ret = NGX_HTTP_WAF_MATCHED;
                    goto RELEASE;
                }
                break;
            }

            default:
                break;
        }
    }

    RELEASE: ;

    key_value_t *temp0 = NULL, *temp1 = NULL;
    HASH_ITER(hh, query_string, temp0, temp1) {
        HASH_DEL(query_string, temp0);
        free(temp0->key.data);
        free(temp0->value.data);
        free(temp0);
    }

    temp0 = NULL;
    temp1 = NULL;
    HASH_ITER(hh, header_in, temp0, temp1) {
        HASH_DEL(header_in, temp0);
        free(temp0->key.data);
        free(temp0->value.data);
        free(temp0);
    }

    return ret;
}


void ngx_http_waf_print_code(UT_array* array) {
    vm_code_t* p = NULL;
    while (p = (vm_code_t*)utarray_next(array, p), p != NULL) {
        vm_code_t* q = p;
        switch (q->type) {
            case VM_CODE_PUSH_INT:
                printf("PUSH_INT %d\n", q->argv.value[0].int_val);
                break;
            case VM_CODE_PUSH_STR:
                printf("PUSH_STR %s\n", q->argv.value[0].str_val.data);
                break;
            case VM_CODE_PUSH_CLIENT_IP:
                printf("PUSH_CLIENT_IP\n");
                break;
            case VM_CODE_PUSH_URL:
                printf("PUSH_URL\n");
                break;
            case VM_CODE_PUSH_USER_AGENT:
                printf("PUSH_USER_AGENT\n");
                break;
            case VM_CODE_PUSH_QUERY_STRING:
                printf("PUSH_QUERY_STRING %s\n", (char*)(q->argv.value[0].str_val.data));
                break;
            case VM_CODE_PUSH_REFERER:
                printf("PUSH_REFERER\n");
                break;
            case VM_CODE_PUSH_HEADER_IN:
                printf("PUSH_HEADER_IN %s\n", (char*)(q->argv.value[0].str_val.data));
                break;
            case VM_CODE_OP_NOT:
                printf("OP_NOT\n");
                break;
            case VM_CODE_OP_AND:
                printf("OP_AND\n");
                break;
            case VM_CODE_OP_OR:
                printf("OP_OR\n");
                break;
            case VM_CODE_OP_CONTAINS:
                printf("OP_CONTAINS\n");
                break;
            case VM_CODE_OP_MATCHES:
                printf("OP_MATCHES\n");
                break;
            case VM_CODE_OP_EQUALS:
                printf("OP_EQUALS\n");
                break;
            case VM_CODE_OP_BELONG_TO:
                printf("OP_BELONG_TO\n");
                break;
            case VM_CODE_ACT_RETURN:
                printf("ACT_RET %d\n", q->argv.value[0].int_val);
                break;
            case VM_CODE_ACT_ALLOW:
                printf("ACT_ALLOW\n");
                break;
            case VM_CODE_OP_SQLI_DETN:
                printf("OP_SQLI_DETN\n");
                break;
            case VM_CODE_OP_XSS_DETN:
                printf("OP_XSS_DETN\n");
                break;
            case VM_CODE_NOP:
                printf("NOP\n");
                break;
            default:
                break;
        }
    }
}