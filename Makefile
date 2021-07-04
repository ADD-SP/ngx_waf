parser: flex/lexer.lex bison/parser.yacc
	@flex flex/lexer.lex
	@bison --defines=inc/ngx_http_waf_module_parser.tab.h -L C -o src/ngx_http_waf_module_parser.tab.c bison/parser.yacc