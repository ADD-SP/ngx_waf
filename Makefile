# ngx_waf - a nginx WAF module whose logic lives in Rust.
#
#   make deps      install the build time dependencies (cbindgen)
#   make build     build nginx with the static module
#   make build-dynamic  build the dynamic module as well
#   make test      run the Rust tests and the nginx integration tests
#   make test-e2e  run the end to end checks (one and four workers)
#   make install   install the built module
#   make header    regenerate include/ngx_http_waf_ffi.h with cbindgen
#   make clean     remove the build artefacts

NGINX_SRC       ?= $(HOME)/src/nginx
NGINX_VERSION   ?= 1.27.2
NGINX_PREFIX    ?= $(CURDIR)/test/nginx-install
JOBS            ?= $(shell nproc 2>/dev/null || echo 2)
CARGO           ?= cargo
CBINDGEN        ?= cbindgen

NGINX_SRC_DIR   := $(CURDIR)/test/nginx-$(NGINX_VERSION)
NGINX_CONFIGURE := $(NGINX_SRC_DIR)/auto/configure
NGINX_BIN       ?= $(NGINX_SRC_DIR)/objs/nginx
MODULE_SO       := $(NGINX_SRC_DIR)/objs/ngx_http_waf_module.so
RUST_LIB        := $(CURDIR)/rust/target/release/libngx_waf_core.a

.PHONY: all deps rust-core build build-static build-dynamic test test-rust test-nginx \
	test-e2e install header clean fmt clippy

all: build

## Install the build time dependencies.
deps:
	$(CARGO) install cbindgen --version 0.29.4 --locked

## Fetch the nginx sources used by the local build.
$(NGINX_CONFIGURE):
	@mkdir -p $(NGINX_SRC_DIR)
	@if [ -d $(NGINX_SRC) ]; then \
		echo " + copying nginx from $(NGINX_SRC)"; \
		(cd $(NGINX_SRC) && tar cf - --exclude=objs .) | (cd $(NGINX_SRC_DIR) && tar xf -); \
	else \
		echo " + downloading nginx $(NGINX_VERSION)"; \
		mkdir -p $(CURDIR)/test; \
		curl -L --fail -o $(CURDIR)/test/nginx.tar.gz \
			https://nginx.org/download/nginx-$(NGINX_VERSION).tar.gz; \
		tar -xzf $(CURDIR)/test/nginx.tar.gz -C $(CURDIR)/test; \
	fi

## Build nginx with the static module.
build: build-static

## Rebuild the Rust core.  The configure script builds it too, but a developer
## iterating on the Rust code must not have to reconfigure nginx.
rust-core:
	cd rust && $(CARGO) build --profile release $(NGX_WAF_CARGO_FLAGS)

build-static: rust-core $(NGINX_CONFIGURE)
	@if [ ! -f $(NGINX_SRC_DIR)/Makefile ] || [ ! -f $(NGINX_BIN) ]; then \
		echo " + configuring nginx (static module)"; \
		(cd $(NGINX_SRC_DIR) && ./auto/configure \
			--prefix=$(NGINX_PREFIX) \
			--with-http_ssl_module \
			--with-http_realip_module \
			--add-module=$(CURDIR) > /dev/null) || exit 1; \
	fi
	@if [ $(NGINX_BIN) -ot $(RUST_LIB) ]; then \
		echo " + the Rust core changed, relinking nginx"; \
		rm -f $(NGINX_BIN); \
	fi
	@echo " + building nginx"
	@$(MAKE) -C $(NGINX_SRC_DIR) -j$(JOBS)

## Build the dynamic module as well.
build-dynamic: rust-core $(NGINX_CONFIGURE)
	@echo " + configuring nginx (dynamic module)"
	@(cd $(NGINX_SRC_DIR) && ./auto/configure \
		--prefix=$(NGINX_PREFIX) \
		--with-http_ssl_module \
		--with-http_realip_module \
		--add-dynamic-module=$(CURDIR) > /dev/null) || exit 1
	@$(MAKE) -C $(NGINX_SRC_DIR) -j$(JOBS) modules

## Regenerate the C header from the Rust FFI definitions.
## `--only-target-dependencies` keeps the `cargo metadata` call of cbindgen to
## the crates of the host platform, so it works without network access.
header:
	$(CBINDGEN) --config rust/cbindgen.toml --only-target-dependencies \
		--output include/ngx_http_waf_ffi.h rust

test: test-rust test-nginx

test-rust:
	cd rust && $(CARGO) test

## Run the nginx integration suite (see test/test-nginx).
test-nginx:
	cd test/test-nginx && ./run.sh

## Run the end to end checks of the module (see test/e2e).  The second pass
## uses four workers, which is what makes the shared memory of the counters and
## the actions matter.
test-e2e:
	NGINX_BIN=$(NGINX_BIN) ./test/e2e/run.sh
	E2E_WORKERS=4 NGINX_BIN=$(NGINX_BIN) ./test/e2e/run.sh

install: build-dynamic
	@mkdir -p $(NGINX_PREFIX)/modules
	@cp $(MODULE_SO) $(NGINX_PREFIX)/modules/
	@$(MAKE) -C $(NGINX_SRC_DIR) install
	@echo " + the module is installed in $(NGINX_PREFIX)/modules"

fmt:
	cd rust && $(CARGO) fmt

clippy:
	cd rust && $(CARGO) clippy --all-targets -- -D warnings

clean:
	cd rust && $(CARGO) clean
	-rm -rf $(NGINX_SRC_DIR)/objs
