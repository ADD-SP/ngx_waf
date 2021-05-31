---
title: Installation Guide
lang: en
sidebarDepth: 3
---

# Installation Guide

This module provides two ways of installation, Docker and compiled.

## Docker

This module provides two ways to get Docker images, pulling remote images and building images locally.

The image is built based on the official Docker image, 
see [Docker image repository](https://hub.docker.com/r/addsp/ngx_waf) for usage.

::: tip Note

Many people have less trust in non-official Docker images, and I do too. 
If you do, it is recommended that you build the image locally.
If you are willing to trust the author of this module, 
it is recommended that you pull the image built by the author directly.

:::

### Pulling Remote Images

This module uploads the corresponding Docker images each time the stable and development versions are updated, 
and rebuilds all images at 00:00:00 UTC on Sunday.

You can choose one of the following two commands to pull an image that has already been built.

```sh
docker pull addsp/ngx_waf:stable

docker pull addsp/ngx_waf:stable-alpine
```

### Build Locally

This module provides two Dockerfile files in the root directory to guide the image build.
They are `docker/Dockerfile.alpine` and `docker/Dockerfile.debian`, respectively.
The former is built based on `nginx:stable-alpine` and the latter is built based on `nginx:stable`.

You can choose one of the following two commands to build the image

```sh
docker build -t nginx:stable-alpine-with-ngx_waf -f docker/Dockerfile.alpine .

docker build -t nginx:stable-with-ngx_waf -f docker/Dockerfile.debian .
```

## Compile And Install

nginx provides two ways to install modules, namely "static linking" and "dynamic loading", 
and the modules installed in these two ways are called "static modules" and "dynamic modules" respectively.

::: warning NOTE

Compiling and installing the module may require some dependencies, 
such as `gcc`, 
so please work out the dependencies yourself; this article does not provide such information.

:::

::: danger WARNING

Compiling and installing a new module requires knowing the parameters of the current nginx's `configure` script, 
which you can get by running `nginx -V`.
Here is an example.

```
nginx version: nginx/1.19.6
built by gcc 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)
built with OpenSSL 1.1.1i  8 Dec 2020
TLS SNI support enabled
configure arguments: --with-mail=dynamic --with-openssl=/usr/local/src/openssl-OpenSSL_1_1_1i --prefix=/usr/local/nginx --user=nginx --group=nginx --with-file-aio --with-http_ssl_module --with-http_geoip_module --with-http_v2_module --with-http_realip_module --with-stream_ssl_preread_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_perl_module --with-http_stub_status_module --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-debug --with-cc-opt='-O3 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic'
```

Be sure to remember what comes after `configure arguments:`, which will be replaced by `ARG` below.

:::

### Static Modules

Installing a static module requires recompiling the entire nginx, which takes longer than installing a dynamic module.

First download the corresponding version of nginx, [download page](http://nginx.org/en/download.html).
The following is an example of `nginx-1.20.1`.

```sh
cd /usr/local/src
wget https://nginx.org/download/nginx-1.20.1.tar.gz
tar -zxf nginx-1.20.1.tar.gz
```

Then download the source code of this module, the following will use the stable version of the source code

```sh
cd /usr/local/src
git clone -b master https://github.com/ADD-SP/ngx_waf.git
cd ngx_waf
git clone https://github.com/libinjection/libinjection.git inc/libinjection
```

Next you should run the configuration script.

```sh
cd /usr/local/src/nginx-1.20.1
./configure ARG --add-module=/usr/local/src/ngx_waf
```

::: warning NOTE

* The meaning of `ARG` is given in [Compile And Install](#compile-and-install).

* If you are using GCC as your compiler, append `-fstack-protector-strong` to `-with-cc-opt`.
For example `--with-cc-opt='-Werror -g'` ---> `--with-cc-opt='-Werror -g -fstack-protector-strong'`

:::

Then start compiling.

```sh
# Not using parallel compilation
make

# Use parallel compilation.
make -j$(nproc)
```

::: tip NOTE

Parallel compilation will improve the compilation speed, but there is a chance of strange errors, 
so you can disable parallel compilation if it goes wrong.

:::

Finally, you should stop nginx and replace the nginx binary.
Assume here that the absolute path to the nginx binary is `/usr/local/nginx/sbin/nginx`.

```sh
cp objs/nginx /usr/local/nginx/sbin/nginx
```

::: tip Hot Deployment

If you do not want to not nginx when replacing binaries, you can refer to the [official documentation for hot deployment scenarios](http://nginx.org/en/docs/control.html).

:::

### Dynamic Modules

Compiling and installing dynamic modules does not require recompiling the entire nginx, 
only all modules, which is faster than static modules, 
which is the recommended way in this document.

The process of downloading nginx source code and module source code is the same as for [Static Modules](#static-modules) and will not be repeated.

Run the configuration script

```sh
./configure --add-dynamic-module=/usr/local/src/ngx_waf --with-compat
```

::: warning NOTE

* If you are using GCC as your compiler, append `-fstack-protector-strong` to `-with-cc-opt`.
For example `--with-cc-opt='-Werror -g'` ---> `--with-cc-opt='-Werror -g -fstack-protector-strong'`

:::

Then start compiling the dynamic module

```sh
make modules
```

You should then stop nginx and copy the dynamic modules to the modules directory.
Assume here that the absolute path to the modules directory is `/usr/local/nginx/modules`.

```sh
cp objs/*.so /usr/local/nginx/modules
```

Finally, add a line to the top of the nginx configuration file.

```vim
load_module "/usr/local/nginx/modules/ngx_http_waf_module.so";
```