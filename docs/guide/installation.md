---
title: Installation Guide
lang: en
sidebarDepth: 3
---

# Installation Guide

Please read the [Version Description](version.md) first to pick the right version.

nginx provides two ways to install modules, namely 'statically linked' and 'dynamically loaded', and the modules installed in each way are called 'static modules' and dynamic modules'.

You can choose whether to use static or dynamic modules by running the script `assets/guide.sh`.

```shell
sh assets/guide.sh
```


## Static Modules

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
git clone -b lts https://github.com/ADD-SP/ngx_waf.git
cd ngx_waf
git clone https://github.com/libinjection/libinjection.git inc/libinjection
```

Next you should run the configuration script.

```sh
cd /usr/local/src/nginx-1.20.1
./configure ARG --add-module=/usr/local/src/ngx_waf --with-debug
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

## Dynamic Modules

### Downloading pre-built modules

You can download dynamic modules by executing the script `assets/download.sh`. Here are some use cases.

```shell
# LTS module for nginx-1.20.1
sh assets/download.sh 1.20.1 lts

# LTS module for nginx-1.21.1
sh assets/download.sh 1.21.1 lts

# Current module for nginx-1.20.1
sh assets/download.sh 1.20.1 current

# Current module for nginx-1.21.1
sh assets/download.sh 1.21.1 current
```

After executing the script you will see output like the following.

```
checking for command ... yes
checking for libc implementation ... yes
 + GNU C libary
Pulling remote image addsp/ngx_waf-prebuild:ngx-1.21.1-module-lts-glibc
......
......
......
Download complete!
```

If you see ``Download complete!`` then the download was successful and the module will be saved in the current directory.
You can copy it to a directory and add a line to the top of `nginx.conf`.

```nginx
load_module "/path/to/ngx_http_waf_module.so";
```

Then close nginx and run `nginx -t`. If there are no errors, the module is loaded properly, otherwise your nginx does not support pre-built modules, so compile and install the module.


::: tip NOTE

Once we have updated the module it takes about two hours to compile and upload the module.

:::

### Compile and install

Compiling and installing dynamic modules does not require recompiling the entire nginx, 
only all modules, which is faster than static modules, 
which is the recommended way in this document.

The process of downloading nginx source code and module source code is the same as for [Static Modules](#static-modules) and will not be repeated.

Run the configuration script

```sh
./configure --add-dynamic-module=/usr/local/src/ngx_waf --with-compat --with-debug
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