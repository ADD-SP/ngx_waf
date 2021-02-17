# ngx_waf Installation Guide

This guide provides two ways of installation:

+ Using Docker
+ Compile & Install

## Using Docker

Run the following command from the project root, which will generate a nginx image with the module already installed when it finishes.

```bash
docker build -t nginx:stable-alpine-with-ngx_waf
```

The image is built on the official Docker image `nginx:stable-alpine`, and the rest of the usage is the same as shown in the [official image documentation](https://hub.docker.com/_/nginx).

## Compile & Install

## download the source code of nginx

If you want to add a new nginx module, you'll need the nginx source code

```bash
cd /usr/local/src
wget http://nginx.org/download/nginx-1.18.0.tar.gz
tar -zxf nginx-1.18.0.tar.gz
```
> The nginx-1.18.0 source code is recommended, but using a lower version of the nginx source code does not guarantee that this module will work. This module is compatible with the Mainline version of nginx, but since the Mainline version is still under development, there is no guarantee that it will always work. If you encounter compatibility issues, please create an issue.

### download the source code of ngx_waf

```bash
cd /usr/local/src
git clone https://github.com/ADD-SP/ngx_waf.git
cd ngx_waf
```

### compile and install

Starting from nginx-1.9.11, nginx began to support dynamic modules.

Using static modules requires all modules to be compiled into binary files, so adding, deleting and updating modules requires recompiling nginx and replacing the old binary files.

Using dynamic modules only needs to load the `.so` at runtime, without recompiling the entire nginx. Just compile the module into a `.so`, and then edit `nginx.conf` to load the corresponding module.

***

**use static modules**

```bash
cd /usr/local/src/nginx-1.18.0
./configure xxx --add-module=/usr/local/src/ngx_waf
make
```
> If you have already installed nginx, it is recommended to run `nginx -V` to get the compilation parameters, and then replace `xxx` with it.

```bash
nginx -s stop
mv /usr/local/nginx/sbin/nginx /usr/local/nginx/sbin/nginx.old
cp objs/nginx /usr/local/nginx/sbin/nginx
nginx
```

> If you don’t want to stop the nginx service, you can upgrade through hot deployment, see [Official Document](https://nginx.org/en/docs/control.html) for hot deployment method.


If nginx is not installed.

```bash
make install
```

***

**use dynamic modules**

```bash
cd /usr/local/src/nginx-1.18.0
./configure xxx --add-dynamic-module=/usr/local/src/ngx_waf
make modules
```
> If you have already installed nginx, it is recommended to run `nginx -V` to get the compilation parameters, and then replace `xxx` with it.

Now you need to find a directory to store the `.so` file of the module, this doc assumes it is stored under `/usr/local/nginx/modules`

```bash
cp objs/ngx_http_waf_module.so /usr/local/nginx/modules/ngx_http_waf_module.so
```

Then edit `nginx.conf` and add a line at the top.

```text
load_module "/usr/local/nginx/modules/ngx_http_waf_module.so";
```
