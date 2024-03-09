
genrule(
    name = "deps",
    srcs = [
        "@uthash//:include/utarray.h",
        "@uthash//:include/uthash.h",
        "@uthash//:include/utlist.h",
        "@uthash//:include/utringbuffer.h",
        "@uthash//:include/utstack.h",
        "@uthash//:include/utstring.h",
        "@libsodium",
        "@libmodsecurity",
        "@libcjson",
        "@libcjson//:cJSON.h",
    ],
    outs = [
        "deps.tar.gz"
    ],
    cmd = """
        mkdir -p deps/libsodium/include
        mkdir -p deps/libsodium/lib
        mkdir -p deps/uthash/include
        mkdir -p deps/libmodsecurity/include
        mkdir -p deps/libmodsecurity/lib
        mkdir -p deps/libcjson/include
        mkdir -p deps/libcjson/lib

        cp -Lr $(location @uthash//:include/utarray.h) deps/uthash/include
        cp -Lr $(location @uthash//:include/uthash.h) deps/uthash/include
        cp -Lr $(location @uthash//:include/utlist.h) deps/uthash/include
        cp -Lr $(location @uthash//:include/utringbuffer.h) deps/uthash/include
        cp -Lr $(location @uthash//:include/utstack.h) deps/uthash/include
        cp -Lr $(location @uthash//:include/utstring.h) deps/uthash/include
        
        libsodium_base=$$(dirname $$(echo '$(locations @libsodium)' | awk '{print $$1}'))
        cp -Lr $$libsodium_base/include/* deps/libsodium/include
        cp -Lr $$libsodium_base/lib/* deps/libsodium/lib

        libmodsecurity_base=$$(dirname $$(echo '$(locations @libmodsecurity)' | awk '{print $$1}'))
        cp -Lr $$libmodsecurity_base/include/* deps/libmodsecurity/include
        cp -Lr $$libmodsecurity_base/lib/* deps/libmodsecurity/lib

        cp -Lr $(location @libcjson//:cJSON.h) deps/libcjson/include
        for f in $(locations @libcjson); do
            # copy .a and .so
            if [ $$(echo $$f | grep -E '\\.a$$') ]; then
                cp -L $$f deps/libcjson/lib
            elif [ $$(echo $$f | grep -E '\\.so$$') ]; then
                cp -L $$f deps/libcjson/lib
            fi
        done


        # chmod
        find deps -type d -exec chmod 755 {} +
        find deps -type f -exec chmod 644 {} +

        rm -f $(RULEDIR)/deps.tar.gz
        tar -zcvf $(RULEDIR)/deps.tar.gz deps
        rm -rf deps
    """,
)
