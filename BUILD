genrule(
    name = "deps",
    srcs = [
        "@libinjection",
        "@libinjection//:src/libinjection.h",
        "@libinjection//:src/libinjection_sqli.h",
        "@libinjection//:src/libinjection_sqli_data.h",
        "@libinjection//:src/libinjection_xss.h",
        "@libinjection//:src/libinjection_html5.h",
        "@uthash//:include/utarray.h",
        "@uthash//:include/uthash.h",
        "@uthash//:include/utlist.h",
        "@uthash//:include/utringbuffer.h",
        "@uthash//:include/utstack.h",
        "@uthash//:include/utstring.h",
        "@libsodium",
    ],
    outs = [
        "deps.tar.gz"
    ],
    cmd = """
        mkdir -p deps/libinjection/include
        mkdir -p deps/libinjection/lib
        mkdir -p deps/libsodium/include
        mkdir -p deps/libsodium/lib
        mkdir -p deps/uthash/include

        for f in $(locations @libinjection); do
            cp -Lr $$f deps/libinjection/lib
        done

        cp -Lr $(location @libinjection//:src/libinjection.h) deps/libinjection/include
        cp -Lr $(location @libinjection//:src/libinjection_sqli.h) deps/libinjection/include
        cp -Lr $(location @libinjection//:src/libinjection_sqli_data.h) deps/libinjection/include
        cp -Lr $(location @libinjection//:src/libinjection_xss.h) deps/libinjection/include
        cp -Lr $(location @libinjection//:src/libinjection_html5.h) deps/libinjection/include

        cp -Lr $(location @uthash//:include/utarray.h) deps/uthash/include
        cp -Lr $(location @uthash//:include/uthash.h) deps/uthash/include
        cp -Lr $(location @uthash//:include/utlist.h) deps/uthash/include
        cp -Lr $(location @uthash//:include/utringbuffer.h) deps/uthash/include
        cp -Lr $(location @uthash//:include/utstack.h) deps/uthash/include
        cp -Lr $(location @uthash//:include/utstring.h) deps/uthash/include
        
        libsodium_base=$$(dirname $$(echo '$(locations @libsodium)' | awk '{print $$1}'))
        cp -Lr $$libsodium_base/include/* deps/libsodium/include
        cp -Lr $$libsodium_base/lib/* deps/libsodium/lib

        rm -f $(RULEDIR)/deps.tar.gz
        tar -zcvf $(RULEDIR)/deps.tar.gz deps
        rm -rf deps
    """,
)
