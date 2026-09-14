#!/bin/sh

set -xe

if [ -z "$MODULE_TEST_PATH" ] ; then
    echo "Environment variable MODULE_TEST_PATH is not set."
    exit 1
fi

base_dir="$MODULE_TEST_PATH"
# The two upstream repositories the ModSecurity cases need are large and are
# only fetched once: they live outside `$base_dir`, which is wiped on every
# run, so a re-run on a machine without network access still works.
deps_dir="${MODULE_TEST_DEPS:-$(dirname "$base_dir")/ngx-waf-test-deps}"
origin_dir=$(pwd)

rm -rf "$base_dir"
mkdir -p "$base_dir"
cp -r ../../assets "$base_dir/waf"

templates=$(ls template)
rm -rf t/*
for file in $templates
do
eval "cat <<EOF
$(cat "template/$file")
EOF
"  > "t/$file"
done

cd "$base_dir/waf"

# The ModSecurity/CRS cases need two upstream repositories.  They are only
# fetched when the cache is empty, the rest of the suite runs without them
# (those cases fail then).
mkdir -p "$deps_dir"
if [ ! -d "$deps_dir/ModSecurity/.git" ]; then
    rm -rf "$deps_dir/ModSecurity"
    git clone https://github.com/SpiderLabs/ModSecurity.git "$deps_dir/ModSecurity" || true
fi
if [ ! -d "$deps_dir/coreruleset/.git" ]; then
    rm -rf "$deps_dir/coreruleset"
    git clone https://github.com/coreruleset/coreruleset.git "$deps_dir/coreruleset" || true
fi

if [ -d "$deps_dir/ModSecurity" ] && [ -d "$deps_dir/coreruleset" ]; then
    ln -sfn "$deps_dir/ModSecurity" ModSecurity
    ln -sfn "$deps_dir/coreruleset" coreruleset

    mkdir -p modsec
    cp coreruleset/crs-setup.conf.example ./modsec/crs-setup.conf
    cp ModSecurity/modsecurity.conf-recommended ./modsec/modsecurity.conf
    cp ModSecurity/unicode.mapping ./modsec/unicode.mapping

    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' ./modsec/modsecurity.conf
    echo "Include ${base_dir}/waf/modsec/crs-setup.conf" >> ./modsec/modsecurity.conf
    echo "Include ${base_dir}/waf/coreruleset/rules/*.conf" >> ./modsec/modsecurity.conf
    echo "SecRule ARGS:test \"@streq deny\" \"id:1234567,phase:2,log,auditlog,deny,status:403\"" >> ./modsec/modsecurity.conf
    echo "SecRule ARGS:test \"@streq redirect\" \"id:123456,phase:2,log,auditlog,redirect:/,status:302\"" >> ./modsec/modsecurity.conf
else
    echo "WARNING: ModSecurity/coreruleset are missing from [$deps_dir], the modsecurity cases will fail."
fi


echo "1.1.1.1" >> ./rules/ipv4
echo "2.0.0.0/8" >> ./rules/ipv4

echo "3.3.3.3" >> ./rules/white-ipv4
echo "4.0.0.0/8" >> ./rules/white-ipv4

echo "AAAA::" >> ./rules/ipv6
echo "BBBB::/16" >> ./rules/ipv6

echo "CCCC::" >> ./rules/white-ipv6
echo "DDDD::/16" >> ./rules/white-ipv6

echo "/white/" >> ./rules/white-url
echo "/white/" >> ./rules/white-referer

cd "$origin_dir"
