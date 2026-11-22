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
# The recommended configuration and CRS have to know the variables supported
# by the libmodsecurity linked into nginx.  Upstream's latest configuration can
# be newer than the distribution library, so keep both test dependencies on
# versions compatible with the installed library.  The variables are overrides
# for runs that intentionally use a different build.
modsecurity_ref="${MODSECURITY_REF:-}"
if [ -z "$modsecurity_ref" ]; then
    modsecurity_version=$(pkg-config --modversion modsecurity 2> /dev/null || true)
    modsecurity_ref="v${modsecurity_version:-3.0.12}"
fi
coreruleset_ref="${CORERULESET_REF:-v3.3.7}"
modsecurity_dir="$deps_dir/ModSecurity-$modsecurity_ref"
coreruleset_dir="$deps_dir/coreruleset-$coreruleset_ref"
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
if [ ! -d "$modsecurity_dir/.git" ]; then
    git clone --depth 1 --branch "$modsecurity_ref" \
        https://github.com/SpiderLabs/ModSecurity.git "$modsecurity_dir" || true
fi
if [ ! -d "$coreruleset_dir/.git" ]; then
    git clone --depth 1 --branch "$coreruleset_ref" \
        https://github.com/coreruleset/coreruleset.git "$coreruleset_dir" || true
fi

if [ -d "$modsecurity_dir" ] && [ -d "$coreruleset_dir" ]; then
    ln -sfn "$modsecurity_dir" ModSecurity
    ln -sfn "$coreruleset_dir" coreruleset

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


cd "$origin_dir"
