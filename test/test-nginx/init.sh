#!/bin/sh

set -xe

origin_dir=$(pwd)

cd /usr/local/nginx/conf/waf
git clone https://github.com/SpiderLabs/ModSecurity.git
git clone https://github.com/coreruleset/coreruleset.git

mkdir -p modsec
cp coreruleset/crs-setup.conf.example ./modsec/crs-setup.conf
cp ModSecurity/modsecurity.conf-recommended ./modsec/modsecurity.conf
cp ModSecurity/unicode.mapping ./modsec/unicode.mapping

sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' ./modsec/modsecurity.conf
echo "Include /usr/local/nginx/conf/waf/modsec/crs-setup.conf" >> ./modsec/modsecurity.conf
echo "Include /usr/local/nginx/conf/waf/coreruleset/rules/*.conf" >> ./modsec/modsecurity.conf
echo "SecRule ARGS:test \"@streq deny\" \"id:1234567,phase:2,log,auditlog,deny,status:403\"" >> ./modsec/modsecurity.conf
echo "SecRule ARGS:test \"@streq redirect\" \"id:123456,phase:2,log,auditlog,redirect:/,status:302\"" >> ./modsec/modsecurity.conf


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