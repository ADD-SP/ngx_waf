#!/usr/bin/env python3
"""Extract the binary assets embedded in src/ngx_http_waf_module_data.c.

The C file is the authoritative source of the pages/templates shipped by
ngx_waf.  This script converts the C byte arrays into raw files under
``rust/data`` so the Rust rewrite can embed exactly the same bytes with
``include_bytes!``.  Run it whenever ``ngx_http_waf_module_data.c`` changes::

    python3 rust/tools/extract_data.py
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "ngx_http_waf_module_data.c"
OUT_DIR = ROOT / "rust" / "data"

# The easter eggs (ascii art + SpongeBob) are intentionally not ported yet, see
# rust/README.md.
WANTED = {
    "ngx_http_waf_data_html_block": "block.html",
    "ngx_http_waf_data_html_sponge_bob": "sponge-bob.html",
    "ngx_http_waf_data_html_under_attack": "under-attack.html",
    "ngx_http_waf_data_html_template_hCaptcha": "hCaptcha.html",
    "ngx_http_waf_data_html_template_reCAPTCHAv2_checkbox": "reCAPTCHAv2_Checkbox.html",
    "ngx_http_waf_data_html_template_reCAPTCHAv2_invisible": "reCAPTCHAv2_Invisible.html",
    "ngx_http_waf_data_html_template_reCAPTCHAv3": "reCAPTCHAv3.html",
}

ARRAY_RE = re.compile(
    r"unsigned\s+char\s+(?P<name>\w+)\s*\[(?P<size>\d+)\]\s*=\s*\{(?P<body>.*?)\};",
    re.S,
)


def main() -> int:
    text = SOURCE.read_text()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    found = {}
    for match in ARRAY_RE.finditer(text):
        name = match.group("name")
        if name not in WANTED:
            continue
        values = [int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]{2})", match.group("body"))]
        declared = int(match.group("size"))
        if len(values) != declared:
            print(f"{name}: expected {declared} bytes, got {len(values)}", file=sys.stderr)
            return 1
        target = OUT_DIR / WANTED[name]
        target.write_bytes(bytes(values))
        found[name] = target

    missing = sorted(set(WANTED) - set(found))
    if missing:
        print(f"arrays not found in {SOURCE}: {missing}", file=sys.stderr)
        return 1

    assets = ROOT / "assets"
    for asset, blob in (("block.html", "block.html"), ("under-attack.html", "under-attack.html")):
        a = (assets / asset).read_bytes()
        b = (OUT_DIR / blob).read_bytes()
        status = "identical" if a == b else "DIFFERENT"
        print(f"assets/{asset} vs data.c: {status}")

    print(f"wrote {len(found)} files to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
