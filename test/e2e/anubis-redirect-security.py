#!/usr/bin/env python3
"""Exercise ambiguous and dangerous Anubis redirect queries through nginx."""

import argparse
import http.client
import sys


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    return parser.parse_args()


def request(port, host, query):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    connection.request(
        "GET",
        "/base/.within.website/x/cmd/anubis/api/pass-challenge?" + query,
        headers={
            "Host": host,
            "X-Real-IP": "203.0.113.20",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "Connection": "close",
        },
    )
    response = connection.getresponse()
    response.read()
    connection.close()
    return response.status


def main():
    args = parse_args()
    failures = []

    rejected = {
        "duplicate canonical and encoded key": (
            "redir=%2Fwp-admin%2F&%72edir=https%3A%2F%2Fevil.example%2F"
        ),
        "duplicate case variant": "redir=%2Fone&reDir=%2Ftwo",
        "duplicate exact key": "redir=%2Fone&redir=%2Ftwo",
        "malformed escape": "redir=%ZZ",
        "control characters": "redir=%2Ffoo%0D%0AX-Bad%3Ayes",
        "scheme-relative target": "redir=%2F%2Fevil.example",
        "cross-origin absolute target": (
            "redir=https%3A%2F%2Fevil.example%2Fwp-admin"
        ),
        "malformed encoded key": "%72edir=%E0%A4%A",
        "invalid UTF-8": "redir=%FF",
        "unescaped semicolon": "redir=%2Fwp-admin%2F;x=1",
    }
    for name, query in rejected.items():
        status = request(args.port, "example.test", query)
        if status != 400:
            failures.append(f"{name}: HTTP {status}, want 400")

    accepted = [
        (
            "domain",
            "example.test",
            "redir=https%3A%2F%2Fexample.test%2Fbase%2F.within.website%2F"
            "%3Fredir%3D%252Fwp-admin%252F",
        ),
        (
            "domain and port",
            "example.test:8443",
            "redir=https%3A%2F%2Fexample.test%3A8443%2Fwp-admin",
        ),
        (
            "IPv4 and port",
            "127.0.0.1:8080",
            "redir=http%3A%2F%2F127.0.0.1%3A8080%2Fwp-admin",
        ),
        (
            "IPv6 and port",
            "[2001:db8::1]:8443",
            "redir=https%3A%2F%2F%5B2001%3Adb8%3A%3A1%5D%3A8443%2Fwp-admin",
        ),
    ]
    for name, host, query in accepted:
        status = request(args.port, host, query)
        if status == 400:
            failures.append(f"{name}: rejected by nginx")
        elif status < 500:
            failures.append(f"{name}: HTTP {status}, expected Anubis error")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        raise SystemExit(1)

    print(f"ok   {len(rejected)} redirect ambiguities rejected")
    print(f"ok   {len(accepted)} Host forms accepted")


if __name__ == "__main__":
    main()
