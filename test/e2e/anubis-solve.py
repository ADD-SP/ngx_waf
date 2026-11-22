#!/usr/bin/env python3
"""Complete one real Anubis challenge through the test nginx server."""

import argparse
import hashlib
import http.client
import json
import re
import sys
import urllib.parse


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--host", default="example.test")
    parser.add_argument("--client", default="203.0.113.10")
    parser.add_argument("--base-prefix", default="/base")
    parser.add_argument("--protected", default="/index.html?x=1")
    parser.add_argument("--expect-body", default="backend")
    parser.add_argument("--expect-risk", default="")
    return parser.parse_args()


class Client:
    def __init__(self, args):
        self.args = args
        self.cookies = {}

    def request(self, method, path):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.args.port, timeout=15
        )
        headers = {
            "Host": self.args.host,
            "X-Real-IP": self.args.client,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "Accept": "*/*",
            "X-Anubis-Status": "SPOOF",
            "Connection": "close",
        }
        if self.cookies:
            headers["Cookie"] = "; ".join(
                f"{cookie['name']}={cookie['value']}"
                for cookie in self.cookies.values()
                if cookie_matches(path, cookie["path"])
            )

        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read()
        response_headers = response.getheaders()
        for name, value in response_headers:
            if name.lower() == "set-cookie":
                parts = value.split(";")
                cookie_name, cookie_value = parts[0].split("=", 1)
                cookie_path = "/"
                for attribute in parts[1:]:
                    key, separator, attribute_value = attribute.strip().partition("=")
                    if separator and key.lower() == "path" and attribute_value:
                        cookie_path = attribute_value
                self.cookies[(cookie_name, cookie_path)] = {
                    "name": cookie_name,
                    "value": cookie_value,
                    "path": cookie_path,
                }
        connection.close()
        return response.status, response_headers, body


def cookie_matches(request_target, cookie_path):
    request_path = urllib.parse.urlsplit(request_target).path or "/"
    if request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    return cookie_path.endswith("/") or request_path[len(cookie_path)] == "/"


def header(headers, name):
    values = [value for key, value in headers if key.lower() == name.lower()]
    if not values:
        return None
    return values[-1]


def solve(args):
    client = Client(args)
    base = args.base_prefix.rstrip("/")
    challenge_path = (
        f"{base}/.within.website/?redir="
        + urllib.parse.quote(args.protected, safe="")
    )

    status, headers, body = client.request("GET", challenge_path)
    if status != 200:
        raise RuntimeError(f"challenge page returned HTTP {status}")
    if not (header(headers, "Content-Type") or "").startswith("text/html"):
        raise RuntimeError("challenge page has no HTML content type")

    match = re.search(
        rb'<script id="anubis_challenge" type="application/json">(.*?)</script>',
        body,
        re.S,
    )
    if not match:
        raise RuntimeError("challenge JSON not found")

    payload = json.loads(match.group(1))
    challenge = payload["challenge"]
    difficulty = int(payload["rules"]["difficulty"])
    prefix = "0" * difficulty

    nonce = 0
    while True:
        response = hashlib.sha256(
            f"{challenge['randomData']}{nonce}".encode("ascii")
        ).hexdigest()
        if response.startswith(prefix):
            break
        nonce += 1

    pass_path = (
        f"{base}/.within.website/x/cmd/anubis/api/pass-challenge?"
        + urllib.parse.urlencode(
            {
                "id": challenge["id"],
                "response": response,
                "nonce": nonce,
                "redir": args.protected,
                "elapsedTime": "100",
            }
        )
    )
    status, headers, _ = client.request("GET", pass_path)
    if status not in {302, 303, 307}:
        raise RuntimeError(f"pass-challenge returned HTTP {status}")
    location = header(headers, "Location")
    if not location:
        raise RuntimeError("pass-challenge did not return a Location header")
    redirect = urllib.parse.urlsplit(location)
    redirect_target = redirect.path or "/"
    if redirect.query:
        redirect_target += f"?{redirect.query}"

    auth_cookies = [
        cookie
        for cookie in client.cookies.values()
        if "-auth" in cookie["name"]
    ]
    if not auth_cookies:
        raise RuntimeError("pass-challenge did not set the auth cookie")
    if any(cookie["path"] != "/" for cookie in auth_cookies):
        raise RuntimeError("auth cookie is not scoped to the protected site root")

    status, headers, body = client.request("GET", redirect_target)
    if status != 200:
        raise RuntimeError(f"protected request returned HTTP {status}")
    if body.strip() != args.expect_body.encode():
        raise RuntimeError(f"unexpected protected body: {body!r}")
    risk = (header(headers, "X-Seen-Anubis") or "").strip()
    if risk != args.expect_risk:
        raise RuntimeError(
            f"unexpected backend Anubis risk header: {risk!r}"
        )

    cookie_paths = ",".join(
        sorted(f"{cookie['name']}:{cookie['path']}" for cookie in client.cookies.values())
    )
    print(
        f"anubis challenge passed: difficulty={difficulty} "
        f"nonce={nonce} redirect={location} "
        f"cookies={len(client.cookies)} [{cookie_paths}]"
    )


if __name__ == "__main__":
    try:
        solve(parse_args())
    except Exception as error:
        print(f"anubis solve failed: {error}", file=sys.stderr)
        raise
