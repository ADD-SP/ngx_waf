#!/usr/bin/env python3
"""Exercise the Anubis integration through a real Chromium browser."""

import argparse
import json
import os
from pathlib import Path
import sys
import urllib.parse

from playwright.sync_api import sync_playwright


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--expect-text", default="backend")
    parser.add_argument("--timeout", type=float, default=60)
    return parser.parse_args()


def with_query(url, key, value):
    parsed = urllib.parse.urlsplit(url)
    query = [
        item
        for item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if item[0] != key
    ]
    query.append((key, value))
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urllib.parse.urlencode(query),
            parsed.fragment,
        )
    )


def records_matching(records, phase, path):
    return [
        record
        for record in records
        if record["phase"] == phase and path in record["url"]
    ]


def main():
    args = parse_args()
    second_url = with_query(args.url, "browser_e2e", "2")
    timeout_ms = int(args.timeout * 1000)
    phase = {"value": 1}
    records = []
    page_errors = []
    screenshot = os.environ.get("ANUBIS_BROWSER_SCREENSHOT")

    with sync_playwright() as playwright:
        browser = None
        page = None

        try:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            def record_response(response):
                records.append(
                    {
                        "phase": phase["value"],
                        "url": response.url,
                        "status": response.status,
                    }
                )

            def prepare_page(target):
                target.set_default_timeout(timeout_ms)
                target.on("response", record_response)
                target.on(
                    "pageerror",
                    lambda error: page_errors.append(str(error)),
                )

            prepare_page(page)
            page.goto(args.url, wait_until="domcontentloaded")
            page.wait_for_url(args.url, wait_until="domcontentloaded")
            page.wait_for_function(
                "(expected) => document.body?.innerText.includes(expected)",
                arg=args.expect_text,
            )

            cookies = context.cookies(args.url)
            auth_cookies = [
                cookie for cookie in cookies if "-auth" in cookie["name"]
            ]
            if not auth_cookies:
                raise RuntimeError("browser did not retain an Anubis auth cookie")
            if any(cookie["path"] != "/" for cookie in auth_cookies):
                raise RuntimeError(
                    f"Anubis auth cookie has the wrong path: {auth_cookies}"
                )

            first_challenge = records_matching(
                records, 1, "/.within.website/?"
            )
            first_pass_challenge = records_matching(
                records, 1, "/api/pass-challenge"
            )
            first_final = [
                record
                for record in records
                if record["phase"] == 1
                and record["url"] == args.url
                and record["status"] == 200
            ]
            if not first_challenge or not first_pass_challenge or not first_final:
                raise RuntimeError(
                    "first browser load did not complete the Anubis challenge"
                )

            browser.close()
            browser = None
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                storage_state={"cookies": cookies, "origins": []}
            )
            phase["value"] = 2
            page = context.new_page()
            prepare_page(page)
            page.goto(second_url, wait_until="commit")
            page.wait_for_url(second_url, wait_until="commit")
            page.wait_for_function(
                "(expected) => document.body?.innerText.includes(expected)",
                arg=args.expect_text,
            )

            second_challenge = records_matching(
                records, 2, "/.within.website/?"
            )
            second_pass_challenge = records_matching(
                records, 2, "/api/pass-challenge"
            )
            second_final = [
                record
                for record in records
                if record["phase"] == 2
                and record["url"] == second_url
                and record["status"] == 200
            ]
            if second_challenge or second_pass_challenge:
                raise RuntimeError("second browser load repeated the challenge")
            if not second_final:
                raise RuntimeError("second browser load was not HTTP 200")

            print(
                json.dumps(
                    {
                        "first_load": {
                            "challenge_responses": len(first_challenge),
                            "pass_challenge_responses": len(first_pass_challenge),
                            "final_status": first_final[-1]["status"],
                        },
                        "auth_cookies": [
                            {
                                "name": cookie["name"],
                                "domain": cookie["domain"],
                                "path": cookie["path"],
                                "secure": cookie["secure"],
                            }
                            for cookie in auth_cookies
                        ],
                        "second_load": {
                            "challenge_responses": len(second_challenge),
                            "pass_challenge_responses": len(second_pass_challenge),
                            "final_status": second_final[-1]["status"],
                        },
                        "page_errors": page_errors,
                    },
                    indent=2,
                )
            )
        except Exception as error:
            print(f"browser e2e failure: {error}", file=sys.stderr)
            if page is not None and screenshot:
                output = Path(screenshot)
                output.parent.mkdir(parents=True, exist_ok=True)
                try:
                    page.screenshot(path=output, full_page=True, timeout=5000)
                    print(f"browser screenshot: {output}", file=sys.stderr)
                except Exception as screenshot_error:
                    print(
                        f"browser screenshot failed: {screenshot_error}",
                        file=sys.stderr,
                    )
            raise
        finally:
            if browser is not None:
                browser.close()


if __name__ == "__main__":
    main()
