#!/usr/bin/env python3
"""Seed a real browser from the protocol auth session and probe ChatGPT register flow."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from playwright.sync_api import sync_playwright

from platforms.chatgpt.chatgpt_client import ChatGPTClient
from platforms.chatgpt.sentinel_token import build_sentinel_token


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", required=True, help="Isolated proxy URL, e.g. http://127.0.0.1:17940")
    parser.add_argument("--email", help="Bootstrap email. Defaults to a fresh random placeholder.")
    parser.add_argument("--password", default="AAb1234567890!", help="Password used for register probes.")
    parser.add_argument(
        "--target-url",
        default="https://auth.openai.com/create-account/password",
        help="Target auth page after seeding cookies.",
    )
    parser.add_argument("--headful", action="store_true", help="Launch headed browser instead of headless.")
    parser.add_argument(
        "--browser-default-ua",
        action="store_true",
        help="Do not override Playwright browser user-agent; keep the browser's own UA/CH in sync.",
    )
    parser.add_argument("--browser-executable", help="Optional browser executable path, e.g. /usr/bin/google-chrome")
    parser.add_argument(
        "--browser-fetch-attempts",
        type=int,
        default=2,
        help="How many in-page fetch attempts to run with fresh Sentinel SDK tokens.",
    )
    parser.add_argument("--output", help="Optional JSON output path.")
    return parser.parse_args()


def random_email() -> str:
    return f"seeded-sentinel-{int(time.time())}@example.com"


def jar_cookie_to_playwright(cookie) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": cookie.name,
        "value": cookie.value,
        "domain": cookie.domain,
        "path": cookie.path or "/",
        "secure": bool(cookie.secure),
        "httpOnly": False,
    }
    if cookie.expires:
        try:
            payload["expires"] = int(cookie.expires)
        except Exception:
            pass
    return payload


def playwright_cookie_to_session(cookie: dict[str, Any], client: ChatGPTClient) -> None:
    client.session.cookies.set(
        cookie["name"],
        cookie["value"],
        domain=cookie.get("domain") or "",
        path=cookie.get("path") or "/",
        secure=bool(cookie.get("secure")),
    )


def slim_response(response) -> dict[str, Any]:
    try:
        body = response.text
    except Exception:
        body = ""
    record = {
        "status": response.status_code,
        "url": str(response.url),
        "headers": {
            key: value
            for key, value in response.headers.items()
            if key.lower() in {
                "content-type",
                "cf-ray",
                "x-request-id",
                "x-openai-public-ip",
                "openai-processing-ms",
            }
        },
        "text": body[:1200],
    }
    try:
        record["json"] = response.json()
    except Exception:
        pass
    return record


def protocol_bootstrap(client: ChatGPTClient, email: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "email": email,
        "visit_homepage": client.visit_homepage(),
    }
    csrf = client.get_csrf_token()
    result["csrf_present"] = bool(csrf)
    if not csrf:
        raise RuntimeError("csrf token missing")

    authorize_url = client.signin(email, csrf)
    result["authorize_url"] = authorize_url
    if not authorize_url:
        raise RuntimeError("signin/openai did not return authorize url")

    final_url = client.authorize(authorize_url)
    result["final_url"] = final_url
    result["cookie_names"] = sorted({cookie.name for cookie in client.session.cookies.jar})

    dump_url = f"{client.AUTH}/api/accounts/client_auth_session_dump"
    try:
        dump_response = client.session.get(
            dump_url,
            headers=client._headers(
                dump_url,
                accept="application/json",
                referer=final_url or client.AUTH,
                fetch_site="same-origin",
            ),
            timeout=30,
        )
        result["client_auth_session_dump_status"] = dump_response.status_code
        if dump_response.status_code == 200:
            result["client_auth_session_dump"] = dump_response.json()
        else:
            result["client_auth_session_dump_body"] = dump_response.text[:800]
    except Exception as exc:
        result["client_auth_session_dump_error"] = repr(exc)

    return result


def curl_register_probe(client: ChatGPTClient, email: str, password: str, sentinel_token: str | None = None) -> dict[str, Any]:
    url = f"{client.AUTH}/api/accounts/user/register"
    headers = client._headers(
        url,
        accept="application/json",
        referer=f"{client.AUTH}/create-account/password",
        origin=client.AUTH,
        content_type="application/json",
        fetch_site="same-origin",
    )
    if sentinel_token:
        headers["OpenAI-Sentinel-Token"] = sentinel_token
    response = client.session.post(
        url,
        json={"username": email, "password": password},
        headers=headers,
        timeout=30,
    )
    record = slim_response(response)
    record["sentinel_header"] = bool(sentinel_token)
    return record


def run_browser_probe(
    client: ChatGPTClient,
    email: str,
    password: str,
    target_url: str,
    headful: bool,
    browser_default_ua: bool,
    browser_executable: str | None,
    browser_fetch_attempts: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "target_url": target_url,
        "requests": [],
        "responses": [],
        "console": [],
        "browser_fetch_attempts": [],
    }

    with sync_playwright() as playwright:
        launch_kwargs: dict[str, Any] = {
            "headless": not headful,
            "proxy": {"server": client.proxy},
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        if browser_executable:
            launch_kwargs["executable_path"] = browser_executable
        browser = playwright.chromium.launch(**launch_kwargs)

        context_kwargs: dict[str, Any] = {
            "locale": "en-US",
            "viewport": {"width": 1440, "height": 960},
        }
        if not browser_default_ua:
            context_kwargs["user_agent"] = client.ua
        context = browser.new_context(**context_kwargs)
        context.add_cookies([jar_cookie_to_playwright(cookie) for cookie in client.session.cookies.jar])
        page = context.new_page()

        def on_request(request) -> None:
            if "/api/accounts/user/register" not in request.url:
                return
            payload = {
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
                "post_data": request.post_data,
            }
            result["requests"].append(payload)

        def on_response(response) -> None:
            if "/api/accounts/user/register" not in response.url:
                return
            try:
                body = response.text()
            except Exception:
                body = ""
            payload = {
                "status": response.status,
                "url": response.url,
                "headers": response.headers,
                "body": body[:1200],
            }
            result["responses"].append(payload)

        def on_console(msg) -> None:
            text = msg.text
            if len(result["console"]) < 30:
                result["console"].append({"type": msg.type, "text": text[:400]})

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("console", on_console)

        page.goto(target_url, wait_until="domcontentloaded", timeout=45000)
        page.wait_for_timeout(2500)
        result["page_url"] = page.url
        result["page_title"] = page.title()
        result["body_preview"] = (page.locator("body").inner_text(timeout=3000) or "")[:2000]
        result["navigator_user_agent"] = page.evaluate("() => navigator.userAgent")
        result["navigator_brands"] = page.evaluate(
            "() => (navigator.userAgentData && navigator.userAgentData.brands) ? navigator.userAgentData.brands : null"
        )

        try:
            page.wait_for_function(
                "() => !!(window.SentinelSDK && typeof window.SentinelSDK.token === 'function')",
                timeout=15000,
            )
            result["sentinel_sdk_loaded"] = True
        except Exception as exc:
            result["sentinel_sdk_loaded"] = False
            result["sentinel_sdk_wait_error"] = repr(exc)

        if result.get("sentinel_sdk_loaded"):
            for attempt in range(max(1, int(browser_fetch_attempts or 1))):
                token = page.evaluate(
                    """
                    async () => {
                      return await window.SentinelSDK.token("username_password_create");
                    }
                    """
                )
                attempt_record = {
                    "attempt": attempt + 1,
                    "token_prefix": str(token or "")[:80],
                    "cookie_names_before": sorted({cookie["name"] for cookie in context.cookies()}),
                }
                browser_fetch = page.evaluate(
                    """
                    async ({email, password, token}) => {
                      const response = await fetch("/api/accounts/user/register", {
                        method: "POST",
                        credentials: "include",
                        headers: {
                          "Accept": "application/json",
                          "Content-Type": "application/json",
                          "OpenAI-Sentinel-Token": token
                        },
                        body: JSON.stringify({ username: email, password })
                      });
                      const text = await response.text();
                      let jsonBody = null;
                      try {
                        jsonBody = JSON.parse(text);
                      } catch (err) {}
                      return {
                        status: response.status,
                        ok: response.ok,
                        text: text.slice(0, 1200),
                        json: jsonBody,
                      };
                    }
                    """,
                    {"email": email, "password": password, "token": token},
                )
                attempt_record["result"] = browser_fetch
                attempt_record["cookie_names_after"] = sorted({cookie["name"] for cookie in context.cookies()})
                result["browser_fetch_attempts"].append(attempt_record)
                if attempt == 0:
                    result["browser_sdk_token"] = token
                    result["browser_sdk_token_prefix"] = str(token or "")[:80]
                    result["browser_fetch_register"] = browser_fetch
                page.wait_for_timeout(1200)

            try:
                password_input = page.locator('input[type="password"], input[name="password"]').first
                password_input.wait_for(state="visible", timeout=5000)
                password_input.fill(password)
                page.wait_for_timeout(300)
                submit = page.locator('button[type="submit"], button:has-text("Continue"), button:has-text("继续")').first
                submit.click(timeout=5000)
                page.wait_for_timeout(3500)
                result["ui_submit_attempted"] = True
                result["post_submit_url"] = page.url
                result["post_submit_body_preview"] = (page.locator("body").inner_text(timeout=3000) or "")[:2000]
            except Exception as exc:
                result["ui_submit_attempted"] = False
                result["ui_submit_error"] = repr(exc)

        browser_cookies = context.cookies()
        result["browser_cookie_names"] = sorted({cookie["name"] for cookie in browser_cookies})
        for cookie in browser_cookies:
            playwright_cookie_to_session(cookie, client)

        browser.close()

    return result


def main() -> int:
    args = parse_args()
    email = args.email or random_email()
    client = ChatGPTClient(proxy=args.proxy, verbose=True, browser_mode="protocol")

    result: dict[str, Any] = {
        "proxy": args.proxy,
        "email": email,
        "password_length": len(args.password),
    }

    result["protocol_bootstrap"] = protocol_bootstrap(client, email)
    result["curl_register_no_sentinel"] = curl_register_probe(client, email, args.password, sentinel_token=None)

    python_token = build_sentinel_token(
        client.session,
        client.device_id,
        flow="username_password_create",
        user_agent=client.ua,
        sec_ch_ua=client.sec_ch_ua,
        impersonate=client.impersonate,
    )
    result["python_sdk_token_prefix"] = str(python_token or "")[:80]
    result["curl_register_python_sentinel"] = curl_register_probe(
        client,
        email,
        args.password,
        sentinel_token=python_token,
    )

    result["browser_probe"] = run_browser_probe(
        client,
        email,
        args.password,
        target_url=args.target_url,
        headful=args.headful,
        browser_default_ua=args.browser_default_ua,
        browser_executable=args.browser_executable,
        browser_fetch_attempts=args.browser_fetch_attempts,
    )

    browser_token = result["browser_probe"].get("browser_sdk_token")
    if browser_token:
        result["curl_register_browser_sentinel"] = curl_register_probe(
            client,
            email,
            args.password,
            sentinel_token=browser_token,
        )

    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
