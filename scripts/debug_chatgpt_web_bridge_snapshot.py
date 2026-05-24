#!/usr/bin/env python3
"""Replay the final ChatGPT web-bridge step from a saved auth-session snapshot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from platforms.chatgpt.chatgpt_client import ChatGPTClient
from platforms.chatgpt.oauth_client import OAuthClient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, help="Path to bridge snapshot JSON.")
    parser.add_argument("--proxy", required=True, help="Proxy URL for this bridge probe.")
    parser.add_argument(
        "--mode",
        choices=("oauth", "chatgpt"),
        default="oauth",
        help="Which bridge implementation to replay.",
    )
    parser.add_argument(
        "--browser-mode",
        choices=("headed", "headless"),
        default="headless",
        help="Browser mode for Playwright replay.",
    )
    parser.add_argument("--target-url", help="Optional target URL override.")
    parser.add_argument("--output", help="Optional JSON output path.")
    return parser.parse_args()


def load_snapshot(path: str) -> dict:
    return json.loads(Path(path).read_text())


def cookie_domain(cookie: dict) -> str:
    domain = str(cookie.get("domain") or "").strip()
    if domain:
        return domain
    url = str(cookie.get("url") or "").strip()
    if url:
        return urlparse(url).netloc
    return ""


def hydrate_session_from_snapshot(client, snapshot: dict) -> None:
    for cookie in snapshot.get("cookies") or []:
        name = str(cookie.get("name") or "").strip()
        value = str(cookie.get("value") or "")
        if not name:
            continue
        domain = cookie_domain(cookie)
        client.session.cookies.set(
            name,
            value,
            domain=domain,
            path=str(cookie.get("path") or "/"),
            secure=bool(cookie.get("secure", True)),
        )


def run_probe(args: argparse.Namespace) -> dict:
    snapshot = load_snapshot(args.snapshot)
    user_agent = str(snapshot.get("user_agent") or "").strip() or None
    target_url = (
        args.target_url
        or str(snapshot.get("consent_url") or "").strip()
        or "https://chatgpt.com/api/auth/signin/openai?callbackUrl=https%3A%2F%2Fchatgpt.com%2F"
    )

    if args.mode == "oauth":
        client = OAuthClient({}, proxy=args.proxy, verbose=True, browser_mode=args.browser_mode)
        hydrate_session_from_snapshot(client, snapshot)
        tokens = client._browser_hydrate_chatgpt_session(
            consent_url=target_url,
            user_agent=user_agent,
        )
    else:
        client = ChatGPTClient({}, proxy=args.proxy, verbose=True, browser_mode=args.browser_mode)
        hydrate_session_from_snapshot(client, snapshot)
        tokens = client._browser_hydrate_chatgpt_session(target_url=target_url)

    result = {
        "mode": args.mode,
        "proxy": args.proxy,
        "browser_mode": args.browser_mode,
        "target_url": target_url,
        "cookie_count": len(snapshot.get("cookies") or []),
        "success": bool(tokens),
        "tokens": tokens or None,
    }
    return result


def main() -> int:
    args = parse_args()
    result = run_probe(args)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        Path(args.output).write_text(text)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
