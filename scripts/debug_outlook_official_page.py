#!/usr/bin/env python3
"""Debug current official Outlook page state for alias/login automation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.base_mailbox import OutlookOfficialWebMailbox


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool-secret", required=True)
    parser.add_argument("--proof-pool-secret", required=True)
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument(
        "--entry",
        choices=("login", "manage"),
        default="login",
        help="login: stop after _login_if_needed; manage: stop after _open_alias_manage_page",
    )
    return parser.parse_args()


def dump_controls(mailbox: OutlookOfficialWebMailbox) -> list[dict]:
    page = mailbox._ensure_page()
    return page.evaluate(
        """
        () => Array.from(document.querySelectorAll('button, input, a, div[role="button"], span[role="button"]'))
          .map((el, i) => ({
            idx: i,
            tag: el.tagName,
            id: el.id || '',
            name: el.getAttribute('name') || '',
            type: el.getAttribute('type') || '',
            role: el.getAttribute('role') || '',
            text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim(),
            disabled: Boolean(el.disabled),
            visible: Boolean(el.offsetWidth || el.offsetHeight || el.getClientRects().length),
            href: el.getAttribute('href') || ''
          }))
          .filter((row) => row.visible)
        """
    )


def main() -> int:
    args = parse_args()
    mailbox = OutlookOfficialWebMailbox(
        pool_secret_path=args.pool_secret,
        proof_pool_secret_path=args.proof_pool_secret,
        proof_alias_mode="base",
        proxy=args.proxy,
        timeout=args.timeout,
    )
    mailbox._log_fn = print

    try:
        try:
            if args.entry == "manage":
                mailbox._open_alias_manage_page()
            else:
                mailbox._login_if_needed()
        except Exception as exc:
            print("ENTRY_ERR", repr(exc))

        page = mailbox._ensure_page()
        print("URL", page.url)
        print("BODY")
        print(mailbox._body_text()[:2000])
        print("CONTROLS")
        print(json.dumps(dump_controls(mailbox)[:120], ensure_ascii=False, indent=2))
        return 0
    finally:
        mailbox.close()


if __name__ == "__main__":
    raise SystemExit(main())
