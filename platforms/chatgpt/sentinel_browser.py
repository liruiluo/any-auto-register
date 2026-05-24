"""Browser-assisted Sentinel token minting for OpenAI auth flows."""

from __future__ import annotations

import threading
from typing import Any, Callable

from .playwright_display import harden_playwright_context, prepare_playwright_launch_kwargs


def mint_browser_sentinel_token(
    *,
    proxy: str | None,
    browser_mode: str,
    context_kwargs: dict[str, Any] | None,
    cookies: list[dict[str, Any]] | None,
    page_url: str,
    flow: str,
    logger: Callable[[str], None] | None = None,
    sdk_timeout_ms: int = 60000,
    clearance_timeout_ms: int = 120000,
) -> dict[str, Any]:
    """Mint a real SentinelSDK token inside a browser context."""
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
    except Exception as exc:
        return {"ok": False, "error": "browser_unavailable", "exception": repr(exc)}

    def log(message: str) -> None:
        if logger:
            logger(message)

    def looks_like_challenge(text: str) -> bool:
        lowered = (text or "").lower()
        return any(
            marker in lowered
            for marker in (
                "just a moment",
                "cloudflare",
                "verify you are human",
                "checking your browser",
                "cf-challenge",
            )
        )

    launch_kwargs: dict[str, Any] = {
        "headless": browser_mode != "headed",
        "args": ["--no-sandbox", "--disable-dev-shm-usage"],
    }
    if proxy:
        launch_kwargs["proxy"] = {"server": proxy}
    launch_kwargs = prepare_playwright_launch_kwargs(launch_kwargs, browser_mode, log)

    def worker() -> dict[str, Any]:
        result: dict[str, Any] = {"ok": False, "error": "unknown"}
        try:
            with sync_playwright() as playwright:
                browser = None
                context = None
                try:
                    browser = playwright.chromium.launch(**launch_kwargs)
                    context = harden_playwright_context(browser.new_context(**(context_kwargs or {})))
                    if cookies:
                        context.add_cookies(cookies)
                    page = context.new_page()

                    def body_preview(limit: int = 1200) -> str:
                        try:
                            return (page.locator("body").inner_text(timeout=3000) or "")[:limit]
                        except Exception:
                            return ""

                    for attempt in range(2):
                        page.goto(page_url, wait_until="domcontentloaded", timeout=45000)
                        page.wait_for_timeout(1800)
                        body = body_preview()
                        title = page.title()
                        if looks_like_challenge("\n".join((title, body))):
                            log(f"browser sentinel 命中 challenge，等待 clearance attempt={attempt + 1}")
                            try:
                                page.wait_for_function(
                                    "() => !document.body || !/just a moment|cloudflare|verify you are human|checking your browser/i.test(document.body.innerText || '')",
                                    timeout=clearance_timeout_ms,
                                )
                                try:
                                    page.wait_for_load_state("networkidle", timeout=15000)
                                except Exception:
                                    pass
                                page.wait_for_timeout(2500)
                            except Exception as exc:
                                result = {
                                    "ok": False,
                                    "error": "challenge_timeout",
                                    "exception": repr(exc),
                                    "page_url": page.url,
                                    "title": title,
                                    "body": body,
                                    "cookies": context.cookies(),
                                }
                                return result
                        try:
                            page.wait_for_function(
                                "() => !!(window.SentinelSDK && typeof window.SentinelSDK.token === 'function')",
                                timeout=sdk_timeout_ms,
                            )
                            token_result = page.evaluate(
                                """
                                async ({flowName, timeoutMs}) => {
                                  try {
                                    const timeoutPromise = new Promise((resolve) => {
                                      setTimeout(() => resolve({ ok: false, error: "sdk_timeout_js" }), timeoutMs);
                                    });
                                    const tokenPromise = (async () => {
                                      const token = await window.SentinelSDK.token(flowName);
                                      return { ok: !!token, token: token || "" };
                                    })();
                                    return await Promise.race([tokenPromise, timeoutPromise]);
                                  } catch (error) {
                                    return {
                                      ok: false,
                                      error: "sdk_exception_js",
                                      exception: String(error && error.stack ? error.stack : error),
                                    };
                                  }
                                }
                                """,
                                {"flowName": flow, "timeoutMs": sdk_timeout_ms},
                            )
                            token = ""
                            if isinstance(token_result, dict):
                                token = str(token_result.get("token") or "").strip()
                                if not token and token_result.get("error"):
                                    result = {
                                        "ok": False,
                                        "error": str(token_result.get("error") or "sdk_error"),
                                        "exception": str(token_result.get("exception") or ""),
                                        "page_url": page.url,
                                        "title": page.title(),
                                        "body": body_preview(),
                                        "cookies": context.cookies(),
                                    }
                                    return result
                            else:
                                token = str(token_result or "").strip()
                            result = {
                                "ok": bool(token),
                                "token": token,
                                "page_url": page.url,
                                "title": page.title(),
                                "body": body_preview(800),
                                "cookies": context.cookies(),
                            }
                            return result
                        except PlaywrightTimeoutError as exc:
                            result = {
                                "ok": False,
                                "error": "sdk_timeout",
                                "exception": repr(exc),
                                "page_url": page.url,
                                "title": page.title(),
                                "body": body_preview(),
                                "cookies": context.cookies(),
                            }
                        except Exception as exc:
                            result = {
                                "ok": False,
                                "error": "sdk_exception",
                                "exception": repr(exc),
                                "page_url": page.url,
                                "title": page.title(),
                                "body": body_preview(),
                                "cookies": context.cookies(),
                            }
                finally:
                    if context is not None:
                        try:
                            context.close()
                        except Exception:
                            pass
                    if browser is not None:
                        try:
                            browser.close()
                        except Exception:
                            pass
        except Exception as exc:
            result = {"ok": False, "error": "browser_exception", "exception": repr(exc)}
        return result

    container: dict[str, Any] = {}

    def target():
        container["result"] = worker()

    thread = threading.Thread(target=target, name="sentinel-browser-worker", daemon=True)
    thread.start()
    thread.join(timeout=max((clearance_timeout_ms * 2 + sdk_timeout_ms) / 1000.0 + 30.0, 120.0))
    if thread.is_alive():
        return {"ok": False, "error": "browser_thread_timeout"}
    return container.get("result") or {"ok": False, "error": "browser_thread_no_result"}
