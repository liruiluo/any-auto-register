"""
ChatGPT 注册客户端模块
使用 curl_cffi 模拟浏览器行为
"""

import base64
import json
import random
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlencode, urlparse

try:
    from curl_cffi import requests as curl_requests
except ImportError:
    print("❌ 需要安装 curl_cffi: pip install curl_cffi")
    import sys
    sys.exit(1)

from .playwright_display import (
    fingerprint_context_overrides,
    harden_playwright_context,
    prepare_playwright_launch_kwargs,
)
from .sentinel_browser import mint_browser_sentinel_token
from .sentinel_token import build_sentinel_token
from .utils import (
    FlowState,
    build_browser_headers,
    decode_jwt_payload,
    describe_flow_state,
    extract_flow_state,
    generate_datadog_trace,
    normalize_flow_url,
    random_delay,
    seed_oai_device_cookie,
)


# Chrome 指纹配置
_CHROME_PROFILES = [
    {
        "major": 131, "impersonate": "chrome131",
        "build": 6778, "patch_range": (69, 205),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    },
    {
        "major": 133, "impersonate": "chrome133a",
        "build": 6943, "patch_range": (33, 153),
        "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    },
    {
        "major": 136, "impersonate": "chrome136",
        "build": 7103, "patch_range": (48, 175),
        "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    },
]


def _random_chrome_version():
    """选择当前栈上已验证更稳定的 Chrome 指纹。"""
    profile = _CHROME_PROFILES[0]
    major = profile["major"]
    build = profile["build"]
    patch = random.randint(*profile["patch_range"])
    full_ver = f"{major}.0.{build}.{patch}"
    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_ver} Safari/537.36"
    return profile["impersonate"], major, full_ver, ua, profile["sec_ch_ua"]


class ChatGPTClient:
    """ChatGPT 注册客户端"""
    
    BASE = "https://chatgpt.com"
    AUTH = "https://auth.openai.com"
    
    def __init__(self, proxy=None, verbose=True, browser_mode="protocol"):
        """
        初始化 ChatGPT 客户端
        
        Args:
            proxy: 代理地址
            verbose: 是否输出详细日志
            browser_mode: protocol | headless | headed
        """
        self.proxy = proxy
        self.verbose = verbose
        self.browser_mode = browser_mode or "protocol"
        self.current_email = ""
        self.current_password = ""
        self._preloaded_chatgpt_tokens = None
        self.device_id = str(uuid.uuid4())
        self.accept_language = random.choice([
            "en-US,en;q=0.9",
            "en-US,en;q=0.9,zh-CN;q=0.8",
            "en,en-US;q=0.9",
            "en-US,en;q=0.8",
        ])
        
        # 随机 Chrome 版本
        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = _random_chrome_version()
        
        # 创建 session
        self.session = curl_requests.Session(impersonate=self.impersonate)
        
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}
        
        # 设置基础 headers
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept-Language": self.accept_language,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": f'"{self.chrome_full}"',
            "sec-ch-ua-platform-version": f'"{random.randint(10, 15)}.0.0"',
        })
        
        # 设置 oai-did cookie
        seed_oai_device_cookie(self.session, self.device_id)
        self.last_registration_state = FlowState()
        self.last_create_account_callback_url = ""
    
    def _log(self, msg):
        """输出日志"""
        if self.verbose:
            print(f"  {msg}")

    def _browser_pause(self, low=0.15, high=0.45):
        """在 headed 模式下加入轻微停顿，模拟有头浏览器节奏。"""
        if self.browser_mode == "headed":
            random_delay(low, high)

    def _mint_browser_sentinel_token(self, page_url, flow):
        result = mint_browser_sentinel_token(
            proxy=self.proxy,
            browser_mode=self.browser_mode,
            context_kwargs=self._playwright_context_kwargs(),
            cookies=self._cookies_for_playwright(),
            page_url=page_url,
            flow=flow,
            logger=self._log,
        )
        self._sync_playwright_cookies(result.get("cookies") or [])
        token = str(result.get("token") or "").strip()
        if token:
            self._log(f"browser sentinel token 已获取 flow={flow} prefix={token[:40]}")
        else:
            detail = " | ".join(
                str(part).strip()
                for part in (
                    result.get("error"),
                    result.get("exception"),
                    result.get("page_url"),
                )
                if str(part or "").strip()
            )
            self._log(f"browser sentinel token 失败 flow={flow}: {detail or 'unknown'}")
        return token

    def _cookies_for_playwright(self):
        cookies = []
        for cookie in self.session.cookies.jar:
            name = str(cookie.name or "").strip()
            value = str(cookie.value or "")
            if not name:
                continue
            domain = str(cookie.domain or "").strip()
            target_url = "https://auth.openai.com/"
            if "chatgpt.com" in domain or name.startswith("__Secure-next-auth"):
                target_url = "https://chatgpt.com/"
            elif "auth.openai.com" in domain or "openai.com" in domain:
                target_url = "https://auth.openai.com/"
            elif name in {"oai-sc"}:
                target_url = "https://chatgpt.com/"
            payload = {"name": name, "value": value}
            path = str(cookie.path or "/").strip() or "/"
            secure = bool(cookie.secure)
            http_only = bool(getattr(cookie, "_rest", {}).get("HttpOnly"))
            same_site = str(getattr(cookie, "_rest", {}).get("SameSite") or "").strip()

            if name.startswith("__Host-") or name.startswith("__Secure-next-auth"):
                payload["url"] = target_url
                payload["secure"] = secure or name.startswith("__Host-")
            elif domain:
                payload["domain"] = domain
                payload["path"] = path
                payload["secure"] = secure
            else:
                payload["url"] = target_url
                payload["secure"] = secure

            if http_only:
                payload["httpOnly"] = True
            if same_site in {"Lax", "None", "Strict"}:
                payload["sameSite"] = same_site
            if cookie.expires:
                try:
                    payload["expires"] = int(cookie.expires)
                except Exception:
                    pass
            cookies.append(payload)
        return cookies

    def clear_next_auth_transient_cookies(self):
        prefixes = (
            "__host-next-auth.",
            "__secure-next-auth.",
            "__host-authjs.",
            "__secure-authjs.",
            "next-auth.",
            "authjs.",
        )
        keep_suffixes = (
            ".session-token",
            ".session-token.0",
            ".session-token.1",
            ".session-token.2",
            ".session-token.3",
        )
        removed = []
        jar = getattr(self.session.cookies, "jar", None)
        if jar is None:
            return removed
        for cookie in list(jar):
            name = str(cookie.name or "")
            lowered = name.lower()
            if not any(lowered.startswith(prefix) for prefix in prefixes):
                continue
            if any(lowered.endswith(suffix) for suffix in keep_suffixes):
                continue
            removed.append(name)
            try:
                self.session.cookies.clear(domain=cookie.domain, path=cookie.path, name=cookie.name)
            except Exception:
                try:
                    self.session.cookies.clear(name=cookie.name)
                except Exception:
                    pass
        if removed:
            unique = sorted(set(removed))
            self._log(f"清理 next-auth/authjs 临时 cookie: {', '.join(unique[:8])}")
        return removed

    def _sync_playwright_cookies(self, cookies):
        for cookie in cookies or []:
            try:
                self.session.cookies.set(
                    cookie.get("name") or "",
                    cookie.get("value") or "",
                    domain=cookie.get("domain") or "",
                    path=cookie.get("path") or "/",
                    secure=bool(cookie.get("secure")),
                )
            except Exception:
                continue

    def _purge_cookie_names(self, names):
        targets = {str(name or "").strip() for name in (names or []) if str(name or "").strip()}
        if not targets:
            return
        jar = getattr(self.session.cookies, "jar", None)
        if jar is None:
            return
        for cookie in list(jar):
            name = str(getattr(cookie, "name", "") or "").strip()
            if name not in targets:
                continue
            try:
                jar.clear(
                    domain=getattr(cookie, "domain", None),
                    path=getattr(cookie, "path", None),
                    name=name,
                )
            except Exception:
                try:
                    self.session.cookies.set(
                        name,
                        "",
                        domain=getattr(cookie, "domain", "") or "",
                        path=getattr(cookie, "path", "/") or "/",
                        expires=0,
                    )
                except Exception:
                    continue

    def _add_cookies_to_playwright_context(self, context, cookies, label):
        payloads = list(cookies or [])
        if not payloads:
            return
        try:
            context.add_cookies(payloads)
            return
        except Exception as exc:
            self._log(f"{label}: bulk add_cookies 失败: {exc}")

        added = 0
        rejected = []
        for cookie in payloads:
            item = dict(cookie or {})
            if item.get("url"):
                item.pop("path", None)
                item.pop("domain", None)
            if item.get("domain") and not item.get("path"):
                item["path"] = "/"
            if not item.get("url") and not item.get("domain"):
                item["url"] = "https://auth.openai.com/"
            try:
                context.add_cookies([item])
                added += 1
            except Exception as exc:
                rejected.append(
                    {
                        "name": item.get("name"),
                        "domain": item.get("domain"),
                        "path": item.get("path"),
                        "url": item.get("url"),
                        "error": repr(exc),
                    }
                )
        self._log(f"{label}: fallback add_cookies added={added} rejected={len(rejected)}")
        if rejected:
            self._log(
                f"{label}: rejected cookie sample "
                f"{json.dumps(rejected[:3], ensure_ascii=False)[:600]}"
            )

    def _playwright_context_kwargs(self):
        kwargs = {
            "locale": "en-US",
            "viewport": {"width": 1440, "height": 960},
            "user_agent": self.ua,
        }
        kwargs.update(fingerprint_context_overrides())
        return kwargs

    def _browser_open_url_and_sync(self, page_url, referer=None, label="browser open"):
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
        except Exception as exc:
            self._log(f"{label} 不可用: {exc}")
            return {"ok": False, "error": "browser_unavailable", "exception": repr(exc)}

        launch_kwargs = {
            "headless": self.browser_mode != "headed",
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}
        launch_kwargs = prepare_playwright_launch_kwargs(launch_kwargs, self.browser_mode, self._log)

        browser = None
        context = None
        result = {"ok": False, "error": "browser_open_unknown"}

        def body_preview(page, limit=1600):
            try:
                return (page.locator("body").inner_text(timeout=3000) or "")[:limit]
            except Exception:
                return ""

        def looks_like_challenge(page, body):
            combined = "\n".join(
                part.lower()
                for part in (
                    body or "",
                    getattr(page, "title", lambda: "")() or "",
                    getattr(page, "url", "") or "",
                )
            )
            return any(
                marker in combined
                for marker in (
                    "just a moment",
                    "cloudflare",
                    "cf-challenge",
                    "/cdn-cgi/challenge-platform/",
                    "checking your browser",
                    "verify you are human",
                )
            )

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**launch_kwargs)
                context = harden_playwright_context(browser.new_context(**self._playwright_context_kwargs()))
                self._add_cookies_to_playwright_context(context, self._cookies_for_playwright(), label)
                page = context.new_page()
                goto_kwargs = {"wait_until": "domcontentloaded", "timeout": 45000}
                if referer:
                    goto_kwargs["referer"] = referer
                page.goto(page_url, **goto_kwargs)
                page.wait_for_timeout(2500)
                body = body_preview(page)
                if looks_like_challenge(page, body):
                    self._log(f"{label} 命中 challenge，等待 clearance")
                    try:
                        page.wait_for_function(
                            "() => !document.body || !/just a moment|cloudflare|verify you are human|checking your browser/i.test(document.body.innerText || '')",
                            timeout=120000,
                        )
                        try:
                            page.wait_for_load_state("networkidle", timeout=15000)
                        except Exception:
                            pass
                        page.wait_for_timeout(2500)
                    except PlaywrightTimeoutError as exc:
                        result = {
                            "ok": False,
                            "error": "challenge_timeout",
                            "exception": repr(exc),
                            "url": page.url,
                            "body": body_preview(page),
                        }
                        return result
                self._sync_playwright_cookies(context.cookies())
                result = {
                    "ok": True,
                    "url": page.url,
                    "title": page.title(),
                    "body": body_preview(page),
                }
                return result
        except Exception as exc:
            result = {"ok": False, "error": "browser_open_exception", "exception": repr(exc)}
            return result
        finally:
            try:
                if context:
                    self._sync_playwright_cookies(context.cookies())
            except Exception:
                pass
            try:
                if browser:
                    browser.close()
            except Exception:
                pass

    def _browser_fetch_same_origin_json(self, page_url, fetch_url, method="GET", headers=None, body=None, referer=None, label="browser fetch"):
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
        except Exception as exc:
            return {"ok": False, "error": "browser_unavailable", "exception": repr(exc)}

        launch_kwargs = {
            "headless": self.browser_mode != "headed",
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}
        launch_kwargs = prepare_playwright_launch_kwargs(launch_kwargs, self.browser_mode, self._log)

        browser = None
        context = None

        def body_preview(page, limit=1600):
            try:
                return (page.locator("body").inner_text(timeout=3000) or "")[:limit]
            except Exception:
                return ""

        def looks_like_challenge(page, body):
            combined = "\n".join(
                part.lower()
                for part in (
                    body or "",
                    getattr(page, "title", lambda: "")() or "",
                    getattr(page, "url", "") or "",
                )
            )
            return any(
                marker in combined
                for marker in (
                    "just a moment",
                    "cloudflare",
                    "cf-challenge",
                    "/cdn-cgi/challenge-platform/",
                    "checking your browser",
                    "verify you are human",
                )
            )

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**launch_kwargs)
                context = harden_playwright_context(browser.new_context(**self._playwright_context_kwargs()))
                self._add_cookies_to_playwright_context(context, self._cookies_for_playwright(), f"{label} fetch")
                page = context.new_page()
                goto_kwargs = {"wait_until": "domcontentloaded", "timeout": 45000}
                if referer:
                    goto_kwargs["referer"] = referer
                page.goto(page_url, **goto_kwargs)
                page.wait_for_timeout(1500)
                body_preview_text = body_preview(page)
                if looks_like_challenge(page, body_preview_text):
                    self._log(f"{label} 命中 challenge，等待 clearance")
                    try:
                        page.wait_for_function(
                            "() => !document.body || !/just a moment|cloudflare|verify you are human|checking your browser/i.test(document.body.innerText || '')",
                            timeout=120000,
                        )
                        try:
                            page.wait_for_load_state("networkidle", timeout=15000)
                        except Exception:
                            pass
                        page.wait_for_timeout(2000)
                    except PlaywrightTimeoutError as exc:
                        return {
                            "ok": False,
                            "error": "challenge_timeout",
                            "exception": repr(exc),
                            "url": page.url,
                            "body": body_preview(page),
                        }
                result = page.evaluate(
                    """
                    async ({ fetchUrl, method, headers, body }) => {
                      const init = {
                        method,
                        credentials: 'include',
                        headers: headers || {},
                      };
                      if (body !== null && body !== undefined) {
                        init.body = body;
                      }
                      const response = await fetch(fetchUrl, init);
                      const text = await response.text();
                      let jsonBody = null;
                      try { jsonBody = JSON.parse(text); } catch (_) {}
                      return {
                        ok: response.ok,
                        status: response.status,
                        url: response.url,
                        text: text.slice(0, 2000),
                        json: jsonBody,
                      };
                    }
                    """,
                    {
                        "fetchUrl": fetch_url,
                        "method": method,
                        "headers": headers or {},
                        "body": body,
                    },
                )
                self._sync_playwright_cookies(context.cookies())
                result["ok"] = bool(result.get("ok"))
                return result
        except Exception as exc:
            return {"ok": False, "error": "browser_fetch_exception", "exception": repr(exc)}
        finally:
            try:
                if context:
                    self._sync_playwright_cookies(context.cookies())
            except Exception:
                pass
            try:
                if browser:
                    browser.close()
            except Exception:
                pass

    def _auth_cookie_snapshot(self):
        snapshot = {
            "count": 0,
            "names": [],
            "has_cf_clearance": False,
            "has_oai_did": False,
            "has_oai_sc": False,
        }
        names = []
        for cookie in self.session.cookies.jar:
            name = str(cookie.name or "").strip()
            domain = str(cookie.domain or "").strip().lower()
            if not name:
                continue
            if "auth.openai.com" in domain or "openai.com" in domain or name in {"oai-did", "cf_clearance"}:
                names.append(name)
        unique_names = sorted(set(names))
        snapshot["count"] = len(unique_names)
        snapshot["names"] = unique_names[:30]
        snapshot["has_cf_clearance"] = "cf_clearance" in unique_names
        snapshot["has_oai_did"] = "oai-did" in unique_names
        snapshot["has_oai_sc"] = "oai-sc" in unique_names
        return snapshot

    def _build_chatgpt_cookie_bundle(self):
        include_names = {
            "__Secure-next-auth.session-token",
            "__Secure-authjs.session-token",
            "__Host-next-auth.csrf-token",
            "__Host-authjs.csrf-token",
            "__Secure-next-auth.callback-url",
            "__Secure-authjs.callback-url",
            "__Secure-next-auth.state",
            "__Secure-authjs.state",
            "cf_clearance",
            "__cf_bm",
            "oai-did",
            "oai-sc",
            "oai-chat-web-route",
        }
        include_domain_markers = (
            "chatgpt.com",
            "auth.openai.com",
            "openai.com",
        )
        merged = {}
        for cookie in list(getattr(self.session.cookies, "jar", []) or []):
            try:
                name = str(cookie.name or "").strip()
                domain = str(cookie.domain or "").strip()
                path = str(cookie.path or "/").strip() or "/"
                value = str(cookie.value or "")
            except Exception:
                continue
            if not name or not value:
                continue
            lowered_domain = domain.lower()
            if name not in include_names and not any(marker in lowered_domain for marker in include_domain_markers):
                continue
            merged[(name, domain, path)] = {
                "name": name,
                "value": value,
                "domain": domain,
                "path": path,
                "secure": bool(getattr(cookie, "secure", False)),
            }

        items = list(merged.values())
        items.sort(key=lambda item: (item["name"], item["domain"], item["path"]))

        header_names = [
            "__Secure-next-auth.session-token",
            "__Secure-authjs.session-token",
            "cf_clearance",
            "__cf_bm",
            "oai-did",
            "oai-sc",
            "oai-chat-web-route",
        ]
        header_parts = []
        seen_header_names = set()
        for name in header_names:
            for item in items:
                if item["name"] != name or item["name"] in seen_header_names:
                    continue
                header_parts.append(f'{item["name"]}={item["value"]}')
                seen_header_names.add(item["name"])
                break

        compact = {}
        for item in items:
            compact.setdefault(item["name"], item["value"])

        return {
            "cookie_header": "; ".join(header_parts),
            "cookie_names": [item["name"] for item in items],
            "cookies": items,
            "compact": compact,
            "cf_clearance": compact.get("cf_clearance", ""),
            "oai_did": compact.get("oai-did", ""),
            "oai_sc": compact.get("oai-sc", ""),
        }

    def _dump_create_account_debug(self, prefix, payload):
        try:
            ts = int(time.time())
            path = Path(f"/tmp/{prefix}_{ts}.json")
            path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            self._log(f"create_account 调试已写出: {path}")
            return str(path)
        except Exception as exc:
            self._log(f"create_account 调试写出失败: {exc}")
            return ""

    def _collect_chatgpt_browser_probe(self, page, context):
        probe = {
            "page_url": "",
            "title": "",
            "body": "",
            "document_cookie": "",
            "local_storage": {},
            "session_storage": {},
            "globals": {},
            "next_data": None,
            "backend_checks": [],
            "context_cookies": [],
        }

        try:
            probe["page_url"] = str(page.url or "")
        except Exception:
            pass
        try:
            probe["title"] = page.title()
        except Exception:
            pass
        try:
            probe["body"] = (page.locator("body").inner_text(timeout=4000) or "")[:4000]
        except Exception as exc:
            probe["body_error"] = repr(exc)
        try:
            browser_state = page.evaluate(
                """
                async () => {
                  const result = {
                    documentCookie: document.cookie || "",
                    localStorage: {},
                    sessionStorage: {},
                    globals: {},
                    nextData: null,
                    backendChecks: [],
                  };

                  try {
                    for (let i = 0; i < localStorage.length; i += 1) {
                      const key = localStorage.key(i);
                      result.localStorage[key] = String(localStorage.getItem(key)).slice(0, 500);
                    }
                  } catch (error) {
                    result.localStorageError = String(error);
                  }

                  try {
                    for (let i = 0; i < sessionStorage.length; i += 1) {
                      const key = sessionStorage.key(i);
                      result.sessionStorage[key] = String(sessionStorage.getItem(key)).slice(0, 500);
                    }
                  } catch (error) {
                    result.sessionStorageError = String(error);
                  }

                  try {
                    const interestingKeys = Object.keys(window)
                      .filter((key) => /auth|token|session|oai|next|chatgpt|access/i.test(key))
                      .slice(0, 200);
                    for (const key of interestingKeys) {
                      try {
                        const value = window[key];
                        if (typeof value === "string") {
                          result.globals[key] = value.slice(0, 500);
                        } else if (value && typeof value === "object") {
                          result.globals[key] = JSON.stringify(value).slice(0, 500);
                        } else {
                          result.globals[key] = String(value).slice(0, 200);
                        }
                      } catch (error) {
                        result.globals[key] = `ERR:${String(error)}`;
                      }
                    }
                  } catch (error) {
                    result.globalsError = String(error);
                  }

                  try {
                    if (typeof window.__NEXT_DATA__ !== "undefined") {
                      result.nextData = JSON.stringify(window.__NEXT_DATA__).slice(0, 4000);
                    }
                  } catch (error) {
                    result.nextDataError = String(error);
                  }

                  for (const url of [
                    "/api/auth/session",
                    "/backend-api/accounts/check/v4-2023-04-27",
                    "/backend-api/accounts/check",
                    "/backend-api/me",
                  ]) {
                    try {
                      const response = await fetch(url, {
                        method: "GET",
                        credentials: "include",
                        headers: {accept: "application/json"},
                      });
                      const text = await response.text();
                      result.backendChecks.push({
                        url,
                        status: response.status,
                        responseUrl: response.url,
                        text: text.slice(0, 800),
                      });
                    } catch (error) {
                      result.backendChecks.push({url, error: String(error)});
                    }
                  }

                  return result;
                }
                """
            )
            probe["document_cookie"] = str(browser_state.get("documentCookie") or "")[:4000]
            probe["local_storage"] = browser_state.get("localStorage") or {}
            probe["session_storage"] = browser_state.get("sessionStorage") or {}
            probe["globals"] = browser_state.get("globals") or {}
            probe["next_data"] = browser_state.get("nextData")
            probe["backend_checks"] = browser_state.get("backendChecks") or []
            for key in (
                "localStorageError",
                "sessionStorageError",
                "globalsError",
                "nextDataError",
            ):
                if browser_state.get(key):
                    probe[key] = browser_state.get(key)
        except Exception as exc:
            probe["browser_state_error"] = repr(exc)

        try:
            raw_cookies = context.cookies()
            filtered = []
            for cookie in raw_cookies:
                name = str(cookie.get("name") or "")
                if any(
                    marker in name
                    for marker in (
                        "next-auth",
                        "auth-session",
                        "manifest",
                        "oai-client-auth",
                        "token",
                    )
                ):
                    filtered.append(
                        {
                            "name": name,
                            "domain": cookie.get("domain"),
                            "path": cookie.get("path"),
                            "secure": cookie.get("secure"),
                            "httpOnly": cookie.get("httpOnly"),
                            "value_prefix": str(cookie.get("value") or "")[:400],
                        }
                    )
            probe["context_cookies"] = filtered
        except Exception as exc:
            probe["context_cookie_error"] = repr(exc)
        return probe

    def _browser_preclear_create_account_challenge(
        self,
        page_url,
        flow="oauth_create_account",
        *,
        submit_payload=None,
        sentinel_token="",
    ):
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
        except Exception as exc:
            return {"ok": False, "error": "browser_unavailable", "exception": repr(exc)}

        launch_kwargs = {
            "headless": self.browser_mode != "headed",
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}
        launch_kwargs = prepare_playwright_launch_kwargs(launch_kwargs, self.browser_mode, self._log)

        def looks_like_challenge(text):
            lowered = (text or "").lower()
            return any(
                marker in lowered
                for marker in (
                    "just a moment",
                    "cf-challenge",
                    "cloudflare",
                    "verify you are human",
                    "checking your browser",
                )
            )

        def browser_fetch_create_account(page, token, payload):
            if not token or not payload:
                return None
            try:
                return page.evaluate(
                    """
                    async ({payload, token, timeoutMs}) => {
                      const controller = new AbortController();
                      const timer = setTimeout(() => controller.abort("timeout"), timeoutMs);
                      try {
                        const response = await fetch("/api/accounts/create_account", {
                          method: "POST",
                          credentials: "include",
                          signal: controller.signal,
                          headers: {
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                            "OpenAI-Sentinel-Token": token
                          },
                          body: JSON.stringify(payload)
                        });
                        const text = await response.text();
                        let jsonBody = null;
                        try { jsonBody = JSON.parse(text); } catch (_) {}
                        return {
                          status: response.status,
                          ok: response.ok,
                          url: response.url,
                          text: text.slice(0, 1200),
                          json: jsonBody,
                          bodyText: (document.body && document.body.innerText) ? document.body.innerText.slice(0, 1600) : ""
                        };
                      } catch (error) {
                        return {
                          error: String(error && error.stack ? error.stack : error),
                          bodyText: (document.body && document.body.innerText) ? document.body.innerText.slice(0, 1600) : ""
                        };
                      } finally {
                        clearTimeout(timer);
                      }
                    }
                    """,
                    {"payload": payload, "token": token, "timeoutMs": 25000},
                )
            except Exception as exc:
                return {"error": repr(exc)}

        result = {"ok": False, "error": "unknown"}
        try:
            with sync_playwright() as playwright:
                browser = None
                context = None
                try:
                    browser = playwright.chromium.launch(**launch_kwargs)
                    context = harden_playwright_context(browser.new_context(**self._playwright_context_kwargs()))
                    cookies = self._cookies_for_playwright()
                    self._add_cookies_to_playwright_context(context, cookies, "browser preclear")
                    page = context.new_page()

                    def body_preview(limit=1600):
                        try:
                            return (page.locator("body").inner_text(timeout=3000) or "")[:limit]
                        except Exception:
                            return ""

                    page.goto(page_url, wait_until="domcontentloaded", timeout=45000)
                    page.wait_for_timeout(2500)
                    title = page.title()
                    body = body_preview()
                    timed_out = False
                    if looks_like_challenge("\n".join((title, body))):
                        self._log("browser preclear 命中 challenge，等待 clearance")
                        try:
                            page.wait_for_function(
                                "() => !document.body || !/just a moment|cloudflare|verify you are human|checking your browser/i.test(document.body.innerText || '')",
                                timeout=120000,
                            )
                            try:
                                page.wait_for_load_state("networkidle", timeout=15000)
                            except Exception:
                                pass
                            page.wait_for_timeout(3000)
                        except PlaywrightTimeoutError as exc:
                            timed_out = True
                            result["error"] = "challenge_timeout"
                            result["exception"] = repr(exc)

                    self._sync_playwright_cookies(context.cookies())
                    body = body_preview()
                    title = page.title()
                    token = str(sentinel_token or "").strip()
                    try:
                        if not token:
                            page.wait_for_function(
                                "() => !!(window.SentinelSDK && typeof window.SentinelSDK.token === 'function')",
                                timeout=45000,
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
                                {"flowName": flow, "timeoutMs": 45000},
                            ) or {}
                            if isinstance(token_result, dict):
                                token = str(token_result.get("token") or "").strip()
                                if not token and token_result.get("error"):
                                    self._log(
                                        "browser preclear sentinel 失败: "
                                        f"{token_result.get('error')} {token_result.get('exception') or ''}".strip()
                                    )
                            else:
                                token = str(token_result or "").strip()
                    except Exception as exc:
                        self._log(f"browser preclear 未补到 sentinel token: {exc}")

                    fetch_result = browser_fetch_create_account(page, token, submit_payload)
                    if isinstance(fetch_result, dict) and fetch_result.get("error"):
                        self._log(f"browser preclear fetch 异常: {fetch_result['error']}")
                    result = {
                        "ok": not looks_like_challenge("\n".join((title, body))),
                        "page_url": page.url,
                        "title": title,
                        "body": body,
                        "token": token,
                        "cookie_snapshot": self._auth_cookie_snapshot(),
                        "fetch_result": fetch_result,
                    }
                    if timed_out:
                        result["ok"] = False
                    result["artifact"] = self._dump_create_account_debug(
                        "create_account_preclear_timeout" if timed_out else "create_account_preclear",
                        result,
                    )
                    return result
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

    def _headers(
        self,
        url,
        *,
        accept,
        referer=None,
        origin=None,
        content_type=None,
        navigation=False,
        fetch_mode=None,
        fetch_dest=None,
        fetch_site=None,
        extra_headers=None,
    ):
        return build_browser_headers(
            url=url,
            user_agent=self.ua,
            sec_ch_ua=self.sec_ch_ua,
            chrome_full_version=self.chrome_full,
            accept=accept,
            accept_language=self.accept_language,
            referer=referer,
            origin=origin,
            content_type=content_type,
            navigation=navigation,
            fetch_mode=fetch_mode,
            fetch_dest=fetch_dest,
            fetch_site=fetch_site,
            headed=self.browser_mode == "headed",
            extra_headers=extra_headers,
        )

    def _reset_session(self):
        """重置浏览器指纹与会话，用于绕过偶发的 Cloudflare/SPA 中间页。"""
        self.device_id = str(uuid.uuid4())
        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = _random_chrome_version()
        self.accept_language = random.choice([
            "en-US,en;q=0.9",
            "en-US,en;q=0.9,zh-CN;q=0.8",
            "en,en-US;q=0.9",
            "en-US,en;q=0.8",
        ])

        self.session = curl_requests.Session(impersonate=self.impersonate)
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}

        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept-Language": self.accept_language,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-ch-ua-arch": '"x86"',
            "sec-ch-ua-bitness": '"64"',
            "sec-ch-ua-full-version": f'"{self.chrome_full}"',
            "sec-ch-ua-platform-version": f'"{random.randint(10, 15)}.0.0"',
        })
        seed_oai_device_cookie(self.session, self.device_id)

    def _state_from_url(self, url, method="GET"):
        state = extract_flow_state(
            current_url=normalize_flow_url(url, auth_base=self.AUTH),
            auth_base=self.AUTH,
            default_method=method,
        )
        if method:
            state.method = str(method).upper()
        return state

    def _state_from_payload(self, data, current_url=""):
        return extract_flow_state(
            data=data,
            current_url=current_url,
            auth_base=self.AUTH,
        )

    def _state_signature(self, state: FlowState):
        return (
            state.page_type or "",
            state.method or "",
            state.continue_url or "",
            state.current_url or "",
        )

    def _is_registration_complete_state(self, state: FlowState):
        current_url = (state.current_url or "").lower()
        continue_url = (state.continue_url or "").lower()
        page_type = state.page_type or ""
        blocked_targets = (
            "chatgpt.com/auth/login_with",
            "chatgpt.com/auth/error",
            "chatgpt.com/api/auth/signin/openai",
        )
        if any(target in current_url for target in blocked_targets):
            return False
        if any(target in continue_url for target in blocked_targets):
            return False
        return (
            page_type in {"callback", "chatgpt_home", "oauth_callback"}
            or ("chatgpt.com" in current_url and "redirect_uri" not in current_url)
            or ("chatgpt.com" in continue_url and "redirect_uri" not in continue_url and page_type != "external_url")
        )

    def _state_is_password_registration(self, state: FlowState):
        return state.page_type in {"create_account_password", "password"}

    def _state_is_login_password(self, state: FlowState):
        return state.page_type == "login_password"

    def _state_is_email_otp(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        return state.page_type == "email_otp_verification" or "email-verification" in target or "email-otp" in target

    def _state_is_about_you(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        return state.page_type == "about_you" or "about-you" in target

    def _state_is_chatgpt_login_with(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        return (
            "chatgpt.com/auth/login_with" in target
            or "chatgpt.com/auth/error" in target
            or "chatgpt.com/api/auth/signin/openai" in target
        )

    def _state_requires_navigation(self, state: FlowState):
        if (state.method or "GET").upper() != "GET":
            return False
        target = f"{state.continue_url} {state.current_url}".lower()
        if "/api/accounts/login" in target and "login_challenge=" in target:
            return True
        if state.page_type == "external_url" and state.continue_url:
            return True
        if state.continue_url and state.continue_url != state.current_url:
            return True
        return False

    def _follow_flow_state(self, state: FlowState, referer=None):
        """跟随服务端返回的 continue_url，推进注册状态机。"""
        target_url = state.continue_url or state.current_url
        if not target_url:
            return False, "缺少可跟随的 continue_url"

        try:
            self._browser_pause()
            r = self.session.get(
                target_url,
                headers=self._headers(
                    target_url,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    referer=referer,
                    navigation=True,
                ),
                allow_redirects=True,
                timeout=30,
            )
            final_url = str(r.url)
            self._log(f"follow -> {r.status_code} {final_url}")

            content_type = (r.headers.get("content-type", "") or "").lower()
            if "application/json" in content_type:
                try:
                    next_state = self._state_from_payload(r.json(), current_url=final_url)
                except Exception:
                    next_state = self._state_from_url(final_url)
            else:
                next_state = self._state_from_url(final_url)

            self._log(f"follow state -> {describe_flow_state(next_state)}")
            return True, next_state
        except Exception as e:
            self._log(f"跟随 continue_url 失败: {e}")
            return False, str(e)

    def _get_cookie_value(self, name, domain_hint=None):
        """读取当前会话中的 Cookie。"""
        for cookie in self.session.cookies.jar:
            if cookie.name != name:
                continue
            if domain_hint and domain_hint not in (cookie.domain or ""):
                continue
            return cookie.value
        return ""

    def get_next_auth_session_token(self):
        """获取 ChatGPT next-auth 会话 Cookie。"""
        return self._get_cookie_value("__Secure-next-auth.session-token", "chatgpt.com")

    def fetch_chatgpt_session(self):
        """请求 ChatGPT Session 接口并返回原始会话数据。"""
        url = f"{self.BASE}/api/auth/session"
        self._browser_pause()
        response = self.session.get(
            url,
            headers=self._headers(
                url,
                accept="application/json",
                referer=f"{self.BASE}/",
                fetch_site="same-origin",
            ),
            timeout=30,
        )
        if response.status_code != 200:
            return False, f"/api/auth/session -> HTTP {response.status_code}"

        try:
            data = response.json()
        except Exception as exc:
            return False, f"/api/auth/session 返回非 JSON: {exc}"

        access_token = (
            str(data.get("accessToken") or "").strip()
            or str(data.get("access_token") or "").strip()
            or str((data.get("session") or {}).get("accessToken") or "").strip()
            or str((data.get("session") or {}).get("access_token") or "").strip()
            or str((data.get("data") or {}).get("accessToken") or "").strip()
            or str((data.get("data") or {}).get("access_token") or "").strip()
        )
        if not access_token:
            self._dump_create_account_debug(
                "chatgpt_session_protocol",
                {
                    "url": str(response.url),
                    "keys": list(data.keys()) if isinstance(data, dict) else [],
                    "data": data,
                    "cookie_snapshot": self._auth_cookie_snapshot(),
                },
            )
            return False, "/api/auth/session 未返回 accessToken"
        return True, data

    def _normalize_chatgpt_session_tokens(self, session_data):
        access_token = (
            str(session_data.get("accessToken") or "").strip()
            or str(session_data.get("access_token") or "").strip()
            or str((session_data.get("session") or {}).get("accessToken") or "").strip()
            or str((session_data.get("session") or {}).get("access_token") or "").strip()
            or str((session_data.get("data") or {}).get("accessToken") or "").strip()
            or str((session_data.get("data") or {}).get("access_token") or "").strip()
        )
        if not access_token:
            return None

        session_token = (
            str(session_data.get("sessionToken") or "").strip()
            or self.get_next_auth_session_token()
        )
        user = session_data.get("user") or {}
        account = session_data.get("account") or {}
        jwt_payload = decode_jwt_payload(access_token)
        auth_payload = jwt_payload.get("https://api.openai.com/auth") or {}
        cookie_bundle = self._build_chatgpt_cookie_bundle()

        account_id = (
            str(account.get("id") or "").strip()
            or str(auth_payload.get("chatgpt_account_id") or "").strip()
        )
        user_id = (
            str(user.get("id") or "").strip()
            or str(auth_payload.get("chatgpt_user_id") or "").strip()
            or str(auth_payload.get("user_id") or "").strip()
        )

        return {
            "access_token": access_token,
            "session_token": session_token,
            "account_id": account_id,
            "user_id": user_id,
            "workspace_id": account_id,
            "expires": session_data.get("expires"),
            "user": user,
            "account": account,
            "auth_provider": session_data.get("authProvider") or "browser_chatgpt_session",
            "cookies": cookie_bundle.get("cookie_header", ""),
            "cookie_bundle": cookie_bundle,
            "cf_clearance": cookie_bundle.get("cf_clearance", ""),
            "oai_did": cookie_bundle.get("oai_did", ""),
            "oai_sc": cookie_bundle.get("oai_sc", ""),
            "raw_session": session_data,
        }

    def _extract_chatgpt_callback_url(self, value):
        candidate = normalize_flow_url(value, auth_base=self.AUTH)
        if not candidate:
            return ""
        try:
            parsed = urlparse(candidate)
        except Exception:
            return ""

        host = (parsed.netloc or "").lower()
        path = (parsed.path or "").lower()
        if "chatgpt.com" not in host or "/api/auth/callback/openai" not in path:
            return ""

        query = parse_qs(parsed.query, keep_blank_values=True)
        code = str((query.get("code") or [""])[0] or "").strip()
        state = str((query.get("state") or [""])[0] or "").strip()
        if code and state:
            return candidate
        return ""

    def _extract_auth_error_retry_url(self, value):
        candidate = normalize_flow_url(value, auth_base=self.AUTH)
        if not candidate:
            return "", {}
        try:
            parsed = urlparse(candidate)
        except Exception:
            return "", {}
        if "auth.openai.com" not in (parsed.netloc or "").lower() or not (parsed.path or "").startswith("/error"):
            return "", {}

        query = parse_qs(parsed.query, keep_blank_values=True)
        payload_raw = str((query.get("payload") or [""])[0] or "").strip()
        payload = {}
        if payload_raw:
            try:
                payload = json.loads(base64.b64decode(unquote(payload_raw) + "===").decode("utf-8"))
            except Exception:
                payload = {}
        retry_url = normalize_flow_url(str(payload.get("retryUrl") or "").strip(), auth_base=self.BASE)
        meta = {
            "kind": str(payload.get("kind") or "").strip(),
            "request_id": str(payload.get("requestId") or "").strip(),
            "error_code": str(payload.get("errorCode") or "").strip(),
            "session_id": str((query.get("session_id") or [""])[0] or "").strip(),
            "verifier_id": str((query.get("verifier_id") or [""])[0] or "").strip(),
        }
        return retry_url, meta

    def _consume_chatgpt_callback_session(self, callback_url, referer=None):
        callback_url = self._extract_chatgpt_callback_url(callback_url)
        if not callback_url:
            return None
        self.last_create_account_callback_url = callback_url

        self._log("检测到 create_account callback/openai，优先直取 ChatGPT session")
        current_url = callback_url
        referer_url = referer or f"{self.AUTH}/about-you"

        for hop in range(3):
            try:
                self._browser_pause()
                response = self.session.get(
                    current_url,
                    headers=self._headers(
                        current_url,
                        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        referer=referer_url,
                        navigation=True,
                    ),
                    allow_redirects=False,
                    timeout=30,
                )
                last_url = str(response.url or current_url)
                self._log(f"callback/openai[{hop + 1}] -> {response.status_code} {last_url}")
            except Exception as exc:
                self._log(f"callback/openai 跟随异常: {exc}")
                return None

            ok, session_or_error = self.fetch_chatgpt_session()
            if ok:
                return self._normalize_chatgpt_session_tokens(session_or_error)

            if response.status_code in (301, 302, 303, 307, 308):
                location = normalize_flow_url(response.headers.get("Location", ""), auth_base=self.BASE)
                if not location:
                    break
                referer_url = last_url or referer_url
                current_url = location
                continue
            break

        return None

    def _chatgpt_web_oauth_config(self):
        return {
            "oauth_client_id": "app_X8zY6vW2pQ9tR3dE7nK1jL5gH",
            "oauth_redirect_uri": "https://chatgpt.com/api/auth/callback/openai",
            "oauth_scope": "openid email profile offline_access model.request model.read organization.read organization.write",
            "oauth_audience": "https://api.openai.com/v1",
            "oauth_extra_authorize_params": {},
        }

    def _browser_hydrate_chatgpt_session(self, target_url=None, skymail_client=None, profile=None):
        def run_browser():
            try:
                from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
            except Exception as exc:
                self._log(f"浏览器 session fallback 不可用: {exc}")
                return None

            launch_kwargs = {
                "headless": self.browser_mode != "headed",
                "args": ["--no-sandbox", "--disable-dev-shm-usage"],
            }
            if self.proxy:
                launch_kwargs["proxy"] = {"server": self.proxy}
            launch_kwargs = prepare_playwright_launch_kwargs(launch_kwargs, self.browser_mode, self._log)

            login_with_url = f"{self.BASE}/auth/login_with"
            signin_bridge_url = (
                f"{self.BASE}/api/auth/signin/openai"
                "?callbackUrl=https%3A%2F%2Fchatgpt.com%2F"
            )
            targets = []
            if target_url:
                targets.append(target_url)
            targets.append(login_with_url)
            targets.append(signin_bridge_url)
            targets.append(f"{self.BASE}/")

            def _body_preview(page, limit=1200):
                try:
                    return (page.locator("body").inner_text(timeout=3000) or "")[:limit]
                except Exception:
                    return ""

            def _html_preview(page, limit=2400):
                try:
                    return page.evaluate(
                        f"() => (document.documentElement ? document.documentElement.outerHTML.slice(0, {limit}) : '')"
                    ) or ""
                except Exception:
                    return ""

            def _looks_like_challenge(body, html):
                lowered = "\n".join(part.lower() for part in (body or "", html or ""))
                return any(
                    marker in lowered
                    for marker in (
                        "just a moment",
                        "cf-challenge",
                        "cloudflare",
                        "/cdn-cgi/challenge-platform/",
                        "__cf$cv$params",
                    )
                )

            def _looks_like_guest_home(body, page_url):
                lowered = "\n".join(part.lower() for part in (body or "", page_url or ""))
                return (
                    "chatgpt.com" in lowered
                    and "log in" in lowered
                    and (
                        "sign up for free" in lowered
                        or "get responses tailored to you" in lowered
                        or "/auth/error" in lowered
                    )
                )

            def _click_guest_login(page):
                selectors = [
                    "button:has-text('Log in')",
                    "a:has-text('Log in')",
                    "button[aria-label='Log in']",
                ]
                for selector in selectors:
                    try:
                        locator = page.locator(selector).first
                        if locator.count() and locator.is_visible(timeout=1000):
                            locator.click(timeout=5000)
                            return True
                    except Exception:
                        continue
                return False

            def _native_nextauth_signin(page):
                email_value = str(getattr(self, "current_email", "") or "").strip()
                if not email_value:
                    return None
                try:
                    return page.evaluate(
                        """
                        async ({ email, deviceId, authSessionLoggingId }) => {
                          try {
                            const csrfResp = await fetch('/api/auth/csrf', {
                              credentials: 'include',
                              headers: { accept: 'application/json, text/plain, */*' },
                            });
                            const csrfText = await csrfResp.text();
                            let csrfData = null;
                            try { csrfData = JSON.parse(csrfText); } catch (_) {}

                            const qs = new URLSearchParams({
                              prompt: 'login',
                              'ext-oai-did': deviceId,
                              auth_session_logging_id: authSessionLoggingId,
                              screen_hint: 'login_or_signup',
                              login_hint: email,
                            });
                            const body = new URLSearchParams({
                              callbackUrl: 'https://chatgpt.com/',
                              csrfToken: (csrfData && csrfData.csrfToken) || '',
                              json: 'true',
                            });
                            const resp = await fetch('/api/auth/signin/openai?' + qs.toString(), {
                              method: 'POST',
                              credentials: 'include',
                              headers: {
                                'content-type': 'application/x-www-form-urlencoded',
                                accept: 'application/json, text/plain, */*',
                              },
                              body,
                            });
                            const text = await resp.text();
                            let data = null;
                            try { data = JSON.parse(text); } catch (_) {}
                            return {
                              csrfStatus: csrfResp.status,
                              status: resp.status,
                              responseUrl: resp.url,
                              data,
                              text: text.slice(0, 600),
                              documentCookie: document.cookie,
                            };
                          } catch (error) {
                            return { error: String(error) };
                          }
                        }
                        """,
                        {
                            "email": email_value,
                            "deviceId": self.device_id,
                            "authSessionLoggingId": str(uuid.uuid4()),
                        },
                    )
                except Exception as exc:
                    self._log(f"浏览器补水 native next-auth signin 异常: {exc}")
                    return None

            def _clear_bridge_error_cookies(context):
                cookie_names = {
                    "error_page_verifier",
                    "__Secure-next-auth.session-token",
                    "next-auth.session-token",
                    "__Secure-next-auth.state",
                    "next-auth.state",
                    "__Secure-next-auth.callback-url",
                    "next-auth.callback-url",
                }
                try:
                    current = list(context.cookies())
                    filtered = [
                        cookie for cookie in current
                        if str(cookie.get("name") or "").strip() not in cookie_names
                    ]
                    context.clear_cookies()
                    if filtered:
                        context.add_cookies(filtered)
                    self._sync_playwright_cookies(filtered)
                    self._purge_cookie_names(cookie_names)
                    self._log(
                        "浏览器补水 session: 已清理 bridge error cookies "
                        f"({','.join(sorted(cookie_names))})"
                    )
                except Exception as exc:
                    self._log(f"浏览器补水 session: 清理 bridge error cookies 失败: {exc}")

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**launch_kwargs)
                try:
                    context = harden_playwright_context(browser.new_context(**self._playwright_context_kwargs()))
                    cookies = self._cookies_for_playwright()
                    self._log(
                        "浏览器补水 session: 注入完整 auth/chatgpt cookie 集 "
                        f"({len(cookies)})"
                    )
                    self._add_cookies_to_playwright_context(context, cookies, "浏览器补水 session")
                    page = context.new_page()

                    for target in targets:
                        guest_login_clicked = False
                        login_with_attempted = False
                        native_signin_attempted = False
                        try:
                            self._log(f"浏览器补水 session: 打开 {target}")
                            page.goto(target, wait_until="domcontentloaded", timeout=45000)
                            page.wait_for_timeout(3500 if "chatgpt.com" in target else 2500)
                        except PlaywrightTimeoutError as exc:
                            self._log(f"浏览器补水打开 {target} 超时: {exc}")
                        except Exception as exc:
                            self._log(f"浏览器补水打开 {target} 异常: {exc}")

                        wait_budget = 12
                        page_url = ""
                        body = _body_preview(page)
                        html = _html_preview(page)
                        if _looks_like_challenge(body, html):
                            wait_budget = 45
                            self._log("浏览器补水 session: 检测到 challenge，延长等待")

                        start_wait = time.time()
                        last_session_error = ""
                        while time.time() - start_wait <= wait_budget:
                            browser_session = None
                            try:
                                page_url = str(page.url or "")
                            except Exception:
                                page_url = ""
                            try:
                                page_host = (urlparse(page_url).netloc or "").lower()
                            except Exception:
                                page_host = ""

                            retry_url, retry_meta = self._extract_auth_error_retry_url(page_url)
                            if retry_url:
                                self._log(
                                    "浏览器补水 session: 命中 auth error，改走 retryUrl "
                                    f"{retry_url[:140]} req={retry_meta.get('request_id')}"
                                )
                                _clear_bridge_error_cookies(context)
                                try:
                                    page.goto(retry_url, wait_until="domcontentloaded", timeout=45000)
                                    page.wait_for_timeout(3500)
                                    self._sync_playwright_cookies(context.cookies())
                                    continue
                                except Exception as exc:
                                    self._log(f"浏览器补水 session: retryUrl 跳转失败: {exc}")

                            if page_host.endswith("chatgpt.com"):
                                try:
                                    browser_session = page.evaluate(
                                        """
                                        async () => {
                                          try {
                                            const response = await fetch("/api/auth/session", {
                                              method: "GET",
                                              credentials: "include",
                                              headers: {"accept": "application/json"},
                                            });
                                            const text = await response.text();
                                            let data = null;
                                            try { data = JSON.parse(text); } catch (_) {}
                                            return {
                                              ok: response.ok,
                                              status: response.status,
                                              url: response.url,
                                              data,
                                              text: text.slice(0, 400),
                                            };
                                          } catch (error) {
                                            return {error: String(error)};
                                          }
                                        }
                                        """
                                    )
                                except Exception as exc:
                                    self._log(f"浏览器补水原生 fetch 异常: {exc}")

                            self._sync_playwright_cookies(context.cookies())
                            if isinstance(browser_session, dict):
                                if browser_session.get("error"):
                                    self._log(f"浏览器补水原生 session 异常: {browser_session['error']}")
                                else:
                                    status = browser_session.get("status")
                                    self._log(
                                        "浏览器补水原生 session -> "
                                        f"HTTP {status} {str(browser_session.get('url') or '')[:120]}"
                                    )
                                    session_data = browser_session.get("data")
                                    if isinstance(session_data, dict):
                                        normalized = self._normalize_chatgpt_session_tokens(session_data)
                                        if normalized:
                                            return normalized
                                        probe = self._collect_chatgpt_browser_probe(page, context)
                                        self._log(
                                            "浏览器补水原生 session keys: "
                                            f"{','.join(list(session_data.keys())[:20])}"
                                        )
                                        self._dump_create_account_debug(
                                            "chatgpt_session_browser",
                                            {
                                                "status": status,
                                                "url": browser_session.get("url"),
                                                "keys": list(session_data.keys()),
                                                "data": session_data,
                                                "cookie_snapshot": self._auth_cookie_snapshot(),
                                                "page_url": page_url,
                                                "probe": probe,
                                            },
                                        )
                                    if browser_session.get("text"):
                                        self._log(
                                            "浏览器补水原生 session body: "
                                            f"{str(browser_session['text'])[:180]}"
                                        )
                            ok, session_or_error = self.fetch_chatgpt_session()
                            if ok:
                                return self._normalize_chatgpt_session_tokens(session_or_error)
                            last_session_error = str(session_or_error)

                            body = _body_preview(page)
                            html = _html_preview(page)
                            if (
                                not guest_login_clicked
                                and _looks_like_guest_home(body, page_url)
                            ):
                                if _click_guest_login(page):
                                    guest_login_clicked = True
                                    self._log("浏览器补水 session: 检测到 guest 首页，改走浏览器原生 Log in 按钮")
                                    try:
                                        page.wait_for_load_state("domcontentloaded", timeout=45000)
                                    except Exception:
                                        pass
                                    page.wait_for_timeout(4000)
                                    self._sync_playwright_cookies(context.cookies())
                                    continue
                            if (
                                not native_signin_attempted
                                and _looks_like_guest_home(body, page_url)
                            ):
                                native_signin_attempted = True
                                _clear_bridge_error_cookies(context)
                                native_result = _native_nextauth_signin(page)
                                if isinstance(native_result, dict):
                                    if native_result.get("error"):
                                        self._log(
                                            "浏览器补水 native next-auth signin 错误: "
                                            f"{native_result['error']}"
                                        )
                                    else:
                                        self._log(
                                            "浏览器补水 native next-auth signin -> "
                                            f"HTTP {native_result.get('status')} {str(native_result.get('responseUrl') or '')[:120]}"
                                        )
                                        data = native_result.get("data")
                                        auth_url = ""
                                        if isinstance(data, dict):
                                            auth_url = str(data.get("url") or "").strip()
                                        if (not auth_url) and native_result.get("text"):
                                            match = re.search(
                                                r"https://auth\\.openai\\.com[^\"'\\s<]+",
                                                native_result["text"],
                                            )
                                            auth_url = match.group(0) if match else ""
                                        if auth_url:
                                            self._log(f"浏览器补水 native next-auth signin: 跳转 {auth_url[:160]}")
                                            self._sync_playwright_cookies(context.cookies())
                                            resumed_ok, resumed_tokens = self._resume_chatgpt_web_authorize_flow(
                                                str(getattr(self, "current_email", "") or "").strip(),
                                                auth_url,
                                                skymail_client=skymail_client,
                                                profile=profile,
                                            )
                                            if resumed_ok and resumed_tokens:
                                                self._log("浏览器补水 native next-auth signin: auth.openai.com 子流程恢复成功")
                                                return resumed_tokens
                                            if resumed_tokens:
                                                self._log(
                                                    "浏览器补水 native next-auth signin: auth.openai.com 子流程未恢复，"
                                                    f"原因={resumed_tokens}"
                                                )
                                            try:
                                                page.goto(auth_url, wait_until="domcontentloaded", timeout=45000)
                                                page.wait_for_timeout(4000)
                                                self._sync_playwright_cookies(context.cookies())
                                                continue
                                            except Exception as exc:
                                                self._log(
                                                    "浏览器补水 native next-auth signin 跳转失败: "
                                                    f"{exc}"
                                                )
                            if (
                                not login_with_attempted
                                and _looks_like_guest_home(body, page_url)
                            ):
                                login_with_attempted = True
                                self._log("浏览器补水 session: guest 首页改走 /auth/login_with")
                                try:
                                    page.goto(login_with_url, wait_until="domcontentloaded", timeout=45000)
                                    page.wait_for_timeout(4000)
                                    self._sync_playwright_cookies(context.cookies())
                                    continue
                                except Exception as exc:
                                    self._log(f"浏览器补水 session: /auth/login_with 跳转失败: {exc}")
                            if not _looks_like_challenge(body, html) and time.time() - start_wait >= 6:
                                break
                            page.wait_for_timeout(3000)

                        self._log(f"浏览器补水 session 未就绪: {last_session_error or 'unknown'}")

                    self._sync_playwright_cookies(context.cookies())
                    return None
                finally:
                    browser.close()

        try:
            browser_timeout = 180
            email_value = str(getattr(self, "current_email", "") or "").lower()
            if email_value.endswith(("@outlook.com", "@hotmail.com", "@live.com")):
                browser_timeout = 900
            with ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(run_browser).result(timeout=browser_timeout)
        except FutureTimeoutError:
            self._log("浏览器补水 session 超时")
            return None
        except Exception as exc:
            self._log(f"浏览器补水 session 异常: {exc}")
            return None

    def reuse_session_and_get_tokens(self):
        """
        复用注册阶段已建立的 ChatGPT 会话，直接读取 Session / AccessToken。

        Returns:
            tuple[bool, dict|str]: 成功时返回标准化 token/session 数据；失败时返回错误信息。
        """
        if self._preloaded_chatgpt_tokens:
            self._log("检测到 create_account same-browser bridge 已恢复 token，直接复用")
            return True, self._preloaded_chatgpt_tokens

        state = self.last_registration_state or FlowState()
        callback_tokens = self._consume_chatgpt_callback_session(
            state.continue_url or state.current_url,
            referer=state.current_url or f"{self.AUTH}/about-you",
        )
        if callback_tokens:
            self._log("通过 callback/openai + /api/auth/session 直接恢复 ChatGPT session")
            return True, callback_tokens

        self._log("步骤 1/4: 跟随注册回调 external_url ...")
        if state.page_type == "external_url" or self._state_requires_navigation(state):
            ok, followed = self._follow_flow_state(
                state,
                referer=state.current_url or f"{self.AUTH}/about-you",
            )
            if not ok:
                return False, f"注册回调落地失败: {followed}"
            self.last_registration_state = followed
            callback_tokens = self._consume_chatgpt_callback_session(
                followed.continue_url or followed.current_url,
                referer=state.current_url or f"{self.AUTH}/about-you",
            )
            if callback_tokens:
                self._log("通过 follow 后的 callback/openai 直接恢复 ChatGPT session")
                return True, callback_tokens
        else:
            self._log("注册回调已落地，跳过额外跟随")

        self._log("步骤 2/4: 检查 __Secure-next-auth.session-token ...")
        session_cookie = self.get_next_auth_session_token()
        if not session_cookie:
            self._log("缺少 next-auth cookie，尝试浏览器补水 ChatGPT session ...")
            hydrated = self._browser_hydrate_chatgpt_session(
                target_url=state.current_url or state.continue_url or f"{self.BASE}/",
            )
            if hydrated:
                self._log("浏览器补水成功，已恢复 ChatGPT session")
                return True, hydrated
            return False, "缺少 __Secure-next-auth.session-token，注册回调可能未落地"

        self._log("步骤 3/4: 请求 ChatGPT /api/auth/session ...")
        ok, session_or_error = self.fetch_chatgpt_session()
        if not ok:
            self._log(f"直接请求 ChatGPT session 失败，尝试浏览器补水: {session_or_error}")
            hydrated = self._browser_hydrate_chatgpt_session(
                target_url=state.current_url or state.continue_url or f"{self.BASE}/",
            )
            if hydrated:
                self._log("浏览器补水成功，已恢复 ChatGPT session")
                return True, hydrated
            return False, session_or_error

        session_data = session_or_error
        normalized = self._normalize_chatgpt_session_tokens(session_data)
        if not normalized:
            return False, "/api/auth/session 未返回 accessToken"

        self._log("步骤 4/4: 已从复用会话中提取 accessToken")
        if normalized.get("account_id"):
            self._log(f"Session Account ID: {normalized['account_id']}")
        if normalized.get("user_id"):
            self._log(f"Session User ID: {normalized['user_id']}")
        return True, normalized

    def _resume_chatgpt_web_authorize_flow(self, email, final_url, skymail_client=None, profile=None):
        """继续处理 ChatGPT Web next-auth 触发出来的 auth.openai.com 子流程。"""
        from .oauth_client import OAuthClient

        oauth_client = OAuthClient(
            self._chatgpt_web_oauth_config(),
            proxy=self.proxy,
            verbose=False,
            browser_mode=self.browser_mode,
            session=self.session,
        )
        oauth_client._log = self._log
        oauth_client.current_email = email or ""
        oauth_client.current_password = str(getattr(self, "current_password", "") or "")
        oauth_client.current_device_id = self.device_id
        oauth_client.current_profile = dict(profile or {})
        oauth_client.current_skymail_client = skymail_client
        oauth_client.current_chatgpt_authorize_url = (
            str(final_url or "").strip()
            if any(
                marker in str(final_url or "").lower()
                for marker in ("/api/accounts/authorize", "/oauth/authorize", "/api/oauth/oauth2/auth")
            )
            else ""
        )
        authorize_reentry_used = 0

        state = oauth_client._state_from_url(final_url)
        referer = f"{self.BASE}/api/auth/signin/openai"

        for _ in range(12):
            current_target = str(state.continue_url or state.current_url or "").strip()
            if any(
                marker in current_target.lower()
                for marker in ("/api/accounts/authorize", "/oauth/authorize", "/api/oauth/oauth2/auth")
            ):
                oauth_client.current_chatgpt_authorize_url = current_target
            callback_tokens = oauth_client._try_chatgpt_callback_session_from_state(
                state,
                user_agent=self.ua,
                impersonate=self.impersonate,
                referer=referer,
            )
            if callback_tokens:
                return True, callback_tokens

            retry_url, retry_meta = oauth_client._extract_auth_error_retry_url(
                current_target or str(state.current_url or "").strip()
            )
            if retry_url:
                self._log(
                    "ChatGPT Web bridge 命中 auth error，改走 retryUrl "
                    f"{retry_url[:140]} req={retry_meta.get('request_id')}"
                )
                referer = state.current_url or state.continue_url or referer
                state = oauth_client._state_from_url(retry_url)
                continue

            ok, session_or_error = self.fetch_chatgpt_session()
            if ok:
                normalized = self._normalize_chatgpt_session_tokens(session_or_error)
                if normalized:
                    return True, normalized

            if oauth_client._state_is_email_otp(state):
                next_state = None
                password_value = str(getattr(self, "current_password", "") or "").strip()
                if skymail_client:
                    self._log("ChatGPT Web bridge 命中 email-verification，优先尝试邮箱 OTP")
                    next_state = oauth_client._handle_otp_verification(
                        email,
                        self.device_id,
                        self.ua,
                        self.sec_ch_ua,
                        self.impersonate,
                        skymail_client,
                        state,
                    )
                if not next_state and password_value:
                    self._log("ChatGPT Web bridge email-verification 改走旧密码回退")
                    next_state = oauth_client._submit_password_verify(
                        password_value,
                        self.device_id,
                        user_agent=self.ua,
                        sec_ch_ua=self.sec_ch_ua,
                        impersonate=self.impersonate,
                        referer=state.current_url or state.continue_url or referer,
                    )
                if not next_state:
                    return False, "ChatGPT Web bridge OTP/密码恢复失败"
                referer = state.current_url or state.continue_url or referer
                state = next_state
                continue

            if oauth_client._state_is_login_password(state):
                password_value = str(getattr(self, "current_password", "") or "").strip()
                if not password_value:
                    return False, "ChatGPT Web bridge 进入 login_password，但当前没有可用密码"
                self._log("ChatGPT Web bridge 进入 login_password，尝试密码回退")
                next_state = oauth_client._submit_password_verify(
                    password_value,
                    self.device_id,
                    user_agent=self.ua,
                    sec_ch_ua=self.sec_ch_ua,
                    impersonate=self.impersonate,
                    referer=state.current_url or state.continue_url or referer,
                )
                if not next_state:
                    return False, "ChatGPT Web bridge 密码回退失败"
                referer = state.current_url or state.continue_url or referer
                state = next_state
                continue

            if oauth_client._state_is_about_you(state):
                if not profile or not profile.get("birthdate"):
                    return False, "ChatGPT Web bridge 需要 about_you profile"
                next_state = oauth_client._submit_about_you(
                    profile.get("first_name", ""),
                    profile.get("last_name", ""),
                    profile.get("birthdate", ""),
                    self.device_id,
                    user_agent=self.ua,
                    sec_ch_ua=self.sec_ch_ua,
                    impersonate=self.impersonate,
                    referer=state.current_url or state.continue_url or referer,
                )
                if not next_state:
                    return False, "ChatGPT Web bridge about_you 提交失败"
                if isinstance(next_state, dict) and next_state.get("access_token"):
                    return True, next_state
                reentry_target = str(getattr(oauth_client, "current_chatgpt_authorize_url", "") or "").strip()
                next_target = str(next_state.continue_url or next_state.current_url or "").strip().lower()
                if (
                    reentry_target
                    and authorize_reentry_used < 2
                    and (
                        "chatgpt.com/auth/login_with" in next_target
                        or "chatgpt.com/auth/error" in next_target
                    )
                ):
                    authorize_reentry_used += 1
                    self._log("ChatGPT Web bridge about_you 命中 existing-account，优先回放原始 authorize URL")
                    referer = state.current_url or state.continue_url or referer
                    state = oauth_client._state_from_url(reentry_target)
                    continue
                referer = state.current_url or state.continue_url or referer
                state = next_state
                continue

            if oauth_client._state_supports_workspace_resolution(state):
                code, next_state = oauth_client._resolve_consent_state(
                    state,
                    referer=referer,
                    device_id=self.device_id,
                    user_agent=self.ua,
                    sec_ch_ua=self.sec_ch_ua,
                    impersonate=self.impersonate,
                )
                if code:
                    # ChatGPT Web flow 的 callback/openai code 会在后续 callback/session 路径中消费；
                    # 这里只负责把状态推进到 callback/openai 或直接可读 session。
                    derived_state = oauth_client._state_from_url(
                        f"{self.BASE}/api/auth/callback/openai?code={code}"
                    )
                    callback_tokens = oauth_client._try_chatgpt_callback_session_from_state(
                        derived_state,
                        user_agent=self.ua,
                        impersonate=self.impersonate,
                        referer=referer,
                    )
                    if callback_tokens:
                        return True, callback_tokens
                if not next_state:
                    return False, "ChatGPT Web bridge consent/workspace 解析失败"
                referer = state.current_url or state.continue_url or referer
                state = next_state
                continue

            if oauth_client._state_requires_navigation(state):
                _, next_state = oauth_client._follow_flow_state(
                    state,
                    referer=referer,
                    user_agent=self.ua,
                    impersonate=self.impersonate,
                )
                if not next_state:
                    return False, "ChatGPT Web bridge follow 失败"
                referer = state.current_url or state.continue_url or referer
                state = next_state
                continue

            return False, f"ChatGPT Web bridge 未支持的状态: {describe_flow_state(state)}"

        return False, "ChatGPT Web bridge 状态机超出最大步数"

    def bridge_existing_auth_to_web_session(self, email, skymail_client=None, profile=None):
        """
        当 auth.openai.com 侧已经完成 existing-account 认证，但 codex consent 不给
        workspace / next-auth 时，主动走一次 ChatGPT Web next-auth 登录桥接。

        Returns:
            tuple[bool, dict|str]: 成功时返回标准化 token/session 数据；失败时返回错误信息。
        """
        self._log("尝试通过 ChatGPT Web signin/openai 桥接现有 auth 会话 ...")
        self.current_email = email or self.current_email

        browser_tokens = self._browser_hydrate_chatgpt_session(
            target_url=f"{self.BASE}/auth/login_with",
            skymail_client=skymail_client,
            profile=profile,
        )
        if browser_tokens:
            self._log("ChatGPT web bridge 已通过同浏览器 next-auth 恢复 session")
            return True, browser_tokens
        return False, "ChatGPT web 同浏览器 bridge 未直接恢复 session"
    
    def visit_homepage(self):
        """访问首页，建立 session"""
        self._log("访问 ChatGPT 首页...")
        url = f"{self.BASE}/"
        try:
            self._browser_pause()
            r = self.session.get(
                url,
                headers=self._headers(
                    url,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    navigation=True,
                ),
                allow_redirects=True,
                timeout=30,
            )
            if r.status_code == 200:
                return True
            self._log(f"访问首页返回异常状态，尝试浏览器 fallback: {r.status_code}")
        except Exception as e:
            self._log(f"访问首页失败: {e}")
        browser_result = self._browser_open_url_and_sync(url, label="homepage fallback")
        if browser_result.get("ok"):
            self._log(f"访问首页浏览器 fallback 成功: {browser_result.get('url')}")
            return True
        self._log(f"访问首页浏览器 fallback 失败: {browser_result.get('error') or browser_result.get('exception')}")
        return False
    
    def get_csrf_token(self):
        """获取 CSRF token"""
        self._log("获取 CSRF token...")
        url = f"{self.BASE}/api/auth/csrf"
        try:
            r = self.session.get(
                url,
                headers=self._headers(
                    url,
                    accept="application/json",
                    referer=f"{self.BASE}/",
                    fetch_site="same-origin",
                ),
                timeout=30,
            )
            
            if r.status_code == 200:
                data = r.json()
                token = data.get("csrfToken", "")
                if token:
                    self._log(f"CSRF token: {token[:20]}...")
                    return token
        except Exception as e:
            self._log(f"获取 CSRF token 失败: {e}")
        browser_result = self._browser_fetch_same_origin_json(
            f"{self.BASE}/",
            "/api/auth/csrf",
            method="GET",
            headers={"accept": "application/json"},
            referer=f"{self.BASE}/",
            label="csrf fallback",
        )
        data = browser_result.get("json") or {}
        token = str(data.get("csrfToken") or "").strip()
        if token:
            self._log(f"CSRF token(browser): {token[:20]}...")
            return token
        self._log(f"获取 CSRF token 浏览器 fallback 失败: {browser_result.get('error') or browser_result.get('status')}")
        return None
    
    def signin(self, email, csrf_token, callback_url=None):
        """
        提交邮箱，获取 authorize URL
        
        Returns:
            str: authorize URL
        """
        self._log(f"提交邮箱: {email}")
        url = f"{self.BASE}/api/auth/signin/openai"
        
        params = {
            "prompt": "login",
            "ext-oai-did": self.device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "screen_hint": "login_or_signup",
            "login_hint": email,
        }
        
        form_data = {
            "callbackUrl": callback_url or f"{self.BASE}/",
            "csrfToken": csrf_token,
            "json": "true",
        }

        try:
            self._browser_pause()
            r = self.session.post(
                url,
                params=params,
                data=form_data,
                headers=self._headers(
                    url,
                    accept="application/json",
                    referer=f"{self.BASE}/",
                    origin=self.BASE,
                    content_type="application/x-www-form-urlencoded",
                    fetch_site="same-origin",
                ),
                timeout=30
            )
            
            if r.status_code == 200:
                data = r.json()
                authorize_url = data.get("url", "")
                if authorize_url:
                    self._log(f"获取到 authorize URL")
                    return authorize_url
        except Exception as e:
            self._log(f"提交邮箱失败: {e}")
        browser_result = self._browser_fetch_same_origin_json(
            f"{self.BASE}/",
            f"/api/auth/signin/openai?{urlencode(params)}",
            method="POST",
            headers={
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded",
            },
            body=urlencode(form_data),
            referer=f"{self.BASE}/",
            label="signin fallback",
        )
        data = browser_result.get("json") or {}
        authorize_url = str(data.get("url") or "").strip()
        if authorize_url:
            self._log("获取到 authorize URL(browser)")
            return authorize_url
        self._log(f"提交邮箱浏览器 fallback 失败: {browser_result.get('error') or browser_result.get('status')}")
        return None
    
    def authorize(self, url, max_retries=3):
        """
        访问 authorize URL，跟随重定向（带重试机制）
        这是关键步骤，建立 auth.openai.com 的 session
        
        Returns:
            str: 最终重定向的 URL
        """
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    self._log(f"访问 authorize URL... (尝试 {attempt + 1}/{max_retries})")
                    time.sleep(1)  # 重试前等待
                else:
                    self._log("访问 authorize URL...")

                self._browser_pause()
                r = self.session.get(
                    url,
                    headers=self._headers(
                        url,
                        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        referer=f"{self.BASE}/",
                        navigation=True,
                    ),
                    allow_redirects=True,
                    timeout=30,
                )
                
                final_url = str(r.url)
                self._log(f"重定向到: {final_url}")
                return final_url
                
            except Exception as e:
                error_msg = str(e)
                is_tls_error = "TLS" in error_msg or "SSL" in error_msg or "curl: (35)" in error_msg
                
                if is_tls_error and attempt < max_retries - 1:
                    self._log(f"Authorize TLS 错误 (尝试 {attempt + 1}/{max_retries}): {error_msg[:100]}")
                    continue
                else:
                    self._log(f"Authorize 失败，尝试浏览器 fallback: {e}")
                    browser_result = self._browser_open_url_and_sync(
                        url,
                        referer=f"{self.BASE}/",
                        label="authorize fallback",
                    )
                    if browser_result.get("ok") and browser_result.get("url"):
                        final_url = str(browser_result.get("url") or "")
                        self._log(f"浏览器 authorize 成功 -> {final_url}")
                        return final_url
                    self._log(
                        f"Authorize 浏览器 fallback 失败: "
                        f"{browser_result.get('error') or browser_result.get('exception')}"
                    )
                    return ""
        
        return ""
    
    def callback(self, callback_url=None, referer=None):
        """完成注册回调"""
        self._log("执行回调...")
        url = callback_url or f"{self.AUTH}/api/accounts/authorize/callback"
        ok, _ = self._follow_flow_state(
            self._state_from_url(url),
            referer=referer or f"{self.AUTH}/about-you",
        )
        return ok
    
    def register_user(self, email, password):
        """
        注册用户（邮箱 + 密码）
        
        Returns:
            tuple: (success, message)
        """
        self._log(f"注册用户: {email}")
        url = f"{self.AUTH}/api/accounts/user/register"
        
        payload = {
            "username": email,
            "password": password,
        }

        def protocol_submit(token_override=None):
            headers = self._headers(
                url,
                accept="application/json",
                referer=f"{self.AUTH}/create-account/password",
                origin=self.AUTH,
                content_type="application/json",
                fetch_site="same-origin",
            )
            headers.update(generate_datadog_trace())
            if token_override:
                headers["openai-sentinel-token"] = token_override
                headers["ext-passkey-client-capabilities"] = "{}"
            self._browser_pause()
            return self.session.post(url, json=payload, headers=headers, timeout=30)

        sentinel_token = self._mint_browser_sentinel_token(
            f"{self.AUTH}/create-account/password",
            "username_password_create",
        )
        browser_sentinel_used = bool(sentinel_token)
        if not sentinel_token:
            sentinel_token = build_sentinel_token(
                self.session,
                self.device_id,
                flow="username_password_create",
                user_agent=self.ua,
                sec_ch_ua=self.sec_ch_ua,
                impersonate=self.impersonate,
            )
        if sentinel_token:
            if browser_sentinel_used:
                self._log("register_user: 已生成 browser sentinel token")
            else:
                self._log("register_user: 已生成 protocol sentinel token")
        else:
            self._log("register_user: 未生成 sentinel token，降级继续请求")
        
        try:
            r = protocol_submit(sentinel_token)
            if r.status_code in {400, 403} and not browser_sentinel_used:
                browser_retry_token = self._mint_browser_sentinel_token(
                    f"{self.AUTH}/create-account/password",
                    "username_password_create",
                )
                if browser_retry_token:
                    self._log("register_user: 协议 sentinel 失败后改用 browser sentinel 重试一次")
                    sentinel_token = browser_retry_token
                    browser_sentinel_used = True
                    r = protocol_submit(sentinel_token)
            
            if r.status_code == 200:
                data = r.json()
                self._log("注册成功")
                return True, "注册成功"
            else:
                header_debug = {
                    key: value
                    for key, value in r.headers.items()
                    if key.lower() in {
                        "content-type",
                        "cf-ray",
                        "cf-cache-status",
                        "openai-processing-ms",
                        "x-request-id",
                        "x-openai-public-ip",
                    }
                }
                try:
                    error_data = r.json()
                    error_msg = error_data.get("error", {}).get("message", r.text[:200])
                    self._log(f"注册失败响应 JSON: {error_data}")
                except:
                    error_msg = r.text[:200]
                if header_debug:
                    self._log(f"注册失败响应头: {header_debug}")
                body_preview = (r.text or "")[:500]
                if body_preview:
                    self._log(f"注册失败原始响应: {body_preview}")
                if r.status_code in {400, 403}:
                    self._log(f"register_user 协议提交失败，尝试浏览器 fallback: {r.status_code}")
                    browser_result = self._register_user_browser_fallback(email, password)
                    browser_error = browser_result.get("error") or ""
                    browser_status = browser_result.get("status")
                    browser_text = str(browser_result.get("text") or browser_result.get("body") or "")[:200]
                    if browser_result.get("ok"):
                        next_state = browser_result.get("state")
                        if next_state:
                            self.last_registration_state = next_state
                            self._log(f"browser register_user 成功 {describe_flow_state(next_state)}")
                        else:
                            self._log("browser register_user 成功")
                        return True, "注册成功"
                    if browser_status:
                        self._log(f"browser register_user 失败: {browser_status} - {browser_text}")
                    elif browser_error:
                        detail = browser_result.get("exception") or browser_result.get("page_url") or ""
                        suffix = f" ({detail})" if detail else ""
                        self._log(f"browser register_user 失败: {browser_error}{suffix}")
                self._log(f"注册失败: {r.status_code} - {error_msg}")
                return False, f"HTTP {r.status_code}: {error_msg}"
                
        except Exception as e:
            self._log(f"注册异常: {e}")
            self._log("register_user 传输异常，尝试浏览器 fallback")
            browser_result = self._register_user_browser_fallback(email, password)
            browser_error = browser_result.get("error") or ""
            browser_status = browser_result.get("status")
            browser_text = str(browser_result.get("text") or browser_result.get("body") or "")[:200]
            if browser_result.get("ok"):
                next_state = browser_result.get("state")
                if next_state:
                    self.last_registration_state = next_state
                    self._log(f"browser register_user 成功 {describe_flow_state(next_state)}")
                else:
                    self._log("browser register_user 成功")
                return True, "注册成功"
            if browser_status:
                self._log(f"browser register_user 失败: {browser_status} - {browser_text}")
            elif browser_error:
                detail = browser_result.get("exception") or browser_result.get("page_url") or ""
                suffix = f" ({detail})" if detail else ""
                self._log(f"browser register_user 失败: {browser_error}{suffix}")
            return False, str(e)

    def _register_user_browser_fallback(self, email, password):
        launch_kwargs = {
            "headless": self.browser_mode != "headed",
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}
        launch_kwargs = prepare_playwright_launch_kwargs(launch_kwargs, self.browser_mode, self._log)
        browser_timeout = 210
        context_kwargs = self._playwright_context_kwargs()
        cookies = self._cookies_for_playwright()

        def run_browser():
            try:
                from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
            except Exception as exc:
                self._log(f"register_user 浏览器 fallback 不可用: {exc}")
                return {"ok": False, "error": "browser_fallback_unavailable"}

            result = {"ok": False, "error": "browser_fallback_unknown"}
            browser = None
            context = None

            def _header_subset(headers):
                keep = {
                    "accept",
                    "content-type",
                    "origin",
                    "referer",
                    "openai-sentinel-token",
                    "sec-fetch-dest",
                    "sec-fetch-mode",
                    "sec-fetch-site",
                    "sec-fetch-user",
                    "cf-ray",
                    "cf-mitigated",
                    "location",
                    "set-cookie",
                }
                subset = {}
                for key, value in (headers or {}).items():
                    key_lower = str(key).lower()
                    if key_lower in keep:
                        subset[key_lower] = str(value)[:800]
                return subset

            try:
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(**launch_kwargs)
                    context = harden_playwright_context(browser.new_context(**context_kwargs))
                    self._add_cookies_to_playwright_context(context, cookies, "register_user browser fallback")
                    page = context.new_page()
                    network_events = []

                    def _record_network(event):
                        network_events.append(event)
                        if len(network_events) > 80:
                            del network_events[:-80]

                    def _on_request(request):
                        url = str(request.url or "")
                        if (
                            "/api/accounts/user/register" not in url
                            and "/cdn-cgi/challenge-platform/" not in url
                            and "challenge-platform" not in url
                        ):
                            return
                        try:
                            post_data = request.post_data
                        except Exception:
                            post_data = ""
                        _record_network(
                            {
                                "type": "request",
                                "method": request.method,
                                "url": url,
                                "resource_type": request.resource_type,
                                "headers": _header_subset(request.headers),
                                "post_data": str(post_data or "")[:2000],
                            }
                        )

                    def _on_response(response):
                        url = str(response.url or "")
                        if (
                            "/api/accounts/user/register" not in url
                            and "/cdn-cgi/challenge-platform/" not in url
                            and "challenge-platform" not in url
                        ):
                            return
                        try:
                            body = response.text()
                        except Exception:
                            body = ""
                        _record_network(
                            {
                                "type": "response",
                                "status": response.status,
                                "url": url,
                                "headers": _header_subset(response.headers),
                                "body": str(body or "")[:2000],
                            }
                        )

                    page.on("request", _on_request)
                    page.on("response", _on_response)
                    page.goto(f"{self.AUTH}/create-account/password", wait_until="domcontentloaded", timeout=45000)
                    page.wait_for_timeout(2500)

                    def _body_preview(limit=1600):
                        try:
                            return (page.locator("body").inner_text(timeout=3000) or "")[:limit]
                        except Exception:
                            return ""

                    def _looks_like_challenge(text):
                        lowered = (text or "").lower()
                        return any(marker in lowered for marker in ("just a moment", "cf-challenge", "cloudflare"))

                    response = None
                    password_input = page.locator('input[type="password"], input[name="password"]').first
                    for wait_attempt in range(2):
                        try:
                            password_input.wait_for(state="visible", timeout=10000)
                            break
                        except PlaywrightTimeoutError:
                            body = _body_preview(1200)
                            if _looks_like_challenge(body) and wait_attempt == 0:
                                self._log("register_user browser fallback 命中 challenge，等待 clearance 后重试")
                                page.wait_for_function(
                                    "() => !document.body || !/just a moment|cloudflare/i.test(document.body.innerText || '')",
                                    timeout=120000,
                                )
                                try:
                                    page.wait_for_load_state("networkidle", timeout=15000)
                                except Exception:
                                    pass
                                page.wait_for_timeout(3000)
                                self._sync_playwright_cookies(context.cookies())
                                continue
                            raise
                    password_input.fill(password, timeout=5000)
                    try:
                        password_input.press("Tab")
                    except Exception:
                        pass
                    page.wait_for_timeout(500)

                    email_input = page.locator('input[type="email"], input[name="email"], input[name="username"]').first
                    try:
                        if email_input.is_visible(timeout=1000):
                            email_input.fill(email, timeout=5000)
                            page.wait_for_timeout(300)
                    except Exception:
                        pass

                    try:
                        page.wait_for_function(
                            "() => !!(window.SentinelSDK && typeof window.SentinelSDK.token === 'function')",
                            timeout=30000,
                        )
                    except Exception:
                        pass

                    fetch_result = None
                    try:
                        browser_token = page.evaluate(
                            """
                            async () => {
                              try {
                                return await window.SentinelSDK.token("username_password_create");
                              } catch (error) {
                                return "";
                              }
                            }
                            """
                        )
                    except Exception as exc:
                        browser_token = ""
                        self._log(f"register_user 浏览器 fetch 未拿到 sentinel token: {exc}")

                    if browser_token:
                        try:
                            fetch_result = page.evaluate(
                                """
                                async ({ email, password, token }) => {
                                  try {
                                    const response = await fetch("/api/accounts/user/register", {
                                      method: "POST",
                                      credentials: "include",
                                      headers: {
                                        "Accept": "application/json",
                                        "Content-Type": "application/json",
                                        "OpenAI-Sentinel-Token": token,
                                        "ext-passkey-client-capabilities": "{}"
                                      },
                                      body: JSON.stringify({ username: email, password })
                                    });
                                    const text = await response.text();
                                    let jsonBody = null;
                                    try {
                                      jsonBody = JSON.parse(text);
                                    } catch (_) {}
                                    return {
                                      status: response.status,
                                      ok: response.ok,
                                      url: response.url,
                                      text: text.slice(0, 1200),
                                      json: jsonBody,
                                      headers: Object.fromEntries(
                                        Array.from(response.headers.entries()).filter(
                                          ([key]) => [
                                            "content-type",
                                            "cf-ray",
                                            "cf-cache-status",
                                            "openai-processing-ms",
                                            "x-request-id",
                                            "x-openai-public-ip",
                                          ].includes(String(key || "").toLowerCase())
                                        )
                                      ),
                                      pageUrl: window.location.href,
                                      bodyText: (document.body && document.body.innerText)
                                        ? document.body.innerText.slice(0, 1600)
                                        : "",
                                      documentCookie: document.cookie.slice(0, 2400),
                                    };
                                  } catch (error) {
                                    return { error: String(error) };
                                  }
                                }
                                """,
                                {"email": email, "password": password, "token": browser_token},
                            )
                        except Exception as exc:
                            fetch_result = {"error": repr(exc)}

                    if isinstance(fetch_result, dict):
                        if fetch_result.get("error"):
                            self._log(f"register_user 浏览器 fetch 异常: {fetch_result['error']}")
                        else:
                            fetch_status = fetch_result.get("status")
                            fetch_text = str(fetch_result.get("text") or "")[:1200]
                            fetch_body = str(fetch_result.get("bodyText") or "")[:1600]
                            fetch_page_url = str(fetch_result.get("pageUrl") or page.url or "")
                            self._log(
                                "register_user 浏览器 fetch -> "
                                f"status={fetch_status} url={fetch_page_url[:140]}"
                            )
                            lowered_fetch = "\n".join((fetch_text, fetch_body)).lower()
                            if fetch_status == 200:
                                data = fetch_result.get("json") or {}
                                state = self._state_from_payload(data, current_url=fetch_page_url)
                                if not state.page_type:
                                    state = self._state_from_url(fetch_page_url)
                                result = {
                                    "ok": True,
                                    "status": fetch_status,
                                    "text": fetch_text,
                                    "page_url": fetch_page_url,
                                    "body": fetch_body,
                                    "state": state,
                                    "headers": fetch_result.get("headers") or {},
                                    "document_cookie": fetch_result.get("documentCookie") or "",
                                }
                                self._sync_playwright_cookies(context.cookies())
                                browser.close()
                                return result
                            if any(
                                marker in lowered_fetch
                                for marker in ("user_already_exists", "already exists", "already exists for this email")
                            ):
                                result = {
                                    "ok": False,
                                    "status": fetch_status,
                                    "text": fetch_text,
                                    "page_url": fetch_page_url,
                                    "body": fetch_body,
                                    "error": "user_already_exists",
                                    "headers": fetch_result.get("headers") or {},
                                    "document_cookie": fetch_result.get("documentCookie") or "",
                                }
                                self._sync_playwright_cookies(context.cookies())
                                browser.close()
                                return result
                            if "registration_disallowed" in lowered_fetch or "failed to create account" in lowered_fetch:
                                result["fetch_error"] = "registration_disallowed"
                                result["fetch_status"] = fetch_status
                                result["fetch_text"] = fetch_text
                                result["fetch_headers"] = fetch_result.get("headers") or {}
                                result["fetch_page_url"] = fetch_page_url
                            elif fetch_status == 403 and any(
                                marker in lowered_fetch
                                for marker in ("just a moment", "cf-challenge", "cloudflare")
                            ):
                                self._log("register_user 浏览器 fetch 收到 403 challenge，继续尝试页面提交流程")
                                result["fetch_error"] = "cloudflare_challenge"
                                result["fetch_status"] = fetch_status
                                result["fetch_text"] = fetch_text
                                result["fetch_headers"] = fetch_result.get("headers") or {}
                                result["fetch_page_url"] = fetch_page_url
                            elif fetch_status and fetch_status != 200:
                                preview = fetch_text or fetch_body
                                if preview:
                                    self._log(f"register_user 浏览器 fetch body: {preview[:240]}")
                                result["fetch_status"] = fetch_status
                                result["fetch_text"] = fetch_text
                                result["fetch_headers"] = fetch_result.get("headers") or {}
                                result["fetch_page_url"] = fetch_page_url

                    submit = page.get_by_role("button", name="Continue")
                    try:
                        submit.wait_for(state="visible", timeout=5000)
                    except PlaywrightTimeoutError:
                        submit = page.get_by_role("button", name="继续")
                        try:
                            submit.wait_for(state="visible", timeout=3000)
                        except PlaywrightTimeoutError as exc:
                            result = {
                                "ok": False,
                                "error": "browser_submit_missing",
                                "exception": repr(exc),
                                "page_url": page.url,
                                "body": (page.locator("body").inner_text(timeout=3000) or "")[:1600],
                                "buttons": page.locator("button").all_inner_texts()[:12],
                            }
                            self._sync_playwright_cookies(context.cookies())
                            browser.close()
                            return result
                    try:
                        with page.expect_response(
                            lambda resp: "/api/accounts/user/register" in resp.url,
                            timeout=15000,
                        ) as response_info:
                            submit.click(timeout=5000)
                        response = response_info.value
                    except PlaywrightTimeoutError as exc:
                        result = {
                            "ok": False,
                            "error": "browser_submit_timeout",
                            "exception": repr(exc),
                            "page_url": page.url,
                            "body": (page.locator("body").inner_text(timeout=3000) or "")[:1600],
                            "buttons": page.locator("button").all_inner_texts()[:12],
                        }
                    except Exception as exc:
                        result = {
                            "ok": False,
                            "error": "browser_submit_exception",
                            "exception": repr(exc),
                            "page_url": page.url,
                            "body": (page.locator("body").inner_text(timeout=3000) or "")[:1600],
                        }
                    else:
                        page.wait_for_timeout(3500)

                    if result.get("error") == "browser_submit_exception":
                        self._sync_playwright_cookies(context.cookies())
                        browser.close()
                        return result

                    current_url = page.url
                    body = (page.locator("body").inner_text(timeout=3000) or "")[:2000]
                    status = response.status if response is not None else None
                    text = response.text()[:1200] if response is not None else ""
                    response_url = str(response.url) if response is not None else ""
                    response_data = {}
                    if response is not None and status == 200:
                        try:
                            response_data = response.json() or {}
                        except Exception:
                            if text:
                                try:
                                    response_data = json.loads(text)
                                except Exception:
                                    response_data = {}
                    if response_data:
                        state = self._state_from_payload(
                            response_data,
                            current_url=current_url or response_url,
                        )
                        if not state.page_type:
                            state = self._state_from_url(current_url or response_url)
                    else:
                        state = self._state_from_url(current_url or response_url)
                    result = {
                        "ok": False,
                        "status": status,
                        "text": text,
                        "page_url": current_url,
                        "body": body,
                    }
                    if (
                        self._is_registration_complete_state(state)
                        or self._state_is_email_otp(state)
                        or self._state_is_about_you(state)
                    ):
                        result["ok"] = True
                        result["state"] = state
                    else:
                        lowered = "\n".join(part.lower() for part in (text or "", body or ""))
                        if any(marker in lowered for marker in ("just a moment", "cf-challenge", "cloudflare")):
                            result["error"] = "cloudflare_challenge"
                        elif any(marker in lowered for marker in ("user_already_exists", "already exists", "already exists for this email")):
                            result["error"] = "user_already_exists"
                        elif "registration_disallowed" in lowered:
                            result["error"] = "registration_disallowed"
                        elif current_url:
                            result["error"] = f"browser_state_{state.page_type or 'unknown'}"

                    self._sync_playwright_cookies(context.cookies())
                    browser.close()
            except Exception as exc:
                result = {"ok": False, "error": "browser_fallback_exception", "exception": repr(exc)}
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
            return result

        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(run_browser).result(timeout=browser_timeout)
        except FutureTimeoutError:
            return {"ok": False, "error": "browser_fallback_timeout"}
    
    def send_email_otp(self):
        """触发发送邮箱验证码"""
        self._log("触发发送验证码...")
        url = f"{self.AUTH}/api/accounts/email-otp/send"
        sent_mark = time.time()

        try:
            self._browser_pause()
            r = self.session.get(
                url,
                headers=self._headers(
                    url,
                    accept="application/json, text/plain, */*",
                    referer=f"{self.AUTH}/create-account/password",
                    fetch_site="same-origin",
                ),
                allow_redirects=True,
                timeout=30,
            )
            self._last_otp_sent_at = sent_mark
            self._log(f"email-otp/send -> HTTP {r.status_code} body={r.text[:160]}")
            return r.status_code == 200
        except Exception as e:
            self._last_otp_sent_at = sent_mark
            self._log(f"发送验证码失败: {e}")
            return False

    def _browser_send_email_otp(self):
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
        except Exception as exc:
            self._log(f"email-otp 浏览器 resend 不可用: {exc}")
            return {"ok": False, "error": "browser_send_otp_unavailable"}

        launch_kwargs = {
            "headless": self.browser_mode != "headed",
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}
        launch_kwargs = prepare_playwright_launch_kwargs(launch_kwargs, self.browser_mode, self._log)

        browser = None
        context = None
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**launch_kwargs)
                context = harden_playwright_context(browser.new_context(**self._playwright_context_kwargs()))
                cookies = self._cookies_for_playwright()
                self._add_cookies_to_playwright_context(context, cookies, "email-otp browser resend")
                page = context.new_page()
                page.goto(f"{self.AUTH}/email-verification", wait_until="domcontentloaded", timeout=45000)
                page.wait_for_timeout(3000)
                try:
                    body_preview = (page.locator("body").inner_text(timeout=2500) or "")[:800]
                except Exception:
                    body_preview = ""
                if "just a moment" in body_preview.lower() or "cloudflare" in body_preview.lower():
                    self._log("email-otp browser resend: 检测到 challenge，额外等待 12s")
                    page.wait_for_timeout(12000)
                result = page.evaluate(
                    """
                    async (deviceId) => {
                      try {
                        const response = await fetch('/api/accounts/email-otp/send', {
                          method: 'GET',
                          credentials: 'include',
                          headers: {
                            accept: 'application/json, text/plain, */*',
                            'oai-device-id': deviceId,
                          },
                        });
                        const text = await response.text();
                        let data = null;
                        try { data = JSON.parse(text); } catch (_) {}
                        return {
                          ok: response.ok,
                          status: response.status,
                          url: response.url,
                          data,
                          text: text.slice(0, 500),
                          documentCookie: document.cookie.slice(0, 2000),
                        };
                      } catch (error) {
                        return { ok: false, error: String(error) };
                      }
                    }
                    """,
                    self.device_id,
                )
                self._sync_playwright_cookies(context.cookies())
                return result or {"ok": False, "error": "empty_browser_send_otp_result"}
        except PlaywrightTimeoutError as exc:
            return {"ok": False, "error": "browser_send_otp_timeout", "exception": str(exc)}
        except Exception as exc:
            return {"ok": False, "error": "browser_send_otp_exception", "exception": repr(exc)}
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
    
    def verify_email_otp(self, otp_code, return_state=False):
        """
        验证邮箱 OTP 码
        
        Args:
            otp_code: 6位验证码
            
        Returns:
            tuple: (success, message)
        """
        self._log(f"验证 OTP 码: {otp_code}")
        url = f"{self.AUTH}/api/accounts/email-otp/validate"
        
        headers = self._headers(
            url,
            accept="application/json",
            referer=f"{self.AUTH}/email-verification",
            origin=self.AUTH,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={
                "oai-device-id": self.device_id,
            },
        )
        headers.update(generate_datadog_trace())
        
        payload = {"code": otp_code}

        def probe_state_after_timeout():
            probe_targets = [
                f"{self.AUTH}/email-verification",
                f"{self.AUTH}/about-you",
                f"{self.BASE}/",
            ]
            for probe_url in probe_targets:
                try:
                    resp = self.session.get(
                        probe_url,
                        headers=self._headers(
                            probe_url,
                            accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            referer=f"{self.AUTH}/email-verification",
                            navigation=True,
                        ),
                        allow_redirects=True,
                        timeout=30,
                    )
                except Exception as probe_exc:
                    self._log(f"OTP 超时后探测状态异常 {probe_url}: {probe_exc}")
                    continue

                probe_state = self._state_from_url(str(resp.url) or probe_url)
                self._log(
                    "OTP 超时后探测状态 -> "
                    f"{probe_url} => {describe_flow_state(probe_state)}"
                )
                if (
                    self._state_is_about_you(probe_state)
                    or self._state_requires_navigation(probe_state)
                    or self._is_registration_complete_state(probe_state)
                ):
                    return probe_state
            return None
        
        try:
            self._browser_pause()
            r = self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=30,
                allow_redirects=False,
            )
            
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    data = {}
                next_state = self._state_from_payload(data, current_url=str(r.url) or f"{self.AUTH}/about-you")
                self._log(f"验证成功 {describe_flow_state(next_state)}")
                return (True, next_state) if return_state else (True, "验证成功")
            if r.status_code in {301, 302, 303, 307, 308}:
                next_url = normalize_flow_url(r.headers.get("Location", ""), auth_base=self.AUTH) or str(r.url or "")
                next_state = self._state_from_url(next_url or f"{self.AUTH}/about-you")
                self._log(f"OTP 验证跳转 {describe_flow_state(next_state)}")
                return (True, next_state) if return_state else (True, "验证成功")
            else:
                error_msg = r.text[:200]
                self._log(f"验证失败: {r.status_code} - {error_msg}")
                return False, f"HTTP {r.status_code}"
                
        except Exception as e:
            self._log(f"验证异常: {e}")
            recovered_state = probe_state_after_timeout()
            if recovered_state:
                self._log(f"OTP 超时后恢复状态成功 {describe_flow_state(recovered_state)}")
                return (True, recovered_state) if return_state else (True, "验证成功")
            return False, str(e)
    
    def _create_account_browser_fallback(self, first_name, last_name, birthdate):
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
        except Exception as exc:
            self._log(f"create_account 浏览器 fallback 不可用: {exc}")
            return {"ok": False, "error": "browser_fallback_unavailable"}

        name = f"{first_name} {last_name}".strip()
        try:
            year, month, day = [part.strip() for part in str(birthdate).split("-", 2)]
        except Exception:
            return {"ok": False, "error": f"invalid_birthdate:{birthdate}"}

        launch_kwargs = {
            "headless": self.browser_mode != "headed",
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}
        launch_kwargs = prepare_playwright_launch_kwargs(launch_kwargs, self.browser_mode, self._log)

        result = {"ok": False, "error": "browser_fallback_unknown"}
        browser = None
        context = None
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**launch_kwargs)
                context = harden_playwright_context(browser.new_context(**self._playwright_context_kwargs()))
                cookies = self._cookies_for_playwright()
                self._add_cookies_to_playwright_context(context, cookies, "create_account browser fallback")
                page = context.new_page()
                network_events = []

                def _record_network(event):
                    network_events.append(event)
                    if len(network_events) > 80:
                        del network_events[:-80]

                def _header_subset(headers):
                    keep = {
                        "content-type",
                        "cf-ray",
                        "cf-cache-status",
                        "location",
                        "server",
                        "x-request-id",
                        "set-cookie",
                    }
                    subset = {}
                    for key, value in (headers or {}).items():
                        key_lower = str(key).lower()
                        if key_lower in keep:
                            subset[key_lower] = str(value)[:800]
                    return subset

                def _on_request(request):
                    url = str(request.url or "")
                    if (
                        "/api/accounts/create_account" not in url
                        and "/cdn-cgi/challenge-platform/" not in url
                        and "challenge-platform" not in url
                    ):
                        return
                    try:
                        post_data = request.post_data
                    except Exception:
                        post_data = ""
                    _record_network(
                        {
                            "type": "request",
                            "method": request.method,
                            "url": url,
                            "resource_type": request.resource_type,
                            "headers": _header_subset(request.headers),
                            "post_data": str(post_data or "")[:2000],
                        }
                    )

                def _on_response(response):
                    url = str(response.url or "")
                    if (
                        "/api/accounts/create_account" not in url
                        and "/cdn-cgi/challenge-platform/" not in url
                        and "challenge-platform" not in url
                    ):
                        return
                    try:
                        body = response.text()
                    except Exception:
                        body = ""
                    _record_network(
                        {
                            "type": "response",
                            "status": response.status,
                            "url": url,
                            "headers": _header_subset(response.headers),
                            "body": str(body or "")[:2000],
                        }
                    )

                page.on("request", _on_request)
                page.on("response", _on_response)

                def _body_preview(limit=1600):
                    try:
                        return (page.locator("body").inner_text(timeout=3000) or "")[:limit]
                    except Exception:
                        return ""

                def _looks_like_challenge(text):
                    lowered = (text or "").lower()
                    return any(marker in lowered for marker in ("just a moment", "cf-challenge", "cloudflare"))

                def _fill_about_you():
                    for nav_attempt in range(2):
                        page.goto(f"{self.AUTH}/about-you", wait_until="domcontentloaded", timeout=45000)
                        try:
                            page.wait_for_function(
                                "() => document.querySelectorAll('[role=spinbutton]').length >= 3",
                                timeout=60000,
                            )
                        except PlaywrightTimeoutError:
                            body = _body_preview(1200)
                            if _looks_like_challenge(body) and nav_attempt == 0:
                                self._log("browser about_you 仍在 challenge，等待 clearance")
                                page.wait_for_function(
                                    "() => !document.body || !/just a moment|cloudflare/i.test(document.body.innerText || '')",
                                    timeout=120000,
                                )
                                page.wait_for_timeout(3000)
                                self._sync_playwright_cookies(context.cookies())
                                continue
                            raise
                        page.wait_for_timeout(1200)
                        page.locator('input[name="name"]').fill(name, timeout=5000)
                        for idx, value in enumerate((month, day, year)):
                            page.get_by_role("spinbutton").nth(idx).fill(value, timeout=5000)
                            page.wait_for_timeout(250)
                        try:
                            return page.locator('input[name="birthday"]').input_value()
                        except Exception:
                            return ""
                    return ""

                def _submit_button_state():
                    try:
                        return page.evaluate(
                            """
                            () => {
                              const btn = document.querySelector('button[type="submit"]');
                              if (!btn) return {present: false};
                              return {
                                present: true,
                                text: (btn.innerText || btn.textContent || '').trim().slice(0, 200),
                                disabled: !!btn.disabled,
                                ariaDisabled: btn.getAttribute('aria-disabled'),
                                className: (btn.className || '').slice(0, 400),
                                formAction: btn.formAction || '',
                                formMethod: btn.formMethod || '',
                              };
                            }
                            """
                        )
                    except Exception as exc:
                        return {"present": False, "error": repr(exc)}

                def _bridge_same_browser_chatgpt_session():
                    login_with_url = f"{self.BASE}/auth/login_with"
                    signin_bridge_url = (
                        f"{self.BASE}/api/auth/signin/openai"
                        "?callbackUrl=https%3A%2F%2Fchatgpt.com%2F"
                    )

                    def _looks_like_guest_home(body_text, page_url):
                        lowered = "\n".join(part.lower() for part in (body_text or "", page_url or ""))
                        return (
                            "chatgpt.com" in lowered
                            and "log in" in lowered
                            and (
                                "sign up for free" in lowered
                                or "get responses tailored to you" in lowered
                                or "/auth/error" in lowered
                            )
                        )

                    def _click_guest_login():
                        selectors = [
                            "button:has-text('Log in')",
                            "a:has-text('Log in')",
                            "button[aria-label='Log in']",
                        ]
                        for selector in selectors:
                            try:
                                locator = page.locator(selector).first
                                if locator.count() and locator.is_visible(timeout=1000):
                                    locator.click(timeout=5000)
                                    return True
                            except Exception:
                                continue
                        return False

                    def _native_nextauth_signin():
                        email_value = str(getattr(self, "current_email", "") or "").strip()
                        if not email_value:
                            return None
                        try:
                            return page.evaluate(
                                """
                                async ({ email, deviceId, authSessionLoggingId }) => {
                                  try {
                                    const csrfResp = await fetch('/api/auth/csrf', {
                                      credentials: 'include',
                                      headers: { accept: 'application/json, text/plain, */*' },
                                    });
                                    const csrfText = await csrfResp.text();
                                    let csrfData = null;
                                    try { csrfData = JSON.parse(csrfText); } catch (_) {}

                                    const qs = new URLSearchParams({
                                      prompt: 'login',
                                      'ext-oai-did': deviceId,
                                      auth_session_logging_id: authSessionLoggingId,
                                      screen_hint: 'login_or_signup',
                                      login_hint: email,
                                    });
                                    const body = new URLSearchParams({
                                      callbackUrl: 'https://chatgpt.com/',
                                      csrfToken: (csrfData && csrfData.csrfToken) || '',
                                      json: 'true',
                                    });
                                    const resp = await fetch('/api/auth/signin/openai?' + qs.toString(), {
                                      method: 'POST',
                                      credentials: 'include',
                                      headers: {
                                        'content-type': 'application/x-www-form-urlencoded',
                                        accept: 'application/json, text/plain, */*',
                                      },
                                      body,
                                    });
                                    const text = await resp.text();
                                    let data = null;
                                    try { data = JSON.parse(text); } catch (_) {}
                                    return {
                                      csrfStatus: csrfResp.status,
                                      status: resp.status,
                                      responseUrl: resp.url,
                                      data,
                                      text: text.slice(0, 600),
                                      documentCookie: document.cookie,
                                    };
                                  } catch (error) {
                                    return { error: String(error) };
                                  }
                                }
                                """,
                                {
                                    "email": email_value,
                                    "deviceId": self.device_id,
                                    "authSessionLoggingId": str(uuid.uuid4()),
                                },
                            )
                        except Exception as exc:
                            self._log(
                                "browser create_account same-browser bridge native next-auth signin 异常: "
                                f"{exc}"
                            )
                            return None

                    for target in ("", login_with_url, signin_bridge_url):
                        guest_login_clicked = False
                        login_with_attempted = False
                        native_signin_attempted = False
                        if target:
                            try:
                                self._log(
                                    "browser create_account same-browser bridge: 打开 "
                                    f"{target}"
                                )
                                page.goto(target, wait_until="domcontentloaded", timeout=45000)
                                page.wait_for_timeout(2500)
                            except Exception as exc:
                                self._log(
                                    "browser create_account same-browser bridge 打开失败: "
                                    f"{exc}"
                                )
                                continue

                        start_wait = time.time()
                        while time.time() - start_wait <= 45:
                            self._sync_playwright_cookies(context.cookies())
                            current_url = str(page.url or "")
                            callback_tokens = self._consume_chatgpt_callback_session(
                                current_url,
                                referer=f"{self.AUTH}/about-you",
                            )
                            if callback_tokens:
                                self._log(
                                    "browser create_account same-browser bridge: "
                                    "callback/openai 恢复成功"
                                )
                                return callback_tokens

                            try:
                                page_host = (urlparse(current_url).netloc or "").lower()
                            except Exception:
                                page_host = ""

                            if page_host.endswith("chatgpt.com"):
                                try:
                                    browser_session = page.evaluate(
                                        """
                                        async () => {
                                          try {
                                            const response = await fetch("/api/auth/session", {
                                              method: "GET",
                                              credentials: "include",
                                              headers: {"accept": "application/json"},
                                            });
                                            const text = await response.text();
                                            let data = null;
                                            try { data = JSON.parse(text); } catch (_) {}
                                            return {
                                              ok: response.ok,
                                              status: response.status,
                                              url: response.url,
                                              data,
                                              text: text.slice(0, 400),
                                            };
                                          } catch (error) {
                                            return {error: String(error)};
                                          }
                                        }
                                        """
                                    )
                                except Exception as exc:
                                    self._log(
                                        "browser create_account same-browser bridge fetch 异常: "
                                        f"{exc}"
                                    )
                                    browser_session = None

                                if isinstance(browser_session, dict):
                                    if browser_session.get("error"):
                                        self._log(
                                            "browser create_account same-browser bridge session 异常: "
                                            f"{browser_session['error']}"
                                        )
                                    else:
                                        status = browser_session.get("status")
                                        self._log(
                                            "browser create_account same-browser bridge session -> "
                                            f"HTTP {status} {str(browser_session.get('url') or '')[:120]}"
                                        )
                                        session_data = browser_session.get("data")
                                        if isinstance(session_data, dict):
                                            normalized = self._normalize_chatgpt_session_tokens(session_data)
                                            if normalized:
                                                return normalized
                                            body = _body_preview(1200)
                                            if (
                                                not guest_login_clicked
                                                and _looks_like_guest_home(body, current_url)
                                            ):
                                                if _click_guest_login():
                                                    guest_login_clicked = True
                                                    self._log(
                                                        "browser create_account same-browser bridge: "
                                                        "检测到 guest 首页，改走浏览器原生 Log in 按钮"
                                                    )
                                                    try:
                                                        page.wait_for_load_state("domcontentloaded", timeout=45000)
                                                    except Exception:
                                                        pass
                                                    page.wait_for_timeout(4000)
                                                    self._sync_playwright_cookies(context.cookies())
                                                    continue
                                            if (
                                                not native_signin_attempted
                                                and _looks_like_guest_home(body, current_url)
                                            ):
                                                native_signin_attempted = True
                                                native_result = _native_nextauth_signin()
                                                if isinstance(native_result, dict):
                                                    if native_result.get("error"):
                                                        self._log(
                                                            "browser create_account same-browser bridge native next-auth signin 错误: "
                                                            f"{native_result['error']}"
                                                        )
                                                    else:
                                                        self._log(
                                                            "browser create_account same-browser bridge native next-auth signin -> "
                                                            f"HTTP {native_result.get('status')} {str(native_result.get('responseUrl') or '')[:120]}"
                                                        )
                                                        data = native_result.get("data")
                                                        auth_url = ""
                                                        if isinstance(data, dict):
                                                            auth_url = str(data.get("url") or "").strip()
                                                        if (not auth_url) and native_result.get("text"):
                                                            match = re.search(r"https://auth\\.openai\\.com[^\"'\\s<]+", native_result["text"])
                                                            auth_url = match.group(0) if match else ""
                                                        if auth_url:
                                                            self._log(
                                                                "browser create_account same-browser bridge native next-auth signin: "
                                                                f"跳转 {auth_url[:160]}"
                                                            )
                                                            self._sync_playwright_cookies(context.cookies())
                                                            resumed_ok, resumed_tokens = self._resume_chatgpt_web_authorize_flow(
                                                                email_value,
                                                                auth_url,
                                                            )
                                                            if resumed_ok and resumed_tokens:
                                                                self._log(
                                                                    "browser create_account same-browser bridge native next-auth signin: "
                                                                    "auth.openai.com 子流程恢复成功"
                                                                )
                                                                return resumed_tokens
                                                            if resumed_tokens:
                                                                self._log(
                                                                    "browser create_account same-browser bridge native next-auth signin: "
                                                                    f"auth.openai.com 子流程未恢复，原因={resumed_tokens}"
                                                                )
                                                            try:
                                                                page.goto(auth_url, wait_until="domcontentloaded", timeout=45000)
                                                                page.wait_for_timeout(4000)
                                                                self._sync_playwright_cookies(context.cookies())
                                                                continue
                                                            except Exception as exc:
                                                                self._log(
                                                                    "browser create_account same-browser bridge native next-auth signin 跳转失败: "
                                                                    f"{exc}"
                                                                )

                            ok, session_or_error = self.fetch_chatgpt_session()
                            if ok:
                                normalized = self._normalize_chatgpt_session_tokens(session_or_error)
                                if normalized:
                                    self._log(
                                        "browser create_account same-browser bridge: "
                                        "协议 /api/auth/session 恢复成功"
                                    )
                                    return normalized
                            page.wait_for_timeout(2500)

                    return None

                hidden_birthdate = ""
                for attempt in range(2):
                    hidden_birthdate = _fill_about_you()
                    if hidden_birthdate != birthdate:
                        self._log(f"browser about_you 生日未同步，实际为: {hidden_birthdate}")

                    try:
                        page.wait_for_function(
                            "() => !!(window.SentinelSDK && typeof window.SentinelSDK.token === 'function')",
                            timeout=30000,
                        )
                        browser_token = page.evaluate(
                            """
                            async () => {
                              return await window.SentinelSDK.token("oauth_create_account");
                            }
                            """
                        )
                    except Exception as exc:
                        browser_token = ""
                        self._log(f"browser create_account fetch 未拿到 sentinel token: {exc}")

                    if browser_token:
                        try:
                            page.evaluate(
                                """
                                ({ token }) => {
                                  window.__oai_create_account_sentinel = token;
                                  return true;
                                }
                                """,
                                {"token": browser_token},
                            )
                            self._log("browser create_account: sentinel 已注入同页上下文，优先走原生提交")
                        except Exception as exc:
                            self._log(f"browser create_account: sentinel 注入页面失败: {exc}")

                    fetch_result = None
                    if browser_token:
                        try:
                            fetch_result = page.evaluate(
                                """
                                async ({ name, birthdate, token }) => {
                                  try {
                                    const response = await fetch("/api/accounts/create_account", {
                                      method: "POST",
                                      credentials: "include",
                                      headers: {
                                        "Accept": "application/json",
                                        "Content-Type": "application/json",
                                        "OpenAI-Sentinel-Token": token
                                      },
                                      body: JSON.stringify({ name, birthdate })
                                    });
                                    const text = await response.text();
                                    let jsonBody = null;
                                    try {
                                      jsonBody = JSON.parse(text);
                                    } catch (_) {}
                                    return {
                                      status: response.status,
                                      ok: response.ok,
                                      url: response.url,
                                      text: text.slice(0, 1200),
                                      json: jsonBody,
                                      headers: Object.fromEntries(
                                        Array.from(response.headers.entries()).filter(
                                          ([key]) => [
                                            "content-type",
                                            "cf-ray",
                                            "cf-cache-status",
                                            "openai-processing-ms",
                                            "x-request-id",
                                            "x-openai-public-ip"
                                          ].includes(String(key || "").toLowerCase())
                                        )
                                      ),
                                      pageUrl: window.location.href,
                                      bodyText: (document.body && document.body.innerText)
                                        ? document.body.innerText.slice(0, 1600)
                                        : "",
                                      documentCookie: document.cookie.slice(0, 2400),
                                    };
                                  } catch (error) {
                                    return { error: String(error) };
                                  }
                                }
                                """,
                                {"name": name, "birthdate": birthdate, "token": browser_token},
                            )
                        except Exception as exc:
                            fetch_result = {"error": repr(exc)}

                    if isinstance(fetch_result, dict):
                        if fetch_result.get("error"):
                            self._log(f"browser create_account fetch 异常: {fetch_result['error']}")
                        else:
                            fetch_status = fetch_result.get("status")
                            fetch_text = str(fetch_result.get("text") or "")[:1200]
                            fetch_body = str(fetch_result.get("bodyText") or "")[:1600]
                            fetch_page_url = str(fetch_result.get("pageUrl") or page.url or "")
                            self._log(
                                "browser create_account fetch -> "
                                f"status={fetch_status} url={fetch_page_url[:140]}"
                            )
                            lowered_fetch = "\n".join((fetch_text, fetch_body)).lower()
                            if fetch_status == 200:
                                data = fetch_result.get("json") or {}
                                state = self._state_from_payload(data, current_url=fetch_page_url)
                                if not state.page_type:
                                    state = self._state_from_url(fetch_page_url)
                                result = {
                                    "ok": True,
                                    "status": fetch_status,
                                    "text": fetch_text,
                                    "page_url": fetch_page_url,
                                    "body": fetch_body,
                                    "hidden_birthdate": hidden_birthdate,
                                    "state": state,
                                    "headers": fetch_result.get("headers") or {},
                                    "document_cookie": fetch_result.get("documentCookie") or "",
                                    "network_events": list(network_events),
                                    "button_state": _submit_button_state(),
                                }
                                break
                            if any(
                                marker in lowered_fetch
                                for marker in (
                                    "user_already_exists",
                                    "already exists for this email address",
                                    "already exists",
                                )
                            ):
                                bridge_tokens = _bridge_same_browser_chatgpt_session()
                                if bridge_tokens:
                                    result = {
                                        "ok": True,
                                        "status": fetch_status,
                                        "text": fetch_text,
                                        "page_url": fetch_page_url,
                                        "body": fetch_body,
                                        "hidden_birthdate": hidden_birthdate,
                                        "state": self._state_from_url(fetch_page_url),
                                        "tokens": bridge_tokens,
                                        "headers": fetch_result.get("headers") or {},
                                        "document_cookie": fetch_result.get("documentCookie") or "",
                                        "network_events": list(network_events),
                                        "button_state": _submit_button_state(),
                                    }
                                else:
                                    result = {
                                        "ok": False,
                                        "status": fetch_status,
                                        "text": fetch_text,
                                        "page_url": fetch_page_url,
                                        "body": fetch_body,
                                        "hidden_birthdate": hidden_birthdate,
                                        "error": "user_already_exists",
                                        "headers": fetch_result.get("headers") or {},
                                        "document_cookie": fetch_result.get("documentCookie") or "",
                                        "network_events": list(network_events),
                                        "button_state": _submit_button_state(),
                                    }
                                break
                            if "registration_disallowed" in lowered_fetch:
                                result["fetch_error"] = "registration_disallowed"
                                result["fetch_status"] = fetch_status
                                result["fetch_text"] = fetch_text
                                result["fetch_headers"] = fetch_result.get("headers") or {}
                                result["fetch_page_url"] = fetch_page_url
                            elif fetch_status == 403 and _looks_like_challenge("\n".join((fetch_text, fetch_body))):
                                self._log("browser create_account fetch 收到 403 challenge，继续尝试页面提交流程")
                                result["fetch_error"] = "cloudflare_challenge"
                                result["fetch_status"] = fetch_status
                                result["fetch_text"] = fetch_text
                                result["fetch_headers"] = fetch_result.get("headers") or {}
                                result["fetch_page_url"] = fetch_page_url

                    response = None
                    try:
                        button_state_before = _submit_button_state()
                        self._log(
                            "browser create_account 原生提交前按钮状态: "
                            f"{json.dumps(button_state_before, ensure_ascii=False)[:240]}"
                        )
                        with page.expect_response(
                            lambda resp: "/api/accounts/create_account" in resp.url,
                            timeout=45000,
                        ) as response_info:
                            page.locator('button[type="submit"]').click(timeout=5000)
                        response = response_info.value
                    except PlaywrightTimeoutError as exc:
                        body = _body_preview(1200)
                        if _looks_like_challenge(body) and attempt == 0:
                            self._log("browser create_account 命中 challenge 页面，等待 clearance 后重试")
                            try:
                                page.wait_for_function(
                                    "() => !document.body || !/just a moment|cloudflare/i.test(document.body.innerText || '')",
                                    timeout=120000,
                                )
                                page.wait_for_timeout(3000)
                                self._sync_playwright_cookies(context.cookies())
                                continue
                            except Exception:
                                pass
                        result = {
                            "ok": False,
                            "error": "browser_submit_timeout",
                            "page_url": page.url,
                            "body": body,
                            "exception": repr(exc),
                            "network_events": list(network_events),
                            "button_state": _submit_button_state(),
                        }
                        break
                    else:
                        page.wait_for_timeout(5000)
                        text = response.text()[:1200]
                        page_url = page.url
                        body = _body_preview(1600)
                        status = response.status
                        result = {
                            "ok": status == 200,
                            "status": status,
                            "text": text,
                            "page_url": page_url,
                            "body": body,
                            "hidden_birthdate": hidden_birthdate,
                            "network_events": list(network_events),
                            "button_state": _submit_button_state(),
                        }
                        if status == 200:
                            try:
                                data = response.json()
                            except Exception:
                                data = {}
                            state = self._state_from_payload(data, current_url=page_url or str(response.url))
                            if not state.page_type:
                                state = self._state_from_url(page_url or str(response.url))
                            result["state"] = state
                            break

                        lowered = "\n".join(part.lower() for part in (text or "", body or ""))
                        if any(
                            marker in lowered
                            for marker in (
                                "user_already_exists",
                                "already exists for this email address",
                                "already exists",
                            )
                        ):
                            bridge_tokens = _bridge_same_browser_chatgpt_session()
                            if bridge_tokens:
                                result["ok"] = True
                                result["tokens"] = bridge_tokens
                                result["state"] = self._state_from_url(page_url or str(response.url))
                            else:
                                result["error"] = "user_already_exists"
                            break
                        if "registration_disallowed" in lowered:
                            result["error"] = "registration_disallowed"
                            break
                        if status == 403 and _looks_like_challenge("\n".join((text or "", body or ""))) and attempt == 0:
                            self._log("browser create_account 收到 403 challenge，等待 clearance 后重试")
                            try:
                                page.wait_for_function(
                                    "() => !document.body || !/just a moment|cloudflare/i.test(document.body.innerText || '')",
                                    timeout=120000,
                                )
                                page.wait_for_timeout(3000)
                                self._sync_playwright_cookies(context.cookies())
                                continue
                            except Exception:
                                result["error"] = "cloudflare_challenge"
                                break
                        result["error"] = f"browser_http_{status}"
                        break

                self._sync_playwright_cookies(context.cookies())
                browser.close()
        except Exception as exc:
            result = {"ok": False, "error": "browser_fallback_exception", "exception": repr(exc)}
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
        return result

    def create_account(self, first_name, last_name, birthdate, return_state=False):
        """
        完成账号创建（提交姓名和生日）
        
        Args:
            first_name: 名
            last_name: 姓
            birthdate: 生日 (YYYY-MM-DD)
            
        Returns:
            tuple: (success, message)
        """
        name = f"{first_name} {last_name}"
        self._log(f"完成账号创建: {name}")
        url = f"{self.AUTH}/api/accounts/create_account"

        sentinel_token = self._mint_browser_sentinel_token(
            f"{self.AUTH}/about-you",
            "oauth_create_account",
        )
        if not sentinel_token:
            sentinel_token = build_sentinel_token(
                self.session,
                self.device_id,
                flow="oauth_create_account",
                user_agent=self.ua,
                sec_ch_ua=self.sec_ch_ua,
                impersonate=self.impersonate,
            )
        if sentinel_token:
            self._log("create_account: 已生成 sentinel token")
        else:
            self._log("create_account: 未生成 sentinel token，降级继续请求")

        headers = self._headers(
            url,
            accept="application/json",
            referer=f"{self.AUTH}/about-you",
            origin=self.AUTH,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={
                "oai-device-id": self.device_id,
            },
        )
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        headers.update(generate_datadog_trace())
        
        payload = {
            "name": name,
            "birthdate": birthdate,
        }

        def protocol_submit(token_override=None):
            request_headers = dict(headers)
            if token_override:
                request_headers["openai-sentinel-token"] = token_override
            self._browser_pause()
            return self.session.post(url, json=payload, headers=request_headers, timeout=30)

        if sentinel_token:
            try:
                r = protocol_submit(sentinel_token)
                if r.status_code == 200:
                    try:
                        data = r.json()
                    except Exception:
                        data = {}
                    next_state = self._state_from_payload(data, current_url=str(r.url) or self.BASE)
                    self._log(f"create_account 协议直提成功 {describe_flow_state(next_state)}")
                    return (True, next_state) if return_state else (True, "账号创建成功")
                error_msg = r.text[:200]
                lowered = (r.text or "").lower()
                if r.status_code == 400 and any(marker in lowered for marker in ("already_exists", "already exists", "user_already_exists")):
                    self._log(f"create_account 协议直提提示已存在，按 existing-account 分支继续: {error_msg}")
                    next_state = self._state_from_url("https://chatgpt.com/auth/login_with")
                    self.last_registration_state = next_state
                    return (True, next_state) if return_state else (True, "账号已存在，转登录")
                self._log(f"create_account 协议直提未过，准备浏览器兜底: {r.status_code} - {error_msg}")
            except Exception as exc:
                self._log(f"create_account 协议直提异常，准备浏览器兜底: {exc}")

        preclear_result = self._browser_preclear_create_account_challenge(
            f"{self.AUTH}/about-you",
            flow="oauth_create_account",
            submit_payload=payload,
            sentinel_token=sentinel_token,
        )
        fetch_result = preclear_result.get("fetch_result") if isinstance(preclear_result, dict) else None
        if isinstance(fetch_result, dict) and not fetch_result.get("error"):
            fetch_status = fetch_result.get("status")
            fetch_text = str(fetch_result.get("text") or "")[:1200]
            fetch_body = str(fetch_result.get("bodyText") or "")[:1600]
            lowered_fetch = "\n".join((fetch_text, fetch_body)).lower()
            self._log(
                "create_account preclear fetch -> "
                f"status={fetch_status} ok={fetch_result.get('ok')}"
            )
            if fetch_status == 200:
                data = fetch_result.get("json") or {}
                next_state = self._state_from_payload(
                    data,
                    current_url=str(fetch_result.get("url") or self.BASE),
                )
                if not next_state.page_type:
                    next_state = self._state_from_url(str(fetch_result.get("url") or self.BASE))
                self._log(f"create_account preclear 直提成功 {describe_flow_state(next_state)}")
                return (True, next_state) if return_state else (True, "账号创建成功")
            if any(marker in lowered_fetch for marker in ("user_already_exists", "already exists", "already exists for this email")):
                self._log("create_account preclear 提示已存在，按 existing-account 分支继续")
                next_state = self._state_from_url("https://chatgpt.com/auth/login_with")
                self.last_registration_state = next_state
                return (True, next_state) if return_state else (True, "账号已存在，转登录")
            if "registration_disallowed" in lowered_fetch:
                self._log(f"create_account preclear 命中 registration_disallowed: {fetch_text[:200]}")
                return False, "HTTP 400"
        elif isinstance(fetch_result, dict) and fetch_result.get("error"):
            self._log(f"create_account preclear fetch 异常: {fetch_result['error']}")

        browser_result = self._create_account_browser_fallback(first_name, last_name, birthdate)
        browser_error = browser_result.get("error") or ""
        browser_status = browser_result.get("status")
        browser_text = str(browser_result.get("text") or browser_result.get("body") or "")[:200]
        if browser_result.get("ok") and browser_result.get("state") is not None:
            if browser_result.get("tokens"):
                self._preloaded_chatgpt_tokens = browser_result.get("tokens")
                self._log("browser create_account same-browser bridge 已恢复 ChatGPT session")
            next_state = browser_result["state"]
            self._log(f"browser create_account 成功 {describe_flow_state(next_state)}")
            return (True, next_state) if return_state else (True, "账号创建成功")
        if browser_error == "user_already_exists":
            self._log("browser create_account 提示已存在，按 existing-account 分支继续")
            next_state = self._state_from_url("https://chatgpt.com/auth/login_with")
            self.last_registration_state = next_state
            return (True, next_state) if return_state else (True, "账号已存在，转登录")
        if browser_error == "registration_disallowed":
            self._log(f"browser create_account 命中 registration_disallowed: {browser_text}")
            return False, "HTTP 400"
        if browser_status == 403 or browser_error in {
            "cloudflare_challenge",
            "browser_http_403",
            "browser_submit_timeout",
            "browser_fallback_exception",
        }:
            artifact = self._dump_create_account_debug(
                "create_account_browser_submit",
                {
                    "browser_status": browser_status,
                    "browser_error": browser_error,
                    "browser_result": browser_result,
                    "cookie_snapshot": self._auth_cookie_snapshot(),
                },
            )
            detail = browser_result.get("exception") or browser_result.get("page_url") or ""
            suffix = f" ({detail})" if detail else ""
            self._log(
                "browser create_account 命中 challenge/timeout，停止在浏览器证据面: "
                f"{browser_error or browser_status}{suffix}"
            )
            if artifact:
                self._log(f"browser create_account 调试已写出: {artifact}")
            return False, f"HTTP {browser_status or 403}"
        
        try:
            r = protocol_submit()
            
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    data = {}
                next_state = self._state_from_payload(data, current_url=str(r.url) or self.BASE)
                self._log(f"账号创建成功 {describe_flow_state(next_state)}")
                return (True, next_state) if return_state else (True, "账号创建成功")
            else:
                error_msg = r.text[:200]
                lowered = (r.text or "").lower()
                if r.status_code == 400 and any(marker in lowered for marker in ("already_exists", "already exists", "user_already_exists")):
                    self._log(f"创建账号提示已存在，按 existing-account 分支继续: {error_msg}")
                    next_state = self._state_from_url("https://chatgpt.com/auth/login_with")
                    self.last_registration_state = next_state
                    return (True, next_state) if return_state else (True, "账号已存在，转登录")
                if r.status_code in {400, 403}:
                    self._log(f"create_account 协议兜底仍失败: {r.status_code} - {error_msg}")
                self._log(f"创建失败: {r.status_code} - {error_msg}")
                return False, f"HTTP {r.status_code}"
                
        except Exception as e:
            self._log(f"创建异常: {e}")
            return False, str(e)
    
    def register_complete_flow(self, email, password, first_name, last_name, birthdate, skymail_client):
        """
        完整的注册流程（基于原版 run_register 方法）
        
        Args:
            email: 邮箱
            password: 密码
            first_name: 名
            last_name: 姓
            birthdate: 生日
            skymail_client: Skymail 客户端（用于获取验证码）
            
        Returns:
            tuple: (success, message)
        """
        from urllib.parse import urlparse
        self.current_email = email
        self.current_password = password or ""
        
        max_auth_attempts = 3
        final_url = ""
        final_path = ""

        for auth_attempt in range(max_auth_attempts):
            if auth_attempt > 0:
                self._log(f"预授权阶段重试 {auth_attempt + 1}/{max_auth_attempts}...")
                self._reset_session()

            # 1. 访问首页
            if not self.visit_homepage():
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "访问首页失败"

            # 2. 获取 CSRF token
            csrf_token = self.get_csrf_token()
            if not csrf_token:
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "获取 CSRF token 失败"

            # 3. 提交邮箱，获取 authorize URL
            auth_url = self.signin(email, csrf_token)
            if not auth_url:
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "提交邮箱失败"

            # 4. 访问 authorize URL（关键步骤！）
            final_url = self.authorize(auth_url)
            if not final_url:
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, "Authorize 失败"

            final_path = urlparse(final_url).path
            self._log(f"Authorize → {final_path}")

            # /api/accounts/authorize 实际上常对应 Cloudflare 403 中间页，不要继续走 authorize_continue。
            if "api/accounts/authorize" in final_path or final_path == "/error":
                self._log(f"检测到 Cloudflare/SPA 中间页，准备重试预授权: {final_url[:160]}...")
                if auth_attempt < max_auth_attempts - 1:
                    continue
                return False, f"预授权被拦截: {final_path}"

            break
        
        state = self._state_from_url(final_url)
        self._log(f"注册状态起点: {describe_flow_state(state)}")

        register_submitted = False
        otp_verified = False
        account_created = False
        seen_states = {}

        for _ in range(12):
            signature = self._state_signature(state)
            seen_states[signature] = seen_states.get(signature, 0) + 1
            if seen_states[signature] > 2:
                return False, f"注册状态卡住: {describe_flow_state(state)}"

            if self._is_registration_complete_state(state):
                self.last_registration_state = state
                self._log("✅ 注册流程完成")
                return True, "注册成功"

            if self._state_is_password_registration(state):
                self._log("全新注册流程")
                if register_submitted:
                    return False, "注册密码阶段重复进入"
                success, msg = self.register_user(email, password)
                if not success:
                    return False, f"注册失败: {msg}"
                register_submitted = True
                if not self.send_email_otp():
                    self._log("发送验证码接口返回失败，继续等待邮箱中的验证码...")
                state = self._state_from_url(f"{self.AUTH}/email-verification")
                continue

            if self._state_is_email_otp(state):
                self._log("等待邮箱验证码...")
                slow_mail_domains = ("@outlook.com", "@hotmail.com", "@live.com")
                cfworker_domains = ("@suxin.edu.kg",)
                lower_email = str(email or "").lower()
                email_service = getattr(skymail_client, "es", None)
                mailbox_class = str(getattr(email_service, "mailbox_class", "") or "").strip().lower()
                is_slow_mail = lower_email.endswith(slow_mail_domains)
                is_cfworker_mail = lower_email.endswith(cfworker_domains)
                is_imap_secret_mail = mailbox_class == "imapsecretmailbox"
                otp_wait_budget = 360 if is_slow_mail else (150 if is_cfworker_mail else (90 if is_imap_secret_mail else 45))
                otp_deadline = time.time() + otp_wait_budget
                otp_anchor = getattr(self, "_last_otp_sent_at", None)
                if not otp_anchor:
                    otp_anchor = time.time() - 15
                    self._last_otp_sent_at = otp_anchor
                tried_codes = set()
                verified = False
                browser_resend_attempted = False

                while time.time() < otp_deadline:
                    remaining = max(1, int(otp_deadline - time.time()))
                    if is_slow_mail:
                        wait_time = min(60, max(30, remaining))
                    elif is_cfworker_mail:
                        wait_time = min(45, max(25, remaining))
                    elif is_imap_secret_mail:
                        wait_time = min(30, max(15, remaining))
                    else:
                        wait_time = min(20, max(12, remaining))
                    try:
                        otp_code = skymail_client.wait_for_verification_code(
                            email,
                            timeout=wait_time,
                            otp_sent_at=otp_anchor,
                            exclude_codes=tried_codes,
                        )
                    except Exception as exc:
                        self._log(f"等待验证码异常: {exc}")
                        otp_code = None

                    if not otp_code:
                        if is_cfworker_mail and not browser_resend_attempted:
                            browser_resend_attempted = True
                            self._log("暂未收到新的验证码，尝试浏览器原生 resend /api/accounts/email-otp/send")
                            resend_result = self._browser_send_email_otp()
                            self._last_otp_sent_at = time.time()
                            self._log(
                                "email-otp browser resend -> "
                                f"ok={resend_result.get('ok')} status={resend_result.get('status')} "
                                f"body={str(resend_result.get('text') or resend_result.get('error') or '')[:180]}"
                            )
                        self._log("暂未收到新的验证码，继续等待...")
                        continue

                    tried_codes.add(otp_code)
                    success, next_state = self.verify_email_otp(otp_code, return_state=True)
                    if success:
                        otp_verified = True
                        state = next_state
                        self.last_registration_state = state
                        verified = True
                        break

                    if "HTTP 401" in str(next_state):
                        self._log(f"验证码 {otp_code} 无效，继续等待下一封")
                        time.sleep(1)
                        continue
                    return False, f"验证码失败: {next_state}"

                if not verified:
                    return False, "未收到可用验证码"
                continue

            if self._state_is_about_you(state):
                if account_created:
                    return False, "填写信息阶段重复进入"
                success, next_state = self.create_account(
                    first_name,
                    last_name,
                    birthdate,
                    return_state=True,
                )
                if not success:
                    return False, f"创建账号失败: {next_state}"
                account_created = True
                state = next_state
                self.last_registration_state = state
                if self._state_is_chatgpt_login_with(state):
                    self._log("create_account 命中 existing-account ChatGPT 登录桥，交给 OAuth 恢复分支处理")
                    return True, "existing_account_login"
                continue

            if self._state_is_login_password(state):
                if register_submitted or otp_verified or account_created:
                    return False, f"existing-account 登录阶段异常回退: {describe_flow_state(state)}"
                self._log("检测到 existing-account 的 /log-in/password 起点，跳过全新注册，转入后续 web bridge / recovery")
                self.last_registration_state = state
                return True, "existing_account_login"

            if self._state_requires_navigation(state):
                success, next_state = self._follow_flow_state(
                    state,
                    referer=state.current_url or f"{self.AUTH}/about-you",
                )
                if not success:
                    return False, f"跳转失败: {next_state}"
                state = next_state
                self.last_registration_state = state
                continue

            if (not register_submitted) and (not otp_verified) and (not account_created):
                self._log(f"未知起始状态，回退为全新注册流程: {describe_flow_state(state)}")
                state = self._state_from_url(f"{self.AUTH}/create-account/password")
                continue

            return False, f"未支持的注册状态: {describe_flow_state(state)}"

        return False, "注册状态机超出最大步数"
