"""
OAuth 客户端模块 - 处理 Codex OAuth 登录流程
"""

import base64
import json
import re
import time
import secrets
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote, urlencode, urljoin

try:
    from curl_cffi import requests as curl_requests
except ImportError:
    import requests as curl_requests

from .utils import (
    FlowState,
    build_browser_headers,
    decode_jwt_payload,
    describe_flow_state,
    extract_flow_state,
    generate_datadog_trace,
    generate_pkce,
    normalize_flow_url,
    random_delay,
    seed_oai_device_cookie,
)
from .playwright_display import harden_playwright_context, prepare_playwright_launch_kwargs
from .sentinel_browser import mint_browser_sentinel_token
from .sentinel_token import build_sentinel_token


class OAuthClient:
    """OAuth 客户端 - 用于获取 Access Token 和 Refresh Token"""
    
    def __init__(self, config, proxy=None, verbose=True, browser_mode="protocol", session=None):
        """
        初始化 OAuth 客户端
        
        Args:
            config: 配置字典
            proxy: 代理地址
            verbose: 是否输出详细日志
            browser_mode: protocol | headless | headed
        """
        self.oauth_issuer = config.get("oauth_issuer", "https://auth.openai.com")
        self.oauth_client_id = config.get("oauth_client_id", "app_EMoamEEZ73f0CkXaXp7hrann")
        self.oauth_redirect_uri = config.get("oauth_redirect_uri", "http://localhost:1455/auth/callback")
        self.oauth_scope = config.get("oauth_scope", "openid profile email offline_access")
        self.oauth_audience = config.get("oauth_audience")
        self.oauth_prompt = config.get("oauth_prompt", "login")
        self.oauth_extra_authorize_params = config.get(
            "oauth_extra_authorize_params",
            {
                "id_token_add_organizations": "true",
                "codex_cli_simplified_flow": "true",
            },
        )
        self.proxy = proxy
        self.verbose = verbose
        self.browser_mode = browser_mode or "protocol"
        self.current_email = ""
        self.current_password = ""
        self.current_device_id = ""
        self.current_profile = {}
        self.current_skymail_client = None
        self.current_chatgpt_authorize_url = ""
        self.chatgpt_session_seed = {}
        self.last_direct_authorize_login_challenge_url = ""
        self.last_direct_authorize_log_in_dump = ""
        self.last_passwordless_send_otp_error_code = ""
        self.password_verify_led_to_email_otp = False
        self.prefer_email_otp_first = False
        self.reuse_existing_email_code_once = False
        self.ignore_otp_sent_at_once = False
        self.direct_authorize_before_about_you_once = False
        self.existing_account_guest_session_loop_count = 0
        self.last_successful_email_otp_code = ""
        self.last_successful_email_otp_at = 0.0
        self.last_login_failure_reason = ""
        self.last_flow_state_description = ""
        
        # 创建或复用 session
        self.session = session or curl_requests.Session()
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}
    
    def _log(self, msg):
        """输出日志"""
        if self.verbose:
            print(f"  [OAuth] {msg}")

    def _browser_pause(self, low=0.15, high=0.4):
        """在 headed 模式下注入轻微延迟，模拟真实浏览器操作节奏。"""
        if self.browser_mode == "headed":
            random_delay(low, high)

    def _set_login_failure_reason(self, reason, *, overwrite=True):
        reason = str(reason or "").strip()
        if not reason:
            return
        if (not overwrite) and str(getattr(self, "last_login_failure_reason", "") or "").strip():
            return
        self.last_login_failure_reason = reason

    def _remember_flow_state(self, state):
        try:
            self.last_flow_state_description = describe_flow_state(state)
        except Exception:
            self.last_flow_state_description = ""

    def _effective_device_id(self):
        device_id = str(getattr(self, "current_device_id", "") or "").strip()
        if device_id:
            return device_id
        return str(self._get_cookie_value("oai-did", "chatgpt.com") or "").strip()

    def _effective_auth_session_logging_id(self):
        session_data = self._decode_oauth_session_cookie() or {}
        value = str(session_data.get("auth_session_logging_id") or "").strip()
        if value:
            return value
        return secrets.token_urlsafe(18)

    def _remember_successful_email_otp(self, code):
        code = str(code or "").strip()
        if not code:
            return
        self.last_successful_email_otp_code = code
        self.last_successful_email_otp_at = time.time()

    def _get_recent_successful_email_otp(self, ttl_seconds=600):
        code = str(getattr(self, "last_successful_email_otp_code", "") or "").strip()
        if not code:
            return ""
        try:
            ts = float(getattr(self, "last_successful_email_otp_at", 0.0) or 0.0)
        except Exception:
            ts = 0.0
        if not ts:
            return ""
        if time.time() - ts > max(int(ttl_seconds or 0), 0):
            return ""
        return code

    def _should_force_fresh_otp_after_browser_submit(self, page_url, page_body, page_html):
        lowered = "\n".join(
            part.lower()
            for part in (page_url, page_body, page_html)
            if part
        )
        return "max_check_attempts" in lowered

    def _about_you_browser_failure_reason(self, *, error="", status=None):
        error = str(error or "").strip()
        if error == "warning_banner_guest_session":
            return "about_you_warning_banner_guest_session"
        if error:
            return f"about_you_browser_{error}"
        if status:
            return f"about_you_browser_http_{int(status)}"
        return "about_you_browser_unknown_failure"

    def _about_you_protocol_failure_reason(self, *, status=None, lowered_text=""):
        lowered_text = str(lowered_text or "").lower()
        if status == 400 and any(
            marker in lowered_text
            for marker in ("already_exists", "already exists", "user_already_exists")
        ):
            return "about_you_user_already_exists"
        if status == 400 and "registration_disallowed" in lowered_text:
            return "about_you_registration_disallowed"
        if status:
            return f"about_you_http_{int(status)}"
        return "about_you_unknown_failure"

    def _terminal_flow_failure_reason(self, kind, state_desc=""):
        kind = str(kind or "").strip()
        state_desc = str(state_desc or "").strip()
        if kind == "state_stuck":
            return f"state_stuck:{state_desc}" if state_desc else "state_stuck"
        if kind == "login_password_no_next_state":
            return "login_password_no_next_state"
        if kind == "oauth_state_machine_exceeded_max_steps":
            return (
                f"oauth_state_machine_exceeded_max_steps:{state_desc}"
                if state_desc
                else "oauth_state_machine_exceeded_max_steps"
            )
        return kind or "oauth_unknown_terminal_failure"

    def _build_seeded_chatgpt_session(self):
        seed = dict(getattr(self, "chatgpt_session_seed", {}) or {})
        access_token = (
            str(seed.get("access_token") or "").strip()
            or str(seed.get("accessToken") or "").strip()
        )
        if not access_token:
            return None

        user = dict(seed.get("user") or {})
        account = dict(seed.get("account") or {})

        workspace_id = (
            str(seed.get("workspace_id") or "").strip()
            or str(seed.get("account_id") or "").strip()
        )
        user_id = str(seed.get("user_id") or "").strip()
        email = str(seed.get("email") or getattr(self, "current_email", "") or "").strip()

        if workspace_id and not str(account.get("id") or "").strip():
            account["id"] = workspace_id
        if user_id and not str(user.get("id") or "").strip():
            user["id"] = user_id
        if email and not str(user.get("email") or "").strip():
            user["email"] = email

        seeded = dict(seed)
        seeded["accessToken"] = access_token
        if str(seed.get("session_token") or "").strip():
            seeded["sessionToken"] = str(seed.get("session_token") or "").strip()
        if user:
            seeded["user"] = user
        if account:
            seeded["account"] = account
        expires = str(seed.get("expires") or seed.get("expires_in") or "").strip()
        if expires:
            seeded["expires"] = expires
        return seeded

    def _seed_chatgpt_web_cookies_from_seed(self):
        seed = dict(getattr(self, "chatgpt_session_seed", {}) or {})
        bundle = dict(seed.get("cookie_bundle") or {})
        bundle_items = list(bundle.get("cookies") or [])
        cookie_header = (
            str(bundle.get("cookie_header") or "").strip()
            or str(seed.get("cookies") or "").strip()
        )
        seeded = 0

        for item in bundle_items:
            try:
                name = str((item or {}).get("name") or "").strip()
                value = str((item or {}).get("value") or "")
                domain = str((item or {}).get("domain") or "").strip()
                path = str((item or {}).get("path") or "/").strip() or "/"
                secure = bool((item or {}).get("secure", False))
                if not name or not value or not domain:
                    continue
                try:
                    self.session.cookies.set(
                        name,
                        value,
                        domain=domain,
                        path=path,
                        secure=secure,
                    )
                    seeded += 1
                except Exception:
                    try:
                        self.session.cookies.set(name, value, domain=domain, path=path)
                        seeded += 1
                    except Exception:
                        continue
            except Exception:
                continue

        if seeded == 0 and cookie_header:
            preferred_domains = [".chatgpt.com", "chatgpt.com"]
            for raw_part in cookie_header.split(";"):
                part = str(raw_part or "").strip()
                if not part or "=" not in part:
                    continue
                name, value = part.split("=", 1)
                name = str(name or "").strip()
                value = str(value or "").strip()
                if not name or not value:
                    continue
                for domain in preferred_domains:
                    try:
                        self.session.cookies.set(name, value, domain=domain, path="/")
                        seeded += 1
                        break
                    except Exception:
                        continue

        if seeded:
            auth_domains = 0
            chatgpt_domains = 0
            for cookie in list(getattr(self.session.cookies, "jar", []) or []):
                domain = str(getattr(cookie, "domain", "") or "").lower()
                if "auth.openai.com" in domain or domain.endswith(".openai.com"):
                    auth_domains += 1
                if "chatgpt.com" in domain:
                    chatgpt_domains += 1
            self._log(
                "已从 ChatGPT Web token seed 注入 cookies "
                f"seeded={seeded} auth/openai={auth_domains} chatgpt={chatgpt_domains}"
            )
        return seeded

    def _load_workspace_session_data_from_seed(self):
        seeded_session = self._build_seeded_chatgpt_session()
        if not seeded_session:
            return None

        normalized = self._normalize_chatgpt_session_tokens(seeded_session) or {}
        workspace_id = str(normalized.get("workspace_id") or "").strip()
        if not workspace_id:
            return None

        account = dict(seeded_session.get("account") or {})
        cookie_session = self._decode_oauth_session_cookie() or {}
        session_payload = {
            "session_id": str(cookie_session.get("session_id") or "").strip(),
            "openai_client_id": str(
                cookie_session.get("openai_client_id") or self.oauth_client_id or ""
            ).strip(),
            "workspaces": [{"id": workspace_id}],
        }
        organization_id = str(
            account.get("organization_id")
            or account.get("org_id")
            or ""
        ).strip()
        if organization_id:
            session_payload["workspaces"][0]["organization_id"] = organization_id

        self._maybe_seed_oauth_session_cookie(
            session_payload,
            existing_session=cookie_session,
            reason="seed_workspace_only",
        )
        self._log(
            "从已有 ChatGPT Web token seed 回填 workspace: "
            f"{workspace_id}"
        )
        return session_payload

    def _native_nextauth_signin_in_page(self, page, *, email, device_id, auth_session_logging_id):
        if not email:
            return None
        try:
            return page.evaluate(
                """
                async ({ email, deviceId, authSessionLoggingId }) => {
                  try {
                    const authBase = 'https://chatgpt.com';
                    const pageUrl = String(window.location.href || '');
                    const pageOrigin = String(window.location.origin || '');
                    if (pageOrigin !== authBase) {
                      return {
                        error: 'cross_origin_page_not_chatgpt',
                        pageUrl,
                        pageOrigin,
                        documentCookie: document.cookie,
                      };
                    }
                    const csrfResp = await fetch(authBase + '/api/auth/csrf', {
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
                      callbackUrl: authBase + '/',
                      csrfToken: (csrfData && csrfData.csrfToken) || '',
                      json: 'true',
                    });
                    const resp = await fetch(authBase + '/api/auth/signin/openai?' + qs.toString(), {
                      method: 'POST',
                      credentials: 'include',
                      redirect: 'manual',
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
                      pageUrl,
                      pageOrigin,
                      csrfStatus: csrfResp.status,
                      status: resp.status,
                      responseUrl: resp.url,
                      locationHeader: resp.headers.get('location') || '',
                      data,
                      text: text.slice(0, 600),
                      documentCookie: document.cookie,
                    };
                  } catch (error) {
                    return {
                      error: String(error),
                      pageUrl: String(window.location.href || ''),
                      pageOrigin: String(window.location.origin || ''),
                      documentCookie: document.cookie,
                    };
                  }
                }
                """,
                {
                    "email": email,
                    "deviceId": device_id,
                    "authSessionLoggingId": auth_session_logging_id,
                },
            )
        except Exception as exc:
            self._log(f"native next-auth signin 异常: {exc}")
            return None

    def _resume_chatgpt_web_authorize_flow(
        self,
        final_url,
        *,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
        skymail_client=None,
        profile=None,
    ):
        state = self._state_from_url(final_url)
        referer = "https://chatgpt.com/api/auth/signin/openai"
        profile_data = profile or getattr(self, "current_profile", {}) or {}
        mailbox_client = skymail_client or getattr(self, "current_skymail_client", None)
        device_id = self._effective_device_id()
        password_value = str(getattr(self, "current_password", "") or "").strip()
        email_value = str(getattr(self, "current_email", "") or "").strip()
        authorize_reentry_used = 0
        if any(
            marker in str(final_url or "").lower()
            for marker in ("/api/accounts/authorize", "/oauth/authorize", "/api/oauth/oauth2/auth")
        ):
            self.current_chatgpt_authorize_url = str(final_url or "").strip()

        for _ in range(12):
            current_target = str(state.continue_url or state.current_url or "").strip()
            if any(
                marker in current_target.lower()
                for marker in ("/api/accounts/authorize", "/oauth/authorize", "/api/oauth/oauth2/auth")
            ):
                self.current_chatgpt_authorize_url = current_target
            callback_tokens = self._try_chatgpt_callback_session_from_state(
                state,
                user_agent=user_agent,
                impersonate=impersonate,
                referer=referer,
            )
            if callback_tokens:
                return callback_tokens

            retry_url, retry_meta = self._extract_auth_error_retry_url(
                current_target or str(state.current_url or "").strip()
            )
            if retry_url:
                self._log(
                    "ChatGPT Web 子流程命中 auth error，改走 retryUrl "
                    f"{retry_url[:140]} req={retry_meta.get('request_id')}"
                )
                referer = state.current_url or state.continue_url or referer
                state = self._state_from_url(retry_url)
                continue

            session_data = self._fetch_chatgpt_session(user_agent=user_agent)
            if session_data:
                normalized = self._normalize_chatgpt_session_tokens(session_data)
                if normalized:
                    return normalized

            if (state.page_type or "") in {
                "log_in",
                "log_in_or_create_account",
                "log_in_or_sign_up",
            }:
                if not email_value or not device_id:
                    return None
                self._log(
                    f"ChatGPT Web 子流程检测到 {(state.page_type or 'log_in')}，重新提交 authorize/continue"
                )
                next_state = self._submit_authorize_continue(
                    email_value,
                    device_id,
                    state.current_url or referer or f"{self.oauth_issuer}/log-in",
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                )
                if not next_state:
                    return None
                if isinstance(next_state, dict) and next_state.get("access_token"):
                    return next_state
                referer = state.current_url or state.continue_url or referer
                state = next_state
                continue

            if self._state_is_login_password(state):
                if not password_value or not device_id:
                    return None
                next_state = self._submit_password_verify(
                    password_value,
                    device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                    referer=state.current_url or state.continue_url or referer,
                )
                if not next_state:
                    return None
                referer = state.current_url or state.continue_url or referer
                state = next_state
                continue

            if self._state_is_email_otp(state):
                next_state = None
                prefer_email_otp_first = bool(getattr(self, "prefer_email_otp_first", True))
                force_email_otp_after_password = bool(
                    getattr(self, "password_verify_led_to_email_otp", False)
                )
                if (
                    prefer_email_otp_first
                    and bool(getattr(self, "reuse_existing_email_code_once", False))
                    and mailbox_client
                ):
                    used_codes = set(getattr(mailbox_client, "_used_codes", set()) or set())
                    if used_codes:
                        self._log(
                            "ChatGPT Web 子流程允许复用最近邮箱验证码一次，"
                            f"先清空已用集合: {sorted(used_codes)}"
                        )
                        mailbox_client._used_codes = set()
                    if hasattr(mailbox_client, "_baseline_id"):
                        old_baseline = str(getattr(mailbox_client, "_baseline_id", "") or "")
                        setattr(mailbox_client, "_baseline_id", "")
                        if old_baseline:
                            self._log(
                                "ChatGPT Web 子流程允许回看最新邮箱验证码，"
                                f"清空 baseline_id: {old_baseline}"
                            )
                    elif hasattr(mailbox_client, "baseline"):
                        old_baseline = str(getattr(mailbox_client, "baseline", "") or "")
                        setattr(mailbox_client, "baseline", "0")
                        if old_baseline:
                            self._log(
                                "ChatGPT Web 子流程允许回看最新邮箱验证码，"
                                f"清空 baseline: {old_baseline}"
                            )
                    self.ignore_otp_sent_at_once = True
                    self._log("ChatGPT Web 子流程本轮忽略 otp_sent_at 锚点，允许回看最近验证码")
                    self.reuse_existing_email_code_once = False
                if force_email_otp_after_password:
                    self._log(
                        "ChatGPT Web 子流程检测到上一跳 password_verify 已触发邮箱 OTP，"
                        "本轮优先等待真实邮箱 OTP"
                    )
                if prefer_email_otp_first:
                    if mailbox_client and email_value and device_id:
                        self._log("ChatGPT Web 子流程命中 email-verification，优先尝试邮箱 OTP")
                        next_state = self._handle_otp_verification(
                            email_value,
                            device_id,
                            user_agent,
                            sec_ch_ua,
                            impersonate,
                            mailbox_client,
                            state,
                        )
                    if not next_state and password_value and device_id and not force_email_otp_after_password:
                        self._log("ChatGPT Web 子流程 email-verification 改走旧密码回退")
                        next_state = self._submit_password_verify(
                            password_value,
                            device_id,
                            user_agent=user_agent,
                            sec_ch_ua=sec_ch_ua,
                            impersonate=impersonate,
                            referer=state.current_url or state.continue_url or referer,
                        )
                else:
                    if password_value and device_id and not force_email_otp_after_password:
                        self._log("ChatGPT Web 子流程命中 email-verification，优先尝试旧密码回退")
                        next_state = self._submit_password_verify(
                            password_value,
                            device_id,
                            user_agent=user_agent,
                            sec_ch_ua=sec_ch_ua,
                            impersonate=impersonate,
                            referer=state.current_url or state.continue_url or referer,
                        )
                    if not next_state and mailbox_client and email_value and device_id:
                        self._log("ChatGPT Web 子流程 email-verification 密码回退失败，改走邮箱 OTP")
                        next_state = self._handle_otp_verification(
                            email_value,
                            device_id,
                            user_agent,
                            sec_ch_ua,
                            impersonate,
                            mailbox_client,
                            state,
                        )
                if not next_state:
                    return None
                referer = state.current_url or state.continue_url or referer
                state = next_state
                continue

            if self._state_is_about_you(state):
                reentry_target = str(getattr(self, "current_chatgpt_authorize_url", "") or "").strip()
                if (
                    bool(getattr(self, "direct_authorize_before_about_you_once", False))
                    and reentry_target
                    and authorize_reentry_used < 2
                ):
                    self.direct_authorize_before_about_you_once = False
                    authorize_reentry_used += 1
                    self._log(
                        "ChatGPT Web 子流程的 about_you 先回放原始 authorize URL，"
                        "避免再次死在 create_account/already_exists"
                    )
                    referer = state.current_url or state.continue_url or referer
                    state = self._state_from_url(reentry_target)
                    continue
                if not profile_data or not profile_data.get("birthdate") or not device_id:
                    return None
                next_state = self._submit_about_you(
                    profile_data.get("first_name", ""),
                    profile_data.get("last_name", ""),
                    profile_data.get("birthdate", ""),
                    device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                    referer=state.current_url or state.continue_url or referer,
                )
                if isinstance(next_state, dict) and next_state.get("access_token"):
                    return next_state
                if not next_state:
                    return None
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
                    self._log(
                        "ChatGPT Web 子流程 about_you 命中 existing-account，优先回放原始 authorize URL"
                    )
                    referer = state.current_url or state.continue_url or referer
                    state = self._state_from_url(reentry_target)
                    continue
                referer = state.current_url or state.continue_url or referer
                state = next_state
                continue

            raw_target = str(state.continue_url or state.current_url or "").strip()
            lowered_target = raw_target.lower()
            if "chatgpt.com/auth/login_with" in lowered_target or "chatgpt.com/auth/error" in lowered_target:
                self._log("ChatGPT Web 子流程命中 auth_login_with/auth_error，直接切浏览器 bridge")
                hydrated = self._browser_hydrate_chatgpt_session(
                    consent_url=raw_target or "https://chatgpt.com/auth/login_with",
                    user_agent=user_agent,
                )
                if hydrated:
                    return hydrated
                return None

            if self._state_requires_navigation(state):
                _, next_state = self._follow_flow_state(
                    state,
                    referer=referer,
                    user_agent=user_agent,
                    impersonate=impersonate,
                )
                if not next_state:
                    return None
                referer = state.current_url or state.continue_url or referer
                state = next_state
                continue

            return None

        return None

    def _mint_browser_sentinel_token(self, page_url, flow, *, user_agent=None):
        result = mint_browser_sentinel_token(
            proxy=self.proxy,
            browser_mode=self.browser_mode,
            context_kwargs=self._playwright_context_kwargs(user_agent=user_agent),
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
            detail = result.get("error") or result.get("exception") or result.get("page_url") or ""
            self._log(f"browser sentinel token 失败 flow={flow}: {detail}")
        return token

    def _submit_about_you_browser_fallback(
        self,
        first_name,
        last_name,
        birthdate,
        *,
        referer=None,
        user_agent=None,
    ):
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
        except Exception as exc:
            self._log(f"about_you 浏览器 fallback 不可用: {exc}")
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
        about_you_url = referer or f"{self.oauth_issuer}/about-you"

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**launch_kwargs)
                try:
                    context = harden_playwright_context(
                        browser.new_context(**self._playwright_context_kwargs(user_agent=user_agent))
                    )
                    cookies = self._cookies_for_playwright()
                    self._add_cookies_to_playwright_context(context, cookies, "oauth about_you browser fallback")
                    page = context.new_page()

                    def _body_preview(limit=1600):
                        try:
                            return (page.locator("body").inner_text(timeout=3000) or "")[:limit]
                        except Exception:
                            return ""

                    def _looks_like_challenge(*parts):
                        lowered = "\n".join(str(part or "").lower() for part in parts)
                        return any(
                            marker in lowered
                            for marker in (
                                "just a moment",
                                "cf-challenge",
                                "cloudflare",
                                "/cdn-cgi/challenge-platform/",
                            )
                        )

                    def _bridge_same_browser_chatgpt_session():
                        login_with_url = "https://chatgpt.com/auth/login_with"
                        signin_bridge_url = (
                            "https://chatgpt.com/api/auth/signin/openai"
                            "?callbackUrl=https%3A%2F%2Fchatgpt.com%2F"
                        )
                        email_value = str(getattr(self, "current_email", "") or "").strip()
                        device_id = self._effective_device_id()
                        def _clear_bridge_error_cookies():
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
                                    "oauth about_you browser bridge: 已清理 bridge error cookies "
                                    f"({','.join(sorted(cookie_names))})"
                                )
                            except Exception as exc:
                                self._log(f"oauth about_you browser bridge 清理 error cookies 失败: {exc}")

                        try:
                            self._log("oauth about_you browser fallback: user_already_exists，尝试同浏览器 ChatGPT bridge")
                            page.goto(login_with_url, wait_until="domcontentloaded", timeout=45000)
                        except Exception as exc:
                            self._log(f"oauth about_you browser bridge 打开失败: {exc}")
                            return None

                        start_wait = time.time()
                        login_with_attempted = True
                        signin_bridge_attempted = False
                        native_signin_attempted = False
                        auth_resume_attempted = set()
                        warning_banner_guest_hits = 0
                        while time.time() - start_wait <= 45:
                            self._sync_playwright_cookies(context.cookies())
                            current_url = str(page.url or "")

                            callback_tokens = self._try_chatgpt_callback_session(
                                current_url,
                                user_agent=user_agent,
                                referer="https://chatgpt.com/",
                            )
                            if callback_tokens:
                                self._log("oauth about_you browser bridge: callback/openai 恢复成功")
                                return callback_tokens

                            try:
                                page_host = (urlparse(current_url).netloc or "").lower()
                            except Exception:
                                page_host = ""
                            lowered_url = current_url.lower()

                            retry_url, retry_meta = self._extract_auth_error_retry_url(current_url)
                            if retry_url:
                                self._log(
                                    "oauth about_you browser bridge: 命中 auth error，改走 retryUrl "
                                    f"{retry_url[:140]} req={retry_meta.get('request_id')}"
                                )
                                _clear_bridge_error_cookies()
                                try:
                                    page.goto(retry_url, wait_until="domcontentloaded", timeout=45000)
                                    page.wait_for_timeout(3500)
                                    self._sync_playwright_cookies(context.cookies())
                                    continue
                                except Exception as exc:
                                    self._log(f"oauth about_you browser bridge retryUrl 跳转失败: {exc}")

                            body = _body_preview(1000)
                            lowered_body = str(body or "").lower()
                            looks_like_guest_home = (
                                "chatgpt.com" in lowered_body
                                and "log in" in lowered_body
                                and (
                                    "sign up for free" in lowered_body
                                    or "get responses tailored to you" in lowered_body
                                    or "/auth/error" in lowered_body
                                )
                            )

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
                                    self._log(f"oauth about_you browser bridge session fetch 异常: {exc}")
                                    browser_session = None

                                if isinstance(browser_session, dict):
                                    if browser_session.get("error"):
                                        self._log(
                                            "oauth about_you browser bridge session 异常: "
                                            f"{browser_session['error']}"
                                        )
                                    else:
                                        status = browser_session.get("status")
                                        self._log(
                                            "oauth about_you browser bridge session -> "
                                            f"HTTP {status} {str(browser_session.get('url') or '')[:120]}"
                                        )
                                        session_data = browser_session.get("data")
                                        if isinstance(session_data, dict):
                                            normalized = self._normalize_chatgpt_session_tokens(session_data)
                                            if normalized:
                                                return normalized
                                            probe = self._collect_chatgpt_browser_probe(page, context)
                                            warning_banner_only = self._chatgpt_session_warning_banner_only(session_data)
                                            guest_probe = self._chatgpt_probe_looks_guest_session(probe)
                                            self._log(
                                                "oauth about_you browser bridge session keys: "
                                                f"{','.join(list(session_data.keys())[:20])}"
                                            )
                                            self._dump_bridge_snapshot(
                                                reason="chatgpt_session_browser",
                                                user_agent=user_agent,
                                                extra={
                                                    "url": browser_session.get("url"),
                                                    "keys": list(session_data.keys()),
                                                    "data": session_data,
                                                    "page_url": current_url,
                                                    "probe": probe,
                                                },
                                            )
                                            if warning_banner_only and guest_probe:
                                                warning_banner_guest_hits += 1
                                                pending_transition_attempts = (
                                                    (not signin_bridge_attempted)
                                                    or (not native_signin_attempted and bool(email_value) and bool(device_id))
                                                )
                                                if pending_transition_attempts:
                                                    self._log(
                                                        "oauth about_you browser bridge: 当前仍是 WARNING_BANNER guest session "
                                                        f"({warning_banner_guest_hits}/2)，但 bridge 过渡步骤尚未耗尽，继续推进"
                                                    )
                                                else:
                                                    self._log(
                                                        "oauth about_you browser bridge: 判定为 WARNING_BANNER guest session "
                                                        f"({warning_banner_guest_hits}/2)，停止继续空转"
                                                    )
                                                if warning_banner_guest_hits >= 2 and not pending_transition_attempts:
                                                    return {
                                                        "error": "warning_banner_guest_session",
                                                        "page_url": current_url,
                                                        "probe": probe,
                                                        "session": session_data,
                                                    }

                            if (
                                not login_with_attempted
                                and looks_like_guest_home
                            ):
                                login_with_attempted = True
                                self._log("oauth about_you browser bridge: guest 首页改走 /auth/login_with")
                                try:
                                    page.goto(login_with_url, wait_until="domcontentloaded", timeout=45000)
                                    page.wait_for_timeout(4000)
                                    self._sync_playwright_cookies(context.cookies())
                                    continue
                                except Exception as exc:
                                    self._log(f"oauth about_you browser bridge: /auth/login_with 跳转失败: {exc}")

                            session_data = self._fetch_chatgpt_session(user_agent=user_agent)
                            if session_data:
                                normalized = self._normalize_chatgpt_session_tokens(session_data)
                                if normalized:
                                    self._log("oauth about_you browser bridge: 通过 /api/auth/session 恢复成功")
                                    return normalized
                            else:
                                self._log("oauth about_you browser bridge session 未就绪: /api/auth/session 未返回 accessToken")

                            if (
                                page_host.endswith("auth.openai.com")
                                and lowered_url not in auth_resume_attempted
                                and any(
                                    marker in lowered_url
                                    for marker in (
                                        "/email-verification",
                                        "/log-in",
                                        "/log-in/password",
                                        "/about-you",
                                        "/api/accounts/authorize",
                                        "/oauth/authorize",
                                        "/api/oauth/oauth2/auth",
                                    )
                                )
                            ):
                                auth_resume_attempted.add(lowered_url)
                                self._log(
                                    "oauth about_you browser bridge: 检测到 auth.openai.com 子流程，尝试协议恢复 "
                                    f"{current_url[:140]}"
                                )
                                resumed = self._resume_chatgpt_web_authorize_flow(
                                    current_url,
                                    user_agent=user_agent,
                                    skymail_client=getattr(self, "current_skymail_client", None),
                                )
                                if resumed:
                                    self._log("oauth about_you browser bridge: auth.openai.com 子流程恢复成功")
                                    return resumed

                            body = _body_preview(1000)
                            lowered_body = str(body or "").lower()
                            if (
                                not signin_bridge_attempted
                                and "chatgpt.com" in current_url
                                and (
                                    "/auth/login_with" in current_url
                                    or "/auth/error" in current_url
                                    or "log in" in lowered_body
                                    or "sign up for free" in lowered_body
                                )
                            ):
                                signin_bridge_attempted = True
                                self._log("oauth about_you browser bridge: /auth/login_with 未直接起效，尝试 native next-auth signin URL")
                                _clear_bridge_error_cookies()
                                try:
                                    page.goto(signin_bridge_url, wait_until="domcontentloaded", timeout=45000)
                                    page.wait_for_timeout(3500)
                                    self._sync_playwright_cookies(context.cookies())
                                    continue
                                except Exception as exc:
                                    self._log(f"oauth about_you browser bridge 打开 signin/openai 失败: {exc}")
                            if (
                                not native_signin_attempted
                                and "chatgpt.com" in current_url
                                and (
                                    "/auth/login_with" in current_url
                                    or "/auth/error" in current_url
                                    or "log in" in lowered_body
                                    or "sign up for free" in lowered_body
                                )
                                and email_value
                                and device_id
                            ):
                                native_signin_attempted = True
                                _clear_bridge_error_cookies()
                                native_result = self._native_nextauth_signin_in_page(
                                    page,
                                    email=email_value,
                                    device_id=device_id,
                                    auth_session_logging_id=self._effective_auth_session_logging_id(),
                                )
                                if isinstance(native_result, dict):
                                    if native_result.get("error"):
                                        if native_result.get("error") == "cross_origin_page_not_chatgpt":
                                            native_signin_attempted = False
                                            self._log(
                                                "oauth about_you browser bridge native next-auth 命中 cross_origin_page_not_chatgpt，"
                                                "不消耗本轮 native attempt，等待回到 chatgpt.com 再试"
                                            )
                                        self._log(
                                            "oauth about_you browser bridge native next-auth 错误: "
                                            f"{native_result['error']}"
                                        )
                                        self._log(
                                            "oauth about_you browser bridge native next-auth 上下文: "
                                            f"page={str(native_result.get('pageUrl') or '')[:140]} "
                                            f"origin={str(native_result.get('pageOrigin') or '')[:80]}"
                                        )
                                    else:
                                        self._log(
                                            "oauth about_you browser bridge native next-auth -> "
                                            f"HTTP {native_result.get('status')} {str(native_result.get('responseUrl') or '')[:120]}"
                                        )
                                        native_status = int(native_result.get("status") or 0)
                                        if native_status == 200:
                                            self.ignore_otp_sent_at_once = True
                                            self._log(
                                                "oauth about_you browser bridge: native next-auth 可能已提前触发 OTP，"
                                                "下一轮允许回看最近验证码"
                                            )
                                        data = native_result.get("data") or {}
                                        auth_url = str(data.get("url") or "").strip()
                                        if not auth_url:
                                            auth_url = str(native_result.get("locationHeader") or "").strip()
                                        if (not auth_url) and native_result.get("text"):
                                            match = re.search(
                                                r"https://auth\\.openai\\.com[^\"'\\s<]+",
                                                native_result["text"],
                                            )
                                            auth_url = match.group(0) if match else ""
                                        if auth_url:
                                            self.current_chatgpt_authorize_url = auth_url
                                            self._sync_playwright_cookies(context.cookies())
                                            resumed = self._resume_chatgpt_web_authorize_flow(
                                                auth_url,
                                                user_agent=user_agent,
                                                skymail_client=getattr(self, "current_skymail_client", None),
                                            )
                                            if resumed:
                                                self._log("oauth about_you browser bridge: native next-auth 子流程恢复成功")
                                                return resumed
                                            try:
                                                page.goto(auth_url, wait_until="domcontentloaded", timeout=45000)
                                                page.wait_for_timeout(3500)
                                                self._sync_playwright_cookies(context.cookies())
                                                continue
                                            except Exception as exc:
                                                self._log(
                                                    "oauth about_you browser bridge native next-auth 跳转 auth_url 失败，改走协议恢复: "
                                                    f"{exc}"
                                                )
                            if _looks_like_challenge(body):
                                self._log("oauth about_you browser bridge: challenge 仍在，继续等待")
                            page.wait_for_timeout(2500)

                        return None

                    def _fill_about_you():
                        for nav_attempt in range(2):
                            page.goto(about_you_url, wait_until="domcontentloaded", timeout=45000)
                            try:
                                page.wait_for_function(
                                    """
                                    () => {
                                      const nameInput = document.querySelector('input[name="name"]');
                                      const birthdayInput = document.querySelector('input[name="birthday"]');
                                      const spinbuttons = document.querySelectorAll('[role=spinbutton]');
                                      return !!nameInput && (!!birthdayInput || spinbuttons.length >= 3);
                                    }
                                    """,
                                    timeout=60000,
                                )
                            except PlaywrightTimeoutError:
                                body = _body_preview(1200)
                                current_url = str(page.url or about_you_url or "")
                                redirect_state = self._state_from_url(current_url)
                                self._log(
                                    "oauth about_you 表单等待超时: "
                                    f"url={current_url[:140]} state={redirect_state.page_type or '-'} "
                                    f"body={body[:180]!r}"
                                )
                                if _looks_like_challenge(body) and nav_attempt == 0:
                                    self._log("oauth about_you 仍在 challenge，等待 clearance")
                                    page.wait_for_function(
                                        "() => !document.body || !/just a moment|cloudflare/i.test(document.body.innerText || '')",
                                        timeout=120000,
                                    )
                                    page.wait_for_timeout(3000)
                                    self._sync_playwright_cookies(context.cookies())
                                    continue
                                if redirect_state.page_type and redirect_state.page_type != "about_you":
                                    self._log(
                                        "oauth about_you 页面未进入表单，直接返回当前 auth 状态: "
                                        f"{describe_flow_state(redirect_state)}"
                                    )
                                    return {
                                        "redirect_state": redirect_state,
                                        "page_url": current_url,
                                        "body": body,
                                    }
                                raise
                            page.wait_for_timeout(1200)
                            page.locator('input[name="name"]').fill(name, timeout=5000)
                            try:
                                page.evaluate(
                                    """
                                    ({birthdate}) => {
                                      const input = document.querySelector('input[name="birthday"]');
                                      if (!input) return false;
                                      input.value = birthdate;
                                      input.dispatchEvent(new Event('input', {bubbles: true}));
                                      input.dispatchEvent(new Event('change', {bubbles: true}));
                                      return true;
                                    }
                                    """,
                                    {"birthdate": birthdate},
                                )
                            except Exception:
                                pass
                            try:
                                spinbuttons = page.get_by_role("spinbutton")
                                spinbutton_count = spinbuttons.count()
                            except Exception:
                                spinbutton_count = 0
                            if spinbutton_count >= 3:
                                for idx, value in enumerate((month, day, year)):
                                    spinbuttons.nth(idx).fill(value, timeout=5000)
                                    page.wait_for_timeout(250)
                            try:
                                return page.locator('input[name="birthday"]').input_value()
                            except Exception:
                                return ""
                        return ""

                    hidden_birthdate = ""
                    for attempt in range(2):
                        fill_result = _fill_about_you()
                        if isinstance(fill_result, dict) and fill_result.get("redirect_state") is not None:
                            redirect_state = fill_result.get("redirect_state")
                            result = {
                                "ok": False,
                                "error": "about_you_redirected_before_form",
                                "page_url": fill_result.get("page_url") or page.url,
                                "body": fill_result.get("body") or "",
                                "state": redirect_state,
                            }
                            break
                        hidden_birthdate = str(fill_result or "")
                        if hidden_birthdate != birthdate:
                            self._log(f"oauth about_you 生日未同步，实际为: {hidden_birthdate}")

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
                            self._log(f"oauth about_you browser fetch 未拿到 sentinel token: {exc}")

                        if browser_token:
                            fetch_result = page.evaluate(
                                """
                                async ({name, birthdate, token}) => {
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
                                  } catch (err) {}
                                  return {
                                    status: response.status,
                                    ok: response.ok,
                                    text: text.slice(0, 1200),
                                    json: jsonBody,
                                    pageUrl: window.location.href,
                                    bodyText: (document.body && document.body.innerText) ? document.body.innerText.slice(0, 1600) : ""
                                  };
                                }
                                """,
                                {"name": name, "birthdate": birthdate, "token": browser_token},
                            )
                            fetch_status = fetch_result.get("status")
                            fetch_text = str(fetch_result.get("text") or "")[:1200]
                            fetch_body = str(fetch_result.get("bodyText") or "")[:1600]
                            page_url = fetch_result.get("pageUrl") or page.url
                            self._log(
                                "oauth about_you browser fetch -> "
                                f"status={fetch_status} url={str(page_url)[:140]}"
                            )
                            lowered_fetch = "\n".join((fetch_text, fetch_body)).lower()
                            if fetch_status == 200:
                                data = fetch_result.get("json") or {}
                                state = self._state_from_payload(data, current_url=page_url)
                                if not state.page_type:
                                    state = self._state_from_url(page_url)
                                result = {
                                    "ok": True,
                                    "status": fetch_status,
                                    "text": fetch_text,
                                    "page_url": page_url,
                                    "body": fetch_body,
                                    "hidden_birthdate": hidden_birthdate,
                                    "state": state,
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
                                self._log(
                                    "oauth about_you browser fallback: fetch 命中 user_already_exists，"
                                    "先继续真实页面 submit，避免遗漏页面自带隐藏上下文"
                                )
                                fetch_user_already_exists = True
                            else:
                                fetch_user_already_exists = False
                            if "registration_disallowed" in lowered_fetch:
                                result = {
                                    "ok": False,
                                    "status": fetch_status,
                                    "text": fetch_text,
                                    "page_url": page_url,
                                    "body": fetch_body,
                                    "hidden_birthdate": hidden_birthdate,
                                    "error": "registration_disallowed",
                                    "state": self._chatgpt_login_with_state(),
                                }
                                break
                            if "invalid_auth_step" in lowered_fetch:
                                self._log(
                                    "oauth about_you browser fallback: invalid_auth_step，"
                                    "直接回退 existing-account 恢复状态"
                                )
                                reentry_target = str(getattr(self, "current_chatgpt_authorize_url", "") or "").strip()
                                result = {
                                    "ok": False,
                                    "status": fetch_status,
                                    "text": fetch_text,
                                    "page_url": page_url,
                                    "body": fetch_body,
                                    "hidden_birthdate": hidden_birthdate,
                                    "error": "invalid_auth_step",
                                    "state": (
                                        self._state_from_url(reentry_target)
                                        if reentry_target
                                        else self._chatgpt_login_with_state()
                                    ),
                                }
                                break
                            if fetch_status == 403 and _looks_like_challenge(fetch_text, fetch_body):
                                self._log("oauth about_you browser fetch 收到 403 challenge，继续尝试页面提交流程")
                            elif fetch_status and fetch_status != 200:
                                preview = fetch_text or fetch_body
                                if preview:
                                    self._log(f"oauth about_you browser fetch body: {preview[:240]}")

                        response = None
                        try:
                            with page.expect_response(
                                lambda resp: "/api/accounts/create_account" in resp.url,
                                timeout=20000,
                            ) as response_info:
                                page.locator('button[type="submit"]').click(timeout=5000)
                            response = response_info.value
                        except PlaywrightTimeoutError as exc:
                            body = _body_preview(1200)
                            if _looks_like_challenge(body) and attempt == 0:
                                self._log("oauth about_you 命中 challenge 页面，等待 clearance 后重试")
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
                            }
                            break
                        else:
                            page.wait_for_timeout(2500)
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
                                self._log(
                                    "oauth about_you 页面提交流程: user_already_exists，"
                                    "再尝试同浏览器 ChatGPT bridge"
                                )
                                bridge_tokens = _bridge_same_browser_chatgpt_session()
                                if isinstance(bridge_tokens, dict) and bridge_tokens.get("access_token"):
                                    result["ok"] = True
                                    result["tokens"] = bridge_tokens
                                    result["state"] = self._state_from_url(page_url or about_you_url)
                                    break
                                bridge_error = str((bridge_tokens or {}).get("error") or "").strip()
                                if bridge_error == "warning_banner_guest_session":
                                    self._log(
                                        "oauth about_you 页面提交流程: 同浏览器 bridge 已判定为 "
                                        "WARNING_BANNER guest session，终止当前 app_X 恢复"
                                    )
                                    result["error"] = bridge_error
                                    break
                                self._log(
                                    "oauth about_you 页面提交流程: 同浏览器 ChatGPT bridge "
                                    "未直接恢复 token，回退 existing-account 状态机"
                                )
                                reentry_target = str(getattr(self, "current_chatgpt_authorize_url", "") or "").strip()
                                result["error"] = "user_already_exists"
                                result["state"] = (
                                    self._state_from_url(reentry_target)
                                    if reentry_target
                                    else self._chatgpt_login_with_state()
                                )
                                break
                            if "registration_disallowed" in lowered:
                                result["error"] = "registration_disallowed"
                                result["state"] = self._chatgpt_login_with_state()
                                break
                            if status == 403 and _looks_like_challenge(text, body) and attempt == 0:
                                self._log("oauth about_you 页面提交流程收到 403 challenge，等待 clearance 后重试")
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
                finally:
                    browser.close()
        except Exception as exc:
            result = {"ok": False, "error": "browser_fallback_exception", "exception": repr(exc)}
        return result

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

    def _extract_auth_error_retry_url(self, value):
        candidate = normalize_flow_url(value, auth_base=self.oauth_issuer)
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
        retry_url = normalize_flow_url(str(payload.get("retryUrl") or "").strip(), auth_base="https://chatgpt.com")
        meta = {
            "kind": str(payload.get("kind") or "").strip(),
            "request_id": str(payload.get("requestId") or "").strip(),
            "error_code": str(payload.get("errorCode") or "").strip(),
            "session_id": str((query.get("session_id") or [""])[0] or "").strip(),
            "verifier_id": str((query.get("verifier_id") or [""])[0] or "").strip(),
        }
        return retry_url, meta

    def _chatgpt_login_with_state(self):
        url = "https://chatgpt.com/auth/login_with"
        return FlowState(
            page_type="external_url",
            continue_url=url,
            current_url=url,
            method="GET",
            source="api",
        )

    def _chatgpt_web_oauth_config(self):
        return {
            "oauth_client_id": "app_X8zY6vW2pQ9tR3dE7nK1jL5gH",
            "oauth_redirect_uri": "https://chatgpt.com/api/auth/callback/openai",
            "oauth_scope": "openid email profile offline_access model.request model.read organization.read organization.write",
            "oauth_audience": "https://api.openai.com/v1",
            "oauth_extra_authorize_params": {},
        }

    def _is_chatgpt_web_client(self) -> bool:
        redirect = str(getattr(self, "oauth_redirect_uri", "") or "").lower()
        client_id = str(getattr(self, "oauth_client_id", "") or "").strip()
        return (
            "chatgpt.com/api/auth/callback/openai" in redirect
            or client_id == "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"
        )

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

    def _playwright_context_kwargs(self, user_agent=None):
        kwargs = {
            "locale": "en-US",
            "viewport": {"width": 1440, "height": 960},
        }
        if user_agent:
            kwargs["user_agent"] = user_agent
        return kwargs

    def _get_cookie_value(self, name, domain_hint=None):
        for cookie in self.session.cookies.jar:
            if cookie.name != name:
                continue
            if domain_hint and domain_hint not in (cookie.domain or ""):
                continue
            return cookie.value
        return ""

    def _dump_bridge_snapshot(self, *, consent_url=None, user_agent=None, reason="bridge", extra=None):
        payload = {
            "created_at": int(time.time() * 1000),
            "reason": reason,
            "proxy": self.proxy,
            "browser_mode": self.browser_mode,
            "user_agent": user_agent or "",
            "consent_url": consent_url or "",
            "cookies": self._cookies_for_playwright(),
        }
        if extra is not None:
            payload["extra"] = extra
        safe_reason = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(reason or "bridge")).strip("_") or "bridge"
        path = Path(f"/tmp/chatgpt_bridge_snapshot_{safe_reason}_{payload['created_at']}.json")
        try:
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2))
            self._log(f"bridge snapshot 已落盘: {path}")
            return str(path)
        except Exception as exc:
            self._log(f"bridge snapshot 落盘失败: {exc}")
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

    def _chatgpt_session_warning_banner_only(self, session_data):
        if not isinstance(session_data, dict) or not session_data:
            return False
        normalized = self._normalize_chatgpt_session_tokens(session_data)
        if normalized:
            return False
        non_empty_keys = {
            str(key)
            for key, value in session_data.items()
            if value not in (None, "", [], {}, False)
        }
        return bool(non_empty_keys) and non_empty_keys == {"WARNING_BANNER"}

    def _chatgpt_probe_looks_guest_session(self, probe):
        if not isinstance(probe, dict):
            return False
        saw_guest_accounts = False
        saw_guest_identity = False
        for item in probe.get("backend_checks") or []:
            url = str(item.get("url") or "").lower()
            text = str(item.get("text") or "").lower()
            if "/backend-api/accounts/check/v4-2023-04-27" in url:
                if all(marker in text for marker in ('"plan_type":"guest"', '"account_id":null', '"account_user_id":null')):
                    saw_guest_accounts = True
            elif "/backend-api/me" in url:
                if all(marker in text for marker in ('"email":""', '"name":""', '"email_domain_type":"unknown"')):
                    saw_guest_identity = True
        return saw_guest_accounts and saw_guest_identity

    def _fetch_chatgpt_session(self, user_agent=None):
        url = "https://chatgpt.com/api/auth/session"
        try:
            self._browser_pause()
            r = self.session.get(
                url,
                headers=self._headers(
                    url,
                    user_agent=user_agent,
                    accept="application/json",
                    referer="https://chatgpt.com/",
                    fetch_site="same-origin",
                ),
                timeout=30,
            )
            self._log(f"chatgpt session -> {r.status_code}")
            if r.status_code != 200:
                return None
            data = r.json()
        except Exception as exc:
            self._log(f"获取 ChatGPT session 异常: {exc}")
            return None

        access_token = (
            str(data.get("accessToken") or "").strip()
            or str(data.get("access_token") or "").strip()
            or str((data.get("session") or {}).get("accessToken") or "").strip()
            or str((data.get("session") or {}).get("access_token") or "").strip()
            or str((data.get("data") or {}).get("accessToken") or "").strip()
            or str((data.get("data") or {}).get("access_token") or "").strip()
        )
        if not access_token:
            self._log("ChatGPT session 未返回 accessToken")
            self._dump_bridge_snapshot(
                reason="chatgpt_session_protocol",
                user_agent=user_agent,
                extra={
                    "url": url,
                    "keys": list(data.keys()) if isinstance(data, dict) else [],
                    "data": data,
                },
            )
            seeded = self._build_seeded_chatgpt_session()
            if seeded:
                self._log("改用已有 ChatGPT Web token seed 继续恢复")
                return seeded
            return None
        return data

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
            or self._get_cookie_value("__Secure-next-auth.session-token", "chatgpt.com")
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
            "refresh_token": "",
            "id_token": "",
            "session_token": session_token,
            "workspace_id": account_id,
            "user_id": user_id,
            "auth_provider": "browser_chatgpt_session",
            "expires_in": session_data.get("expires") or "",
            "cookies": cookie_bundle.get("cookie_header", ""),
            "cookie_bundle": cookie_bundle,
            "cf_clearance": cookie_bundle.get("cf_clearance", ""),
            "oai_did": cookie_bundle.get("oai_did", ""),
            "oai_sc": cookie_bundle.get("oai_sc", ""),
            "raw_session": session_data,
        }

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

    def _extract_chatgpt_callback_url(self, value):
        candidate = normalize_flow_url(value, auth_base=self.oauth_issuer)
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

    def _extract_chatgpt_callback_code(self, value):
        callback_url = self._extract_chatgpt_callback_url(value)
        if not callback_url:
            return None
        try:
            return parse_qs(urlparse(callback_url).query, keep_blank_values=True).get("code", [None])[0]
        except Exception:
            return None

    def _extract_chatgpt_callback_url_from_cookies(self):
        candidate_names = (
            "__Secure-next-auth.callback-url",
            "next-auth.callback-url",
            "__Secure-authjs.callback-url",
            "authjs.callback-url",
        )
        for name in candidate_names:
            raw_value = str(self._get_cookie_value(name, "chatgpt.com") or self._get_cookie_value(name) or "").strip()
            if not raw_value:
                continue
            for candidate in (raw_value, unquote(raw_value), unquote(unquote(raw_value))):
                callback_url = self._extract_chatgpt_callback_url(candidate)
                if callback_url:
                    self._log(f"从 cookie {name} 提取到 ChatGPT callback/openai")
                    return callback_url
        return ""

    def _try_chatgpt_callback_session(
        self,
        callback_url,
        *,
        user_agent=None,
        impersonate=None,
        referer=None,
        code_verifier=None,
        prefer_token_exchange=False,
    ):
        callback_url = self._extract_chatgpt_callback_url(callback_url)
        if not callback_url:
            callback_url = self._extract_chatgpt_callback_url_from_cookies()
        if not callback_url:
            return None

        if prefer_token_exchange and code_verifier and self._is_chatgpt_web_client():
            callback_code = self._extract_chatgpt_callback_code(callback_url)
            if callback_code:
                self._log("检测到 ChatGPT callback/openai code，优先直接换 OAuth token")
                tokens = self._exchange_code_for_tokens(callback_code, code_verifier, user_agent, impersonate)
                if tokens:
                    return tokens
                self._log("callback/openai code 直换失败，回退 /api/auth/session")

        self._log("检测到 ChatGPT callback/openai，优先直取 /api/auth/session")
        current_url = callback_url
        referer_url = referer or f"{self.oauth_issuer}/about-you"

        for hop in range(3):
            try:
                headers = self._headers(
                    current_url,
                    user_agent=user_agent,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    referer=referer_url,
                    navigation=True,
                )
                kwargs = {"headers": headers, "allow_redirects": False, "timeout": 30}
                if impersonate:
                    kwargs["impersonate"] = impersonate

                self._browser_pause(0.12, 0.3)
                r = self.session.get(current_url, **kwargs)
                last_url = str(r.url or current_url)
                self._log(f"callback/openai[{hop + 1}] -> {r.status_code} {last_url[:120]}")
            except Exception as exc:
                self._log(f"callback/openai 跟随异常: {exc}")
                return None

            session_data = self._fetch_chatgpt_session(user_agent=user_agent)
            if session_data:
                return self._normalize_chatgpt_session_tokens(session_data)

            if r.status_code in (301, 302, 303, 307, 308):
                location = normalize_flow_url(r.headers.get("Location", ""), auth_base="https://chatgpt.com")
                if not location:
                    break
                referer_url = last_url or referer_url
                current_url = location
                continue
            break

        if last_non_terminal_session:
            self._log(
                "consent fallback: direct authorize re-entry 未拿到 localhost code，"
                "返回当前 ChatGPT Web session 给上层决定是否继续"
            )
            return last_non_terminal_session

        return None

    def _try_chatgpt_callback_session_from_state(
        self,
        state: FlowState,
        *,
        user_agent=None,
        impersonate=None,
        referer=None,
        code_verifier=None,
        prefer_token_exchange=False,
    ):
        for candidate in (
            state.continue_url,
            state.current_url,
            (state.payload or {}).get("url", ""),
        ):
            tokens = self._try_chatgpt_callback_session(
                candidate,
                user_agent=user_agent,
                impersonate=impersonate,
                referer=referer,
                code_verifier=code_verifier,
                prefer_token_exchange=prefer_token_exchange,
            )
            if tokens:
                return tokens
        return None

    def _try_direct_authorize_reentry(
        self,
        authorize_url,
        authorize_params,
        code_verifier,
        *,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
    ):
        """在现有 auth/chatgpt cookie 上重进一次 authorize，但去掉 prompt=login。"""
        if not authorize_url or not authorize_params:
            return None

        self.last_direct_authorize_final_url = ""
        self.last_direct_authorize_login_challenge_url = ""
        self.last_direct_authorize_log_in_dump = ""
        retry_params = dict(authorize_params or {})
        retry_params.pop("prompt", None)
        retry_url = f"{authorize_url}?{urlencode(retry_params)}"
        self._log("consent fallback: direct authorize re-entry (without prompt=login)")

        current_url = retry_url
        referer_url = "https://chatgpt.com/"
        last_non_terminal_session = None

        for hop in range(8):
            callback_tokens = self._try_chatgpt_callback_session(
                current_url,
                user_agent=user_agent,
                impersonate=impersonate,
                referer=referer_url,
                code_verifier=code_verifier,
                prefer_token_exchange=self._is_chatgpt_web_client(),
            )
            if callback_tokens:
                self._log("consent fallback: direct authorize re-entry 命中 callback/openai session")
                return callback_tokens

            code = self._extract_code_from_url(current_url)
            if code:
                self._log("consent fallback: direct authorize re-entry 获取到 authorization code")
                tokens = self._exchange_code_for_tokens(code, code_verifier, user_agent, impersonate)
                if tokens:
                    return tokens
                return None

            try:
                headers = self._headers(
                    current_url,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    referer=referer_url,
                    navigation=True,
                )
                kwargs = {"headers": headers, "allow_redirects": False, "timeout": 30}
                if impersonate:
                    kwargs["impersonate"] = impersonate

                self._browser_pause(0.12, 0.3)
                response = self.session.get(current_url, **kwargs)
                last_url = str(response.url or current_url)
                self.last_direct_authorize_final_url = last_url
                self._log(f"direct authorize[{hop + 1}] -> {response.status_code} {last_url[:120]}")
            except Exception as exc:
                self._log(f"direct authorize re-entry 异常: {exc}")
                return None

            session_data = self._fetch_chatgpt_session(user_agent=user_agent)
            if session_data:
                normalized = self._normalize_chatgpt_session_tokens(session_data)
                if self._browser_tokens_are_terminal(normalized):
                    self._log("consent fallback: direct authorize re-entry 直接恢复到目标 session/token")
                    return normalized
                if normalized:
                    last_non_terminal_session = normalized
                self._log(
                    "consent fallback: direct authorize re-entry 当前仅恢复到 ChatGPT Web session，"
                    "继续等待 localhost code"
                )

            code = self._extract_code_from_url(last_url)
            if code:
                self._log("consent fallback: direct authorize re-entry 从最终 URL 获取到 authorization code")
                tokens = self._exchange_code_for_tokens(code, code_verifier, user_agent, impersonate)
                if tokens:
                    return tokens
                return None

            if response.status_code in (301, 302, 303, 307, 308):
                location = normalize_flow_url(response.headers.get("Location", ""), auth_base="https://chatgpt.com")
                if not location:
                    return None
                if "/api/accounts/login?login_challenge=" in location:
                    self.last_direct_authorize_login_challenge_url = location
                    self._log(
                        "direct authorize re-entry 捕获 login_challenge: "
                        f"{location[:180]}"
                    )
                referer_url = last_url or referer_url
                current_url = urljoin(last_url or current_url, location)
                self.last_direct_authorize_final_url = current_url
                continue

            if "/log-in" in last_url:
                try:
                    html = response.text or ""
                    dump_payload = {
                        "url": last_url,
                        "status": response.status_code,
                        "login_challenge_url": self.last_direct_authorize_login_challenge_url,
                        "headers": dict(response.headers),
                        "cookie_names": sorted(
                            {
                                str(getattr(item, "name", "") or "").strip()
                                for item in list(getattr(getattr(self.session, "cookies", None), "jar", None) or [])
                                if str(getattr(item, "name", "") or "").strip()
                            }
                        ),
                        "has_login_challenge_in_html": "login_challenge" in html,
                        "html_preview": html[:4000],
                        "html": html,
                    }
                    dump_path = f"/tmp/oauth_log_in_debug_{int(time.time() * 1000)}.json"
                    Path(dump_path).write_text(
                        json.dumps(dump_payload, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    self.last_direct_authorize_log_in_dump = dump_path
                    self._log(f"direct authorize re-entry /log-in 已落盘: {dump_path}")
                except Exception as exc:
                    self._log(f"direct authorize re-entry /log-in 落盘失败: {exc}")
            break

        if last_non_terminal_session and not self._is_chatgpt_web_client():
            self._log(
                "consent fallback: direct authorize re-entry 已恢复 ChatGPT Web session，"
                "改走固定 consent/workspace 路径再试一次"
            )
            merged_seed = dict(getattr(self, "chatgpt_session_seed", {}) or {})
            for key, value in dict(last_non_terminal_session or {}).items():
                if value in (None, "", {}, []):
                    continue
                merged_seed[key] = value
            if merged_seed:
                self.chatgpt_session_seed = merged_seed

            current_device_id = str(getattr(self, "current_device_id", "") or "").strip()
            fallback_state = self._state_from_url(
                f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
            )
            code, resolved_state = self._resolve_consent_state(
                fallback_state,
                referer=referer_url or "https://chatgpt.com/",
                device_id=current_device_id,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                impersonate=impersonate,
            )
            if code:
                self._log(
                    "consent fallback: 固定 consent/workspace 路径获取到 authorization code"
                )
                tokens = self._exchange_code_for_tokens(
                    code,
                    code_verifier,
                    user_agent,
                    impersonate,
                )
                if tokens:
                    return tokens

            if resolved_state:
                callback_tokens = self._try_chatgpt_callback_session_from_state(
                    resolved_state,
                    user_agent=user_agent,
                    impersonate=impersonate,
                    referer=referer_url,
                    code_verifier=code_verifier,
                    prefer_token_exchange=False,
                )
                if callback_tokens:
                    self._log(
                        "consent fallback: 固定 consent/workspace 路径命中 callback/openai session"
                    )
                    return callback_tokens

                resolved_code = self._extract_code_from_state(resolved_state)
                if resolved_code:
                    self._log(
                        "consent fallback: 固定 consent/workspace 路径从状态提取到 authorization code"
                    )
                    tokens = self._exchange_code_for_tokens(
                        resolved_code,
                        code_verifier,
                        user_agent,
                        impersonate,
                    )
                    if tokens:
                        return tokens

                resolved_target = str(
                    resolved_state.continue_url or resolved_state.current_url or ""
                ).strip()
                if resolved_target:
                    self.last_direct_authorize_final_url = resolved_target
                    if "/api/accounts/login?login_challenge=" in resolved_target:
                        self.last_direct_authorize_login_challenge_url = resolved_target
                    self._log(
                        "consent fallback: 固定 consent/workspace 路径未直接出 token，"
                        f"改把状态交回主状态机 -> {describe_flow_state(resolved_state)}"
                    )

        return None

    def _browser_hydrate_chatgpt_session(self, consent_url=None, user_agent=None):
        def run_browser():
            try:
                from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
            except Exception as exc:
                self._log(f"consent 浏览器 fallback 不可用: {exc}")
                return None

            launch_kwargs = {
                "headless": self.browser_mode != "headed",
                "args": ["--no-sandbox", "--disable-dev-shm-usage"],
            }
            if self.proxy:
                launch_kwargs["proxy"] = {"server": self.proxy}
            launch_kwargs = prepare_playwright_launch_kwargs(launch_kwargs, self.browser_mode, self._log)

            signin_bridge_url = (
                "https://chatgpt.com/api/auth/signin/openai"
                "?callbackUrl=https%3A%2F%2Fchatgpt.com%2F"
            )
            login_with_url = "https://chatgpt.com/auth/login_with"
            email_value = str(getattr(self, "current_email", "") or "").strip()
            password_value = str(getattr(self, "current_password", "") or "").strip()
            profile_data = dict(getattr(self, "current_profile", {}) or {})
            mailbox_client = getattr(self, "current_skymail_client", None)
            device_id = self._effective_device_id()
            targets = []
            if consent_url:
                targets.append(consent_url)
            targets.append(login_with_url)
            targets.append(signin_bridge_url)
            targets.append("https://chatgpt.com/")
            self._dump_bridge_snapshot(
                consent_url=consent_url,
                user_agent=user_agent,
                reason="oauth_browser_hydrate_chatgpt_session",
            )

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

            def _page_title(page):
                try:
                    return str(page.title() or "")
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

            def _cookie_names(raw_cookies):
                names = []
                for item in raw_cookies or []:
                    try:
                        name = str((item or {}).get("name") or "").strip()
                    except Exception:
                        name = ""
                    if name:
                        names.append(name)
                return names

            def _existing_account_chain_active():
                return bool(getattr(self, "prefer_email_otp_first", False))

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
                        "consent 浏览器 fallback: 已清理 bridge error cookies "
                        f"({','.join(sorted(cookie_names))})"
                    )
                except Exception as exc:
                    self._log(f"consent 浏览器 fallback 清理 error cookies 失败: {exc}")

            def _browser_click_text(page_obj, candidates):
                try:
                    return page_obj.evaluate(
                        """
                        (texts) => {
                          const isVisible = (el) => {
                            if (!el) return false;
                            const style = window.getComputedStyle(el);
                            const rect = el.getBoundingClientRect();
                            return !!rect.width && !!rect.height && style.visibility !== 'hidden' && style.display !== 'none';
                          };
                          const wanted = (texts || []).map((item) => String(item || '').trim().toLowerCase()).filter(Boolean);
                          const nodes = Array.from(document.querySelectorAll('button, a, [role="button"], input[type="submit"]'));
                          for (const node of nodes) {
                            if (!isVisible(node) || node.disabled) continue;
                            const label = String(node.innerText || node.textContent || node.value || '').trim().toLowerCase();
                            if (!label) continue;
                            if (wanted.some((part) => label.includes(part))) {
                              node.click();
                              return {ok: true, label};
                            }
                          }
                          return {ok: false};
                        }
                        """,
                        list(candidates or []),
                    )
                except Exception as exc:
                    self._log(f"consent 浏览器 fallback 点击控件异常: {exc}")
                    return {"ok": False, "error": str(exc)}

            def _browser_fill_input(page_obj, selectors, value):
                if not value:
                    return False
                for selector in selectors:
                    try:
                        locator = page_obj.locator(selector).first
                        if locator.count() and locator.is_visible(timeout=800):
                            locator.fill(value)
                            return True
                    except Exception:
                        continue
                return False

            def _browser_has_password_input(page_obj):
                selectors = (
                    "input[type='password']",
                    "input[name='password']",
                    "input[autocomplete='current-password']",
                )
                for selector in selectors:
                    try:
                        locator = page_obj.locator(selector).first
                        if locator.count() and locator.is_visible(timeout=800):
                            return True
                    except Exception:
                        continue
                return False

            def _browser_fill_and_submit(page_obj, selectors, value, submit_labels=None):
                if not value:
                    return {"ok": False, "reason": "empty_value"}
                try:
                    return page_obj.evaluate(
                        """
                        (payload) => {
                          const selectors = Array.isArray(payload?.selectors) ? payload.selectors : [];
                          const value = String(payload?.value ?? '');
                          const labels = Array.isArray(payload?.labels) ? payload.labels.map((item) => String(item || '').trim().toLowerCase()) : [];
                          const isVisible = (el) => {
                            if (!el) return false;
                            const style = window.getComputedStyle(el);
                            const rect = el.getBoundingClientRect();
                            return !!rect.width && !!rect.height && style.visibility !== 'hidden' && style.display !== 'none';
                          };
                          const textOf = (el) => String(el?.innerText || el?.textContent || el?.value || '').trim().toLowerCase();
                          const isSocialLabel = (label) => {
                            const lowered = String(label || '').trim().toLowerCase();
                            if (!lowered) return false;
                            return (
                              lowered.includes('continue with')
                              || lowered.includes('google')
                              || lowered.includes('apple')
                              || lowered.includes('microsoft')
                              || lowered.includes('phone')
                            );
                          };
                          let input = null;
                          for (const selector of selectors) {
                            const candidate = Array.from(document.querySelectorAll(selector)).find((el) => isVisible(el) && !el.disabled);
                            if (candidate) {
                              input = candidate;
                              break;
                            }
                          }
                          if (!input) return {ok: false, reason: 'no_input'};
                          input.focus();
                          input.value = '';
                          input.dispatchEvent(new Event('input', {bubbles: true}));
                          input.value = value;
                          input.dispatchEvent(new Event('input', {bubbles: true}));
                          input.dispatchEvent(new Event('change', {bubbles: true}));

                          const findSubmit = (root) => {
                            const nodes = Array.from((root || document).querySelectorAll('button, input[type="submit"], [role="button"]'));
                            return nodes.find((el) => {
                              if (!isVisible(el) || el.disabled) return false;
                              const label = textOf(el);
                              if (isSocialLabel(label)) return false;
                              return !labels.length || labels.some((part) => label === part || label.startsWith(part + ' ') || label.includes(part));
                            });
                          };

                          const form = input.closest('form');
                          if (form) {
                            if (typeof form.requestSubmit === 'function') {
                              form.requestSubmit();
                              return {ok: true, via: 'form_request_submit'};
                            }
                            const submit = findSubmit(form);
                            if (submit) {
                              submit.click();
                              return {ok: true, via: 'form_button', label: textOf(submit)};
                            }
                          }

                          input.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true}));
                          input.dispatchEvent(new KeyboardEvent('keyup', {key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true}));

                          const localRoot = input.parentElement?.closest('form, div, section, main') || document.body;
                          const localSubmit = findSubmit(localRoot);
                          if (localSubmit) {
                            localSubmit.click();
                            return {ok: true, via: 'local_button', label: textOf(localSubmit)};
                          }

                          return {ok: true, via: 'enter_only'};
                        }
                        """,
                        {
                            "selectors": list(selectors or []),
                            "value": str(value or ""),
                            "labels": list(submit_labels or []),
                        },
                    )
                except Exception as exc:
                    self._log(f"consent 浏览器 fallback 表单提交异常: {exc}")
                    return {"ok": False, "error": str(exc)}

            def _browser_fill_openai_email_otp(page_obj, code):
                try:
                    return page_obj.evaluate(
                        """
                        (rawCode) => {
                          const code = String(rawCode || '').trim();
                          const isVisible = (el) => {
                            if (!el) return false;
                            const style = window.getComputedStyle(el);
                            const rect = el.getBoundingClientRect();
                            return !!rect.width && !!rect.height && style.visibility !== 'hidden' && style.display !== 'none';
                          };
                          const fire = (el, value) => {
                            el.focus();
                            el.value = value;
                            el.dispatchEvent(new Event('input', {bubbles: true}));
                            el.dispatchEvent(new Event('change', {bubbles: true}));
                            el.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true}));
                            el.dispatchEvent(new KeyboardEvent('keyup', {key: 'Enter', bubbles: true}));
                          };
                          const inputs = Array.from(document.querySelectorAll('input')).filter((el) => isVisible(el) && !el.disabled);
                          const single = inputs.filter((el) => String(el.maxLength || el.getAttribute('maxlength') || '') === '1');
                          if (single.length >= code.length && code.length > 1) {
                            code.split('').forEach((ch, idx) => {
                              if (single[idx]) fire(single[idx], ch);
                            });
                          } else {
                            const target = inputs.find((el) => {
                              const type = String(el.type || '').toLowerCase();
                              const name = String(el.name || '').toLowerCase();
                              const auto = String(el.autocomplete || '').toLowerCase();
                              return (
                                auto.includes('one-time-code')
                                || name.includes('code')
                                || type === 'tel'
                                || type === 'number'
                                || type === 'text'
                              );
                            }) || inputs[0];
                            if (!target) return {ok: false, reason: 'no_input'};
                            fire(target, code);
                          }
                          const target = single.length >= code.length && code.length > 1 ? single[0] : (inputs.find((el) => {
                            const type = String(el.type || '').toLowerCase();
                            const name = String(el.name || '').toLowerCase();
                            const auto = String(el.autocomplete || '').toLowerCase();
                            return (
                              auto.includes('one-time-code')
                              || name.includes('code')
                              || type === 'tel'
                              || type === 'number'
                              || type === 'text'
                            );
                          }) || inputs[0]);
                          const textOf = (el) => String(el?.innerText || el?.textContent || el?.value || '').trim().toLowerCase();
                          const form = target?.closest('form');
                          let submit = null;
                          if (form) {
                            submit = Array.from(form.querySelectorAll('button, input[type="submit"], [role="button"]')).find((el) => {
                              const label = textOf(el);
                              return isVisible(el) && !el.disabled && ['continue', 'verify', 'next', 'submit', 'log in'].some((part) => label.includes(part));
                            });
                            if (submit) submit.click();
                            else if (typeof form.requestSubmit === 'function') form.requestSubmit();
                          }
                          if (!submit) {
                            const buttons = Array.from(document.querySelectorAll('button, a, [role="button"], input[type="submit"]')).filter(isVisible);
                            submit = buttons.find((el) => {
                              const label = textOf(el);
                              return ['continue', 'verify', 'next', 'submit', 'log in'].some((part) => label.includes(part));
                            });
                            if (submit && !submit.disabled) submit.click();
                          }
                          return {ok: true, inputCount: inputs.length, singleCount: single.length, clicked: !!submit, submitLabel: submit ? textOf(submit) : ''};
                        }
                        """,
                        str(code or "").strip(),
                    )
                except Exception as exc:
                    self._log(f"consent 浏览器 fallback 填 OTP 异常: {exc}")
                    return {"ok": False, "error": str(exc)}

            def _browser_send_passwordless_otp(page_obj):
                if not device_id:
                    return None
                try:
                    return page_obj.evaluate(
                        """
                        async (deviceId) => {
                          try {
                            const response = await fetch('/api/accounts/passwordless/send-otp', {
                              method: 'POST',
                              credentials: 'include',
                              headers: {
                                accept: 'application/json, text/plain, */*',
                                'content-type': 'application/json',
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
                            };
                          } catch (error) {
                            return {error: String(error)};
                          }
                        }
                        """,
                        device_id,
                    )
                except Exception as exc:
                    self._log(f"consent 浏览器 fallback send-otp 异常: {exc}")
                    return {"error": str(exc)}

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**launch_kwargs)
                try:
                    context = harden_playwright_context(
                        browser.new_context(**self._playwright_context_kwargs(user_agent=user_agent))
                    )
                    all_cookies = self._cookies_for_playwright()
                    cookies = list(all_cookies)
                    self._log(
                        "consent 浏览器 fallback: 注入完整 auth/chatgpt cookie 集 "
                        f"({len(cookies)})"
                    )
                    self._add_cookies_to_playwright_context(context, cookies, "consent 浏览器 fallback")
                    page = context.new_page()

                    for target in targets:
                        try:
                            self._log(f"浏览器直落 session: 打开 {target}")
                            page.goto(target, wait_until="domcontentloaded", timeout=45000)
                            page.wait_for_timeout(3500 if "chatgpt.com" in target else 1800)
                        except PlaywrightTimeoutError as exc:
                            self._log(f"浏览器打开 {target} 超时: {exc}")
                        except Exception as exc:
                            self._log(f"浏览器打开 {target} 异常: {exc}")

                        try:
                            page_url = str(page.url or "")
                        except Exception:
                            page_url = ""
                        title = _page_title(page)
                        body = _body_preview(page)
                        html = _html_preview(page)
                        body_lower = body.lower()
                        if body_lower and "first time using codex" in body_lower:
                            self._log("consent 页面提示先登录 chatgpt.com，继续转 ChatGPT 首页")

                        self._log(
                            "浏览器直落落点: "
                            f"url={page_url[:140]} title={title[:80]!r} body={body[:180]!r}"
                        )

                        wait_budget = 12
                        if "auth.openai.com" in page_url:
                            wait_budget = 20
                        if _looks_like_challenge(body, html):
                            wait_budget = 45
                            self._log("consent 浏览器 fallback: 检测到 challenge，延长等待")

                        start_wait = time.time()
                        last_session_error = ""
                        last_page_url = page_url
                        login_with_attempted = False
                        native_signin_attempted = False
                        auth_resume_attempted = set()
                        browser_send_otp_attempted = set()
                        browser_password_switch_until = {}
                        browser_email_submit_attempted = set()
                        browser_password_submit_attempted = set()
                        browser_otp_anchor = 0.0
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
                            lowered_url = page_url.lower()
                            if page_url != last_page_url:
                                self._log(f"consent 浏览器 URL 漂移 -> {page_url[:160]}")
                                last_page_url = page_url

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
                                    self._log(f"浏览器原生 session fetch 异常: {exc}")

                            raw_cookies = context.cookies()
                            self._sync_playwright_cookies(raw_cookies)
                            cookie_names = _cookie_names(raw_cookies)
                            if isinstance(browser_session, dict):
                                if browser_session.get("error"):
                                    self._log(f"浏览器原生 session 异常: {browser_session['error']}")
                                else:
                                    status = browser_session.get("status")
                                    self._log(
                                        "浏览器原生 session -> "
                                        f"HTTP {status} {str(browser_session.get('url') or '')[:120]}"
                                    )
                                    session_data = browser_session.get("data")
                                    if isinstance(session_data, dict):
                                        normalized = self._normalize_chatgpt_session_tokens(session_data)
                                        if normalized:
                                            return normalized
                                        probe = self._collect_chatgpt_browser_probe(page, context)
                                        self._log(
                                            "浏览器原生 session keys: "
                                            f"{','.join(list(session_data.keys())[:20])}"
                                        )
                                        self._dump_bridge_snapshot(
                                            consent_url=consent_url,
                                            user_agent=user_agent,
                                            reason="chatgpt_session_browser",
                                            extra={
                                                "url": browser_session.get("url"),
                                                "keys": list(session_data.keys()),
                                                "data": session_data,
                                                "page_url": page_url,
                                                "probe": probe,
                                            },
                                        )
                                    if browser_session.get("text"):
                                        self._log(
                                            "浏览器原生 session body: "
                                            f"{str(browser_session['text'])[:180]}"
                                        )

                            session_data = self._fetch_chatgpt_session(user_agent=user_agent)
                            if session_data:
                                return self._normalize_chatgpt_session_tokens(session_data)
                            last_session_error = "chatgpt session -> 403"

                            if page_host.endswith("auth.openai.com"):
                                body = _body_preview(page)
                                html = _html_preview(page)
                                lowered_body = str(body or "").lower()

                                if (
                                    "/log-in/password" in lowered_url
                                    or "type=\"password\"" in str(html or "").lower()
                                ) and password_value:
                                    if lowered_url in browser_password_submit_attempted:
                                        page.wait_for_timeout(1200)
                                        self._sync_playwright_cookies(context.cookies())
                                    else:
                                        browser_password_submit_attempted.add(lowered_url)
                                        password_submit = _browser_fill_and_submit(
                                            page,
                                            [
                                                "input[type='password']",
                                                "input[name='password']",
                                                "input[autocomplete='current-password']",
                                            ],
                                            password_value,
                                            ["continue", "log in", "login", "next"],
                                        )
                                        if (password_submit or {}).get("ok"):
                                            self._log(
                                                "consent 浏览器 fallback: 已在浏览器内提交密码 "
                                                f"via={str((password_submit or {}).get('via') or '')}"
                                            )
                                            page.wait_for_timeout(3500)
                                            self._sync_playwright_cookies(context.cookies())
                                            resumed = self._resume_chatgpt_web_authorize_flow(
                                                str(page.url or "") or lowered_url,
                                                user_agent=user_agent,
                                                sec_ch_ua=None,
                                                impersonate=getattr(self, "impersonate", None),
                                                skymail_client=mailbox_client,
                                                profile=profile_data,
                                            )
                                            if resumed:
                                                return resumed
                                            start_wait = time.time()
                                            continue

                                if (
                                    "/log-in" in lowered_url
                                    and "/log-in/password" not in lowered_url
                                    and email_value
                                ):
                                    if lowered_url in browser_email_submit_attempted:
                                        page.wait_for_timeout(1200)
                                        self._sync_playwright_cookies(context.cookies())
                                    else:
                                        browser_email_submit_attempted.add(lowered_url)
                                        email_submit = _browser_fill_and_submit(
                                            page,
                                            [
                                                "input[type='email']",
                                                "input[name='email']",
                                                "input[name='username']",
                                                "input[autocomplete='email']",
                                            ],
                                            email_value,
                                            ["continue", "next", "log in"],
                                        )
                                        if (email_submit or {}).get("ok"):
                                            if not browser_otp_anchor:
                                                browser_otp_anchor = time.time()
                                            self._log(
                                                "consent 浏览器 fallback: 已在浏览器内提交邮箱 "
                                                f"via={str((email_submit or {}).get('via') or '')}"
                                            )
                                            try:
                                                page.wait_for_function(
                                                    """
                                                    () => {
                                                      const href = String(window.location.href || '').toLowerCase();
                                                      if (
                                                        href.includes('/log-in/password')
                                                        || href.includes('/email-verification')
                                                        || href.includes('/about-you')
                                                      ) return true;
                                                      return !!document.querySelector(
                                                        "input[type='password'], input[name='password'], input[autocomplete='current-password']"
                                                      );
                                                    }
                                                    """,
                                                    timeout=15000,
                                                )
                                            except Exception:
                                                pass
                                            page.wait_for_timeout(1500)
                                            self._sync_playwright_cookies(context.cookies())
                                            current_browser_url = str(page.url or "") or lowered_url
                                            current_browser_html = str(_html_preview(page) or "").lower()
                                            password_input_present = _browser_has_password_input(page)
                                            if (
                                                current_browser_url.lower() != lowered_url
                                                or "/log-in/password" in current_browser_url.lower()
                                                or "/email-verification" in current_browser_url.lower()
                                                or "/about-you" in current_browser_url.lower()
                                                or "type=\"password\"" in current_browser_html
                                                or password_input_present
                                            ):
                                                start_wait = time.time()
                                                continue
                                            self._log(
                                                "consent 浏览器 fallback: /log-in 提邮箱后仍停留当前页，"
                                                "继续保留浏览器态等待，不立刻回退协议 authorize/continue"
                                            )
                                            start_wait = time.time()
                                            continue

                                if "/email-verification" in lowered_url and email_value and mailbox_client:
                                    prefer_email_otp_first = bool(
                                        getattr(self, "prefer_email_otp_first", True)
                                    )
                                    switch_until = float(browser_password_switch_until.get(lowered_url, 0.0) or 0.0)
                                    if switch_until and time.time() < switch_until:
                                        page.wait_for_timeout(1200)
                                        self._sync_playwright_cookies(context.cookies())
                                        start_wait = time.time()
                                        continue

                                    browser_ignore_otp_anchor = bool(
                                        getattr(self, "ignore_otp_sent_at_once", False)
                                    )
                                    if browser_ignore_otp_anchor:
                                        self.ignore_otp_sent_at_once = False
                                        if not hasattr(mailbox_client, "_used_codes"):
                                            mailbox_client._used_codes = set()
                                        used_codes = set(getattr(mailbox_client, "_used_codes", set()) or set())
                                        if used_codes:
                                            self._log(
                                                "consent 浏览器 fallback: 允许回看最近验证码一次，"
                                                f"先清空已用集合: {sorted(used_codes)}"
                                            )
                                            mailbox_client._used_codes = set()
                                        if hasattr(mailbox_client, "_baseline_id"):
                                            old_baseline = str(getattr(mailbox_client, "_baseline_id", "") or "")
                                            setattr(mailbox_client, "_baseline_id", "")
                                            if old_baseline:
                                                self._log(
                                                    "consent 浏览器 fallback: 允许回看最近验证码一次，"
                                                    f"清空 baseline_id: {old_baseline}"
                                                )
                                        elif hasattr(mailbox_client, "baseline"):
                                            old_baseline = str(getattr(mailbox_client, "baseline", "") or "")
                                            setattr(mailbox_client, "baseline", "0")
                                            if old_baseline:
                                                self._log(
                                                    "consent 浏览器 fallback: 允许回看最近验证码一次，"
                                                    f"清空 baseline: {old_baseline}"
                                                )
                                        self._log(
                                            "consent 浏览器 fallback: 本轮忽略 otp_sent_at 锚点，优先回看最近验证码"
                                        )

                                    if password_value and not prefer_email_otp_first:
                                        click_result = _browser_click_text(
                                            page,
                                            [
                                                "use your password",
                                                "password",
                                                "try another way",
                                            ],
                                        )
                                        if (click_result or {}).get("ok"):
                                            browser_password_switch_until[lowered_url] = time.time() + 10.0
                                            self._log("consent 浏览器 fallback: email-verification 优先改走浏览器密码回退")
                                            page.wait_for_timeout(4500)
                                            self._sync_playwright_cookies(context.cookies())
                                            resumed = self._resume_chatgpt_web_authorize_flow(
                                                str(page.url or "") or lowered_url,
                                                user_agent=user_agent,
                                                sec_ch_ua=None,
                                                impersonate=getattr(self, "impersonate", None),
                                                skymail_client=mailbox_client,
                                                profile=profile_data,
                                            )
                                            if resumed:
                                                return resumed
                                            start_wait = time.time()
                                            continue

                                    if (not browser_ignore_otp_anchor) and lowered_url not in browser_send_otp_attempted:
                                        browser_send_otp_attempted.add(lowered_url)
                                        browser_otp_anchor = browser_otp_anchor or time.time()
                                        send_result = _browser_send_passwordless_otp(page)
                                        if isinstance(send_result, dict):
                                            if send_result.get("error"):
                                                self._log(
                                                    "consent 浏览器 fallback send-otp 错误: "
                                                    f"{send_result['error']}"
                                                )
                                            else:
                                                self._log(
                                                    "consent 浏览器 fallback send-otp -> "
                                                    f"HTTP {send_result.get('status')} {str(send_result.get('url') or '')[:120]}"
                                                )
                                                if send_result.get("text"):
                                                    self._log(
                                                        "consent 浏览器 fallback send-otp body: "
                                                        f"{str(send_result['text'])[:180]}"
                                                    )
                                                send_data = send_result.get("data") or {}
                                                send_error = (send_data.get("error") or {}) if isinstance(send_data, dict) else {}
                                                send_error_code = str(send_error.get("code") or "").strip()
                                                if send_error_code == "invalid_state":
                                                    self._log(
                                                        "consent 浏览器 fallback send-otp 返回 invalid_state，"
                                                        "立刻重建 auth 状态，不再继续等待邮箱"
                                                    )
                                                    browser_state = self._submit_authorize_continue_browser_fallback(
                                                        email_value,
                                                        user_agent=user_agent,
                                                    )
                                                    if browser_state:
                                                        if self._state_is_email_otp(browser_state):
                                                            self.reuse_existing_email_code_once = True
                                                            self._log(
                                                                "authorize/continue 浏览器 fallback 已回到 email_otp_verification，"
                                                                "允许 existing-account 恢复链复用一次最近邮箱验证码"
                                                            )
                                                        self._log(
                                                            "authorize/continue 浏览器 fallback 已重建状态 -> "
                                                            f"{describe_flow_state(browser_state)}"
                                                        )
                                                        resumed = self._resume_chatgpt_web_authorize_flow(
                                                            str(browser_state.current_url or browser_state.continue_url or "") or lowered_url,
                                                            user_agent=user_agent,
                                                            sec_ch_ua=None,
                                                            impersonate=getattr(self, "impersonate", None),
                                                            skymail_client=mailbox_client,
                                                            profile=profile_data,
                                                        )
                                                        if resumed:
                                                            return resumed
                                                        start_wait = time.time()
                                                        continue
                                        page.wait_for_timeout(1200)

                                    if not hasattr(mailbox_client, "_used_codes"):
                                        mailbox_client._used_codes = set()
                                    tried_codes = set(getattr(mailbox_client, "_used_codes", set()))
                                    otp_code = None
                                    if browser_ignore_otp_anchor:
                                        recent_success_code = self._get_recent_successful_email_otp()
                                        if recent_success_code:
                                            otp_code = recent_success_code
                                            self._log(
                                                "consent 浏览器 fallback: 本轮优先复用最近一次成功验证码，"
                                                f"避免回看邮箱时命中更旧历史码: {recent_success_code}"
                                            )
                                    try:
                                        if not otp_code:
                                            browser_wait_otp_sent_at = (
                                                None
                                                if browser_ignore_otp_anchor
                                                else (browser_otp_anchor or time.time())
                                            )
                                            otp_code = mailbox_client.wait_for_verification_code(
                                                email_value,
                                                timeout=60,
                                                otp_sent_at=browser_wait_otp_sent_at,
                                                exclude_codes=set(),
                                            )
                                    except Exception as exc:
                                        self._log(f"consent 浏览器 fallback 等待 OTP 异常: {exc}")

                                    if otp_code:
                                        if otp_code in tried_codes:
                                            self._log(
                                                "consent 浏览器 fallback: 命中 post-anchor 重发同码，"
                                                f"允许复用 OTP code={otp_code}"
                                            )
                                        tried_codes.add(otp_code)
                                        mailbox_client._used_codes = tried_codes
                                        fill_result = _browser_fill_openai_email_otp(page, otp_code)
                                        self._log(
                                            "consent 浏览器 fallback: 已在浏览器内提交 OTP "
                                            f"code={otp_code} result={fill_result}"
                                        )
                                        try:
                                            page.wait_for_function(
                                                """
                                                () => {
                                                  const href = String(window.location.href || '').toLowerCase();
                                                  if (
                                                    href.includes('/about-you')
                                                    || href.includes('/log-in')
                                                    || href.includes('/create-account/password')
                                                    || href.includes('/api/accounts/login')
                                                    || href.includes('chatgpt.com')
                                                  ) return true;
                                                  const body = String(document.body?.innerText || '').toLowerCase();
                                                  return (
                                                    body.includes('log in')
                                                    || body.includes('sign up for free')
                                                    || body.includes('about you')
                                                    || body.includes('oops!')
                                                  );
                                                }
                                                """,
                                                timeout=15000,
                                            )
                                        except Exception:
                                            pass
                                        page.wait_for_timeout(1500)
                                        self._sync_playwright_cookies(context.cookies())
                                        current_browser_url = str(page.url or "") or lowered_url
                                        current_browser_body = _body_preview(page)
                                        current_browser_html = _html_preview(page)
                                        current_lowered_url = current_browser_url.lower()
                                        self._log(
                                            "consent 浏览器 fallback: OTP 提交后落点 "
                                            f"url={current_browser_url[:160]} body={current_browser_body[:180]!r}"
                                        )
                                        if self._should_force_fresh_otp_after_browser_submit(
                                            current_browser_url,
                                            current_browser_body,
                                            current_browser_html,
                                        ):
                                            self._log(
                                                "consent 浏览器 fallback: OTP 提交后命中 max_check_attempts，"
                                                "判定最近成功 OTP 不可复用，清空缓存并强制 fresh OTP"
                                            )
                                            if getattr(self, "last_successful_email_otp_code", ""):
                                                self.last_successful_email_otp_code = ""
                                                self.last_successful_email_otp_at = 0.0
                                            browser_send_otp_attempted.discard(lowered_url)
                                            browser_send_otp_attempted.discard(current_lowered_url)
                                            browser_otp_anchor = None
                                            start_wait = time.time()
                                            continue
                                        if (
                                            current_lowered_url != lowered_url
                                            or "/email-verification" not in current_lowered_url
                                            or "/about-you" in current_lowered_url
                                            or "/log-in" in current_lowered_url
                                            or "/create-account/password" in current_lowered_url
                                            or "chatgpt.com" in current_lowered_url
                                            or "oops!" in str(current_browser_body or "").lower()
                                        ):
                                            resumed_state = self._state_from_url(current_browser_url)
                                            if (
                                                self._state_is_about_you(resumed_state)
                                                and bool(getattr(self, "prefer_email_otp_first", False))
                                            ):
                                                self._remember_successful_email_otp(otp_code)
                                                self.direct_authorize_before_about_you_once = True
                                                self._log(
                                                    "consent 浏览器 fallback: OTP 提交后命中 about_you，"
                                                    "下一次 about_you 先尝试 direct authorize re-entry"
                                                )
                                            resumed = self._resume_chatgpt_web_authorize_flow(
                                                current_browser_url,
                                                user_agent=user_agent,
                                                sec_ch_ua=None,
                                                impersonate=getattr(self, "impersonate", None),
                                                skymail_client=mailbox_client,
                                                profile=profile_data,
                                            )
                                            if resumed:
                                                self._log("consent 浏览器 fallback: OTP 提交后子流程恢复成功")
                                                return resumed
                                        start_wait = time.time()
                                        continue

                                    if password_value:
                                        click_result = _browser_click_text(
                                            page,
                                            [
                                                "use your password",
                                                "password",
                                                "try another way",
                                            ],
                                        )
                                        if (click_result or {}).get("ok"):
                                            browser_password_switch_until[lowered_url] = time.time() + 10.0
                                            self._log("consent 浏览器 fallback: email-verification 等 OTP 失败后改走浏览器密码回退")
                                            page.wait_for_timeout(4500)
                                            self._sync_playwright_cookies(context.cookies())
                                            resumed = self._resume_chatgpt_web_authorize_flow(
                                                str(page.url or "") or lowered_url,
                                                user_agent=user_agent,
                                                sec_ch_ua=None,
                                                impersonate=getattr(self, "impersonate", None),
                                                skymail_client=mailbox_client,
                                                profile=profile_data,
                                            )
                                            if resumed:
                                                return resumed
                                            start_wait = time.time()
                                            continue

                                if (
                                    page_host.endswith("auth.openai.com")
                                    and lowered_url not in auth_resume_attempted
                                    and any(
                                        marker in lowered_url
                                        for marker in (
                                            "/email-verification",
                                            "/log-in/password",
                                            "/about-you",
                                            "/api/accounts/authorize",
                                            "/oauth/authorize",
                                            "/api/oauth/oauth2/auth",
                                        )
                                    )
                                ):
                                    auth_resume_attempted.add(lowered_url)
                                    self._log(
                                        "consent 浏览器 fallback: 检测到 auth.openai.com 子流程，尝试协议恢复 "
                                        f"{page_url[:140]}"
                                    )
                                    resumed = self._resume_chatgpt_web_authorize_flow(
                                        page_url,
                                        user_agent=user_agent,
                                        skymail_client=getattr(self, "current_skymail_client", None),
                                    )
                                    if resumed:
                                        self._log("consent 浏览器 fallback: auth.openai.com 子流程恢复成功")
                                        return resumed

                            body = _body_preview(page)
                            html = _html_preview(page)
                            lowered_body = str(body or "").lower()
                            looks_like_guest_home = (
                                "chatgpt.com" in lowered_body
                                and "log in" in lowered_body
                                and (
                                    "sign up for free" in lowered_body
                                    or "get responses tailored to you" in lowered_body
                                    or "/auth/error" in lowered_body
                                )
                            )
                            if (
                                not login_with_attempted
                                and looks_like_guest_home
                            ):
                                login_with_attempted = True
                                self._log("consent 浏览器 fallback: guest 首页改走 /auth/login_with")
                                try:
                                    page.goto(login_with_url, wait_until="domcontentloaded", timeout=45000)
                                    page.wait_for_timeout(4000)
                                    self._sync_playwright_cookies(context.cookies())
                                    start_wait = time.time()
                                    continue
                                except Exception as exc:
                                    self._log(f"consent 浏览器 fallback: /auth/login_with 跳转失败: {exc}")
                            if (
                                not native_signin_attempted
                                and page_host.endswith("chatgpt.com")
                                and (
                                    "/auth/login_with" in page_url
                                    or "/auth/error" in page_url
                                    or "log in" in lowered_body
                                    or "sign up for free" in lowered_body
                                )
                                and email_value
                                and device_id
                            ):
                                native_signin_attempted = True
                                _clear_bridge_error_cookies(context)
                                native_result = self._native_nextauth_signin_in_page(
                                    page,
                                    email=email_value,
                                    device_id=device_id,
                                    auth_session_logging_id=self._effective_auth_session_logging_id(),
                                )
                                if isinstance(native_result, dict):
                                    if native_result.get("error"):
                                        if native_result.get("error") == "cross_origin_page_not_chatgpt":
                                            native_signin_attempted = False
                                            self._log(
                                                "consent 浏览器 fallback native next-auth 命中 cross_origin_page_not_chatgpt，"
                                                "不消耗本轮 native attempt，等待回到 chatgpt.com 再试"
                                            )
                                        self._log(
                                            "consent 浏览器 fallback native next-auth 错误: "
                                            f"{native_result['error']}"
                                        )
                                        self._log(
                                            "consent 浏览器 fallback native next-auth 上下文: "
                                            f"page={str(native_result.get('pageUrl') or '')[:140]} "
                                            f"origin={str(native_result.get('pageOrigin') or '')[:80]}"
                                        )
                                    else:
                                        self._log(
                                            "consent 浏览器 fallback native next-auth -> "
                                            f"HTTP {native_result.get('status')} {str(native_result.get('responseUrl') or '')[:120]}"
                                        )
                                        native_status = int(native_result.get("status") or 0)
                                        if native_status == 200:
                                            self.ignore_otp_sent_at_once = True
                                            self._log(
                                                "consent 浏览器 fallback: native next-auth 可能已提前触发 OTP，"
                                                "下一轮允许回看最近验证码"
                                            )
                                        data = native_result.get("data") or {}
                                        auth_url = str(data.get("url") or "").strip()
                                        if not auth_url:
                                            auth_url = str(native_result.get("locationHeader") or "").strip()
                                        if (not auth_url) and native_result.get("text"):
                                            match = re.search(
                                                r"https://auth\\.openai\\.com[^\"'\\s<]+",
                                                native_result["text"],
                                            )
                                            auth_url = match.group(0) if match else ""
                                        if auth_url:
                                            self._sync_playwright_cookies(context.cookies())
                                            resumed = self._resume_chatgpt_web_authorize_flow(
                                                auth_url,
                                                user_agent=user_agent,
                                                skymail_client=mailbox_client,
                                            )
                                            if resumed:
                                                self._log("consent 浏览器 fallback native next-auth 子流程恢复成功")
                                                return resumed
                                            try:
                                                page.goto(auth_url, wait_until="domcontentloaded", timeout=45000)
                                                page.wait_for_timeout(3500)
                                                self._sync_playwright_cookies(context.cookies())
                                                start_wait = time.time()
                                                continue
                                            except Exception as exc:
                                                self._log(
                                                    "consent 浏览器 fallback native next-auth 跳转 auth_url 失败，改走协议恢复: "
                                                    f"{exc}"
                                                )
                            if (
                                "/create-account/password" in lowered_url
                                and _existing_account_chain_active()
                            ):
                                self._log(
                                    "consent 浏览器 fallback: existing-account 恢复链漂到 create-account/password，"
                                    "优先协议恢复而不在浏览器里继续 create-account"
                                )
                                resumed = self._resume_chatgpt_web_authorize_flow(
                                    page_url,
                                    user_agent=user_agent,
                                    sec_ch_ua=None,
                                    impersonate=getattr(self, "impersonate", None),
                                    skymail_client=mailbox_client,
                                    profile=profile_data,
                                )
                                if resumed:
                                    self._log("consent 浏览器 fallback: create-account/password 恢复成功")
                                    return resumed
                                page.wait_for_timeout(1500)
                                self._sync_playwright_cookies(context.cookies())
                                start_wait = time.time()
                                continue
                            if _looks_like_challenge(body, html):
                                self._log(
                                    "consent 浏览器 fallback: challenge 仍在，"
                                    f" cookies={cookie_names[:12]}"
                                )
                                page.wait_for_timeout(3000)
                                continue
                            if "auth.openai.com" in page_url and time.time() - start_wait < wait_budget:
                                self._log(
                                    "consent 浏览器 fallback: 仍停留 auth.openai.com，继续等待/同步 cookie"
                                )
                                page.wait_for_timeout(2500)
                                continue
                            break

                        self._log(
                            "consent 浏览器 fallback 未就绪: "
                            f"{last_session_error or 'unknown'}, final_url={page_url[:140]}"
                        )

                    self._sync_playwright_cookies(context.cookies())
                    return None
                finally:
                    browser.close()

        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(run_browser).result(timeout=180)
        except FutureTimeoutError:
            self._log("consent 浏览器 fallback 超时")
            return None
        except Exception as exc:
            self._log(f"consent 浏览器 fallback 异常: {exc}")
            return None

    def _submit_authorize_continue_browser_fallback(self, email, *, user_agent=None):
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
        except Exception as exc:
            self._log(f"authorize/continue 浏览器 fallback 不可用: {exc}")
            return None

        email_value = str(email or "").strip()
        password_value = str(getattr(self, "current_password", "") or "").strip()
        device_id = self._effective_device_id()
        if not email_value:
            return None

        launch_kwargs = {
            "headless": self.browser_mode != "headed",
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}
        launch_kwargs = prepare_playwright_launch_kwargs(launch_kwargs, self.browser_mode, self._log)

        result_path = f"/tmp/oauth_authorize_continue_browser_{int(time.time() * 1000)}.json"

        def run_browser():
            attempts = []

            def _looks_like_challenge(body, html):
                lowered = "\n".join(str(part or "").lower() for part in (body, html))
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

            def _looks_like_route_error(body, html):
                lowered = "\n".join(str(part or "").lower() for part in (body, html))
                return any(
                    marker in lowered
                    for marker in (
                        "unexpected token '<'",
                        "invalid content type: text/html",
                        "route error",
                        "oops, an error occurred!",
                    )
                )

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**launch_kwargs)
                try:
                    context = harden_playwright_context(
                        browser.new_context(**self._playwright_context_kwargs(user_agent=user_agent))
                    )
                    self._add_cookies_to_playwright_context(
                        context,
                        self._cookies_for_playwright(),
                        "authorize/continue 浏览器 fallback",
                    )
                    page = context.new_page()
                    captured = []

                    def _capture_response(response):
                        try:
                            url = str(response.url or "")
                            if "/api/accounts/authorize/continue" not in url:
                                return
                            headers = dict(response.headers)
                            body_preview = ""
                            try:
                                body_preview = (response.text() or "")[:1200]
                            except Exception:
                                body_preview = ""
                            captured.append(
                                {
                                    "status": response.status,
                                    "url": url,
                                    "content_type": headers.get("content-type", ""),
                                    "body_preview": body_preview,
                                }
                            )
                        except Exception:
                            return

                    page.on("response", _capture_response)

                    def _body_preview(limit=1400):
                        try:
                            return (page.locator("body").inner_text(timeout=3000) or "")[:limit]
                        except Exception:
                            return ""

                    def _html_preview(limit=2400):
                        try:
                            return page.evaluate(
                                f"() => (document.documentElement ? document.documentElement.outerHTML.slice(0, {limit}) : '')"
                            ) or ""
                        except Exception:
                            return ""

                    def _title():
                        try:
                            return str(page.title() or "")
                        except Exception:
                            return ""

                    def _snapshot(tag):
                        body = _body_preview()
                        html = _html_preview()
                        snap = {
                            "tag": tag,
                            "url": str(page.url or ""),
                            "title": _title(),
                            "body": body[:800],
                            "challenge": _looks_like_challenge(body, html),
                            "route_error": _looks_like_route_error(body, html),
                        }
                        attempts.append(snap)
                        return snap, body, html

                    def _fill_and_submit(selectors, value, labels):
                        if not value:
                            return {"ok": False, "reason": "empty_value"}
                        try:
                            return page.evaluate(
                                """
                                (payload) => {
                                  const selectors = Array.isArray(payload?.selectors) ? payload.selectors : [];
                                  const value = String(payload?.value ?? '');
                                  const labels = Array.isArray(payload?.labels) ? payload.labels.map((item) => String(item || '').trim().toLowerCase()) : [];
                                  const isVisible = (el) => {
                                    if (!el) return false;
                                    const style = window.getComputedStyle(el);
                                    const rect = el.getBoundingClientRect();
                                    return !!rect.width && !!rect.height && style.visibility !== 'hidden' && style.display !== 'none';
                                  };
                                  const textOf = (el) => String(el?.innerText || el?.textContent || el?.value || '').trim().toLowerCase();
                                  const isSocialLabel = (label) => {
                                    const lowered = String(label || '').trim().toLowerCase();
                                    if (!lowered) return false;
                                    return (
                                      lowered.includes('continue with')
                                      || lowered.includes('google')
                                      || lowered.includes('apple')
                                      || lowered.includes('microsoft')
                                      || lowered.includes('phone')
                                    );
                                  };
                                  let input = null;
                                  for (const selector of selectors) {
                                    const candidate = Array.from(document.querySelectorAll(selector)).find((el) => isVisible(el) && !el.disabled);
                                    if (candidate) {
                                      input = candidate;
                                      break;
                                    }
                                  }
                                  if (!input) return {ok: false, reason: 'no_input'};
                                  input.focus();
                                  input.value = '';
                                  input.dispatchEvent(new Event('input', {bubbles: true}));
                                  input.value = value;
                                  input.dispatchEvent(new Event('input', {bubbles: true}));
                                  input.dispatchEvent(new Event('change', {bubbles: true}));

                                  const findSubmit = (root) => {
                                    const nodes = Array.from((root || document).querySelectorAll('button, input[type="submit"], [role="button"]'));
                                    return nodes.find((el) => {
                                      if (!isVisible(el) || el.disabled) return false;
                                      const label = textOf(el);
                                      if (isSocialLabel(label)) return false;
                                      return !labels.length || labels.some((part) => label === part || label.startsWith(part + ' ') || label.includes(part));
                                    });
                                  };

                                  const form = input.closest('form');
                                  if (form) {
                                    if (typeof form.requestSubmit === 'function') {
                                      form.requestSubmit();
                                      return {ok: true, via: 'form_request_submit'};
                                    }
                                    const submit = findSubmit(form);
                                    if (submit) {
                                      submit.click();
                                      return {ok: true, via: 'form_button', label: textOf(submit)};
                                    }
                                  }

                                  input.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true}));
                                  input.dispatchEvent(new KeyboardEvent('keyup', {key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true}));

                                  const localRoot = input.parentElement?.closest('form, div, section, main') || document.body;
                                  const localSubmit = findSubmit(localRoot);
                                  if (localSubmit) {
                                    localSubmit.click();
                                    return {ok: true, via: 'local_button', label: textOf(localSubmit)};
                                  }
                                  return {ok: true, via: 'enter_only'};
                                }
                                """,
                                {
                                    "selectors": list(selectors or []),
                                    "value": str(value or ""),
                                    "labels": list(labels or []),
                                },
                            )
                        except Exception as exc:
                            self._log(f"authorize/continue 浏览器 fallback 表单提交异常: {exc}")
                            return {"ok": False, "error": str(exc)}

                    def _browser_authorize_continue_fetch():
                        if not device_id:
                            return None
                        try:
                            return page.evaluate(
                                """
                                async ({email, deviceId}) => {
                                  try {
                                    let token = '';
                                    let tokenFlow = '';
                                    const flows = ['authorize_continue', 'password_verify', 'oauth_create_account'];
                                    if (window.SentinelSDK && typeof window.SentinelSDK.token === 'function') {
                                      for (const flow of flows) {
                                        try {
                                          const candidate = await window.SentinelSDK.token(flow);
                                          if (candidate) {
                                            token = candidate;
                                            tokenFlow = flow;
                                            break;
                                          }
                                        } catch (_) {}
                                      }
                                    }
                                    const headers = {
                                      accept: 'application/json, text/plain, */*',
                                      'content-type': 'application/json',
                                      'oai-device-id': deviceId,
                                    };
                                    if (token) {
                                      headers['openai-sentinel-token'] = token;
                                    }
                                    const response = await fetch('/api/accounts/authorize/continue', {
                                      method: 'POST',
                                      credentials: 'include',
                                      headers,
                                      body: JSON.stringify({username: {kind: 'email', value: email}}),
                                    });
                                    const text = await response.text();
                                    let data = null;
                                    try { data = JSON.parse(text); } catch (_) {}
                                    return {
                                      ok: response.ok,
                                      status: response.status,
                                      url: response.url,
                                      text: text.slice(0, 1200),
                                      data,
                                      tokenFlow,
                                      pageUrl: window.location.href,
                                      bodyText: (document.body && document.body.innerText) ? document.body.innerText.slice(0, 1600) : '',
                                    };
                                  } catch (error) {
                                    return {error: String(error)};
                                  }
                                }
                                """,
                                {"email": email_value, "deviceId": device_id},
                            )
                        except Exception as exc:
                            self._log(f"authorize/continue 浏览器 fallback fetch 异常: {exc}")
                            return {"error": str(exc)}

                    request_url = f"{self.oauth_issuer}/api/accounts/authorize/continue"
                    for attempt_idx in range(2):
                        captured.clear()
                        try:
                            page.goto(request_url, wait_until="domcontentloaded", timeout=45000)
                        except PlaywrightTimeoutError as exc:
                            self._log(f"authorize/continue 浏览器 fallback 打开超时: {exc}")
                        except Exception as exc:
                            self._log(f"authorize/continue 浏览器 fallback 打开异常: {exc}")
                        page.wait_for_timeout(2500)
                        snap, body, html = _snapshot(f"attempt{attempt_idx+1}_initial")

                        if _looks_like_challenge(body, html) or _looks_like_route_error(body, html):
                            self._log(
                                "authorize/continue 浏览器 fallback 初始页异常: "
                                f"url={snap['url'][:120]} title={snap['title'][:80]!r}"
                            )
                            if attempt_idx == 0:
                                continue
                            break

                        current_url = str(page.url or "")
                        lowered_url = current_url.lower()
                        skip_email_submit = False
                        if any(token in lowered_url for token in ("/log-in-or-create-account", "/log-in")):
                            fetch_result = _browser_authorize_continue_fetch()
                            if isinstance(fetch_result, dict) and not fetch_result.get("error"):
                                fetch_status = fetch_result.get("status")
                                fetch_flow = str(fetch_result.get("tokenFlow") or "").strip()
                                fetch_text = str(fetch_result.get("text") or "")[:240]
                                if fetch_flow:
                                    self._log(
                                        "authorize/continue 浏览器 fallback fetch sentinel "
                                        f"flow={fetch_flow}"
                                    )
                                self._log(
                                    "authorize/continue 浏览器 fallback fetch -> "
                                    f"status={fetch_status} url={str(fetch_result.get('pageUrl') or page.url)[:120]}"
                                )
                                if fetch_status == 200 and isinstance(fetch_result.get("data"), dict):
                                    state = self._state_from_payload(
                                        fetch_result["data"],
                                        current_url=str(fetch_result.get("pageUrl") or page.url or request_url),
                                    )
                                    if not state.page_type:
                                        state = self._state_from_url(str(fetch_result.get("pageUrl") or page.url or request_url))
                                    if self._state_is_login_password(state) and password_value:
                                        self._log(
                                            "authorize/continue 浏览器 fallback fetch 落到 login_password，"
                                            "继续在浏览器内提交密码，不回退到协议 /password/verify"
                                        )
                                        target_url = str(state.current_url or state.continue_url or "").strip()
                                        if target_url:
                                            try:
                                                page.goto(target_url, wait_until="domcontentloaded", timeout=45000)
                                                page.wait_for_timeout(1200)
                                                current_url = str(page.url or "")
                                                lowered_url = current_url.lower()
                                                if "/create-account/password" in lowered_url or "/log-in/password" in lowered_url:
                                                    skip_email_submit = True
                                            except Exception as exc:
                                                self._log(
                                                    "authorize/continue 浏览器 fallback 跳转 password 页失败: "
                                                    f"{exc}"
                                                )
                                    else:
                                        Path(result_path).write_text(
                                            json.dumps(
                                                {
                                                    "attempts": attempts,
                                                    "responses": captured,
                                                    "fetch_result": fetch_result,
                                                    "final_state": {
                                                        "page_type": state.page_type,
                                                        "method": state.method,
                                                        "current_url": state.current_url,
                                                        "continue_url": state.continue_url,
                                                    },
                                                },
                                                ensure_ascii=False,
                                                indent=2,
                                            ),
                                            encoding="utf-8",
                                        )
                                        self._log(
                                            "authorize/continue 浏览器 fallback fetch 成功: "
                                            f"{describe_flow_state(state)} artifact={result_path}"
                                        )
                                        return state
                                if fetch_status and fetch_status != 200 and fetch_text:
                                    self._log(
                                        "authorize/continue 浏览器 fallback fetch 未直接恢复: "
                                        f"{fetch_status} {fetch_text[:180]}"
                                    )
                            if not skip_email_submit:
                                submit_result = _fill_and_submit(
                                    (
                                        "input[type='email']",
                                        "input[name='email']",
                                        "input[name='username']",
                                        "input[autocomplete='email']",
                                    ),
                                    email_value,
                                    ("continue", "next", "log in"),
                                )
                                if not (submit_result or {}).get("ok"):
                                    self._log("authorize/continue 浏览器 fallback 邮箱提交失败")
                                    if attempt_idx == 0:
                                        continue
                                    break
                                self._log(
                                    "authorize/continue 浏览器 fallback 邮箱提交 "
                                    f"via={str((submit_result or {}).get('via') or '')}"
                                )
                                page.wait_for_timeout(4500)
                                snap, body, html = _snapshot(f"attempt{attempt_idx+1}_after_email")
                                current_url = str(page.url or "")
                                lowered_url = current_url.lower()
                                if any(token in lowered_url for token in ("/log-in-or-create-account", "/log-in")):
                                    fetch_result = _browser_authorize_continue_fetch()
                                    if isinstance(fetch_result, dict) and not fetch_result.get("error"):
                                        fetch_status = fetch_result.get("status")
                                        fetch_flow = str(fetch_result.get("tokenFlow") or "").strip()
                                        fetch_text = str(fetch_result.get("text") or "")[:240]
                                        if fetch_flow:
                                            self._log(
                                                "authorize/continue 浏览器 fallback after_email fetch sentinel "
                                                f"flow={fetch_flow}"
                                            )
                                        self._log(
                                            "authorize/continue 浏览器 fallback after_email fetch -> "
                                            f"status={fetch_status} url={str(fetch_result.get('pageUrl') or page.url)[:120]}"
                                        )
                                        if fetch_status == 200 and isinstance(fetch_result.get("data"), dict):
                                            state = self._state_from_payload(
                                                fetch_result["data"],
                                                current_url=str(fetch_result.get("pageUrl") or page.url or request_url),
                                            )
                                            if not state.page_type:
                                                state = self._state_from_url(
                                                    str(fetch_result.get("pageUrl") or page.url or request_url)
                                                )
                                            if self._state_is_login_password(state) and password_value:
                                                self._log(
                                                    "authorize/continue 浏览器 fallback after_email fetch 落到 login_password，"
                                                    "继续在浏览器内提交密码，不回退到协议 /password/verify"
                                                )
                                                target_url = str(state.current_url or state.continue_url or "").strip()
                                                if target_url:
                                                    try:
                                                        page.goto(target_url, wait_until="domcontentloaded", timeout=45000)
                                                        page.wait_for_timeout(1200)
                                                        current_url = str(page.url or "")
                                                        lowered_url = current_url.lower()
                                                    except Exception as exc:
                                                        self._log(
                                                            "authorize/continue 浏览器 fallback after_email 跳转 password 页失败: "
                                                            f"{exc}"
                                                        )
                                            else:
                                                Path(result_path).write_text(
                                                    json.dumps(
                                                        {
                                                            "attempts": attempts,
                                                            "responses": captured,
                                                            "fetch_result": fetch_result,
                                                            "final_state": {
                                                                "page_type": state.page_type,
                                                                "method": state.method,
                                                                "current_url": state.current_url,
                                                                "continue_url": state.continue_url,
                                                            },
                                                        },
                                                        ensure_ascii=False,
                                                        indent=2,
                                                    ),
                                                    encoding="utf-8",
                                                )
                                                self._log(
                                                    "authorize/continue 浏览器 fallback after_email fetch 成功: "
                                                    f"{describe_flow_state(state)} artifact={result_path}"
                                                )
                                                return state
                                        if fetch_status and fetch_status != 200 and fetch_text:
                                            self._log(
                                                "authorize/continue 浏览器 fallback after_email fetch 未直接恢复: "
                                                f"{fetch_status} {fetch_text[:180]}"
                                            )

                        if (
                            "/create-account/password" in lowered_url
                            or "/log-in/password" in lowered_url
                        ) and password_value:
                            submit_result = _fill_and_submit(
                                (
                                    "input[type='password']",
                                    "input[name='password']",
                                    "input[autocomplete='new-password']",
                                    "input[autocomplete='current-password']",
                                ),
                                password_value,
                                ("continue", "next", "log in"),
                            )
                            if (submit_result or {}).get("ok"):
                                self._log(
                                    "authorize/continue 浏览器 fallback 密码提交 "
                                    f"via={str((submit_result or {}).get('via') or '')}"
                                )
                                page.wait_for_timeout(4500)
                                snap, body, html = _snapshot(f"attempt{attempt_idx+1}_after_password")
                                current_url = str(page.url or "")
                                lowered_url = current_url.lower()
                                if any(token in lowered_url for token in ("/log-in-or-create-account", "/log-in")):
                                    fetch_result = _browser_authorize_continue_fetch()
                                    if isinstance(fetch_result, dict) and not fetch_result.get("error"):
                                        fetch_status = fetch_result.get("status")
                                        fetch_flow = str(fetch_result.get("tokenFlow") or "").strip()
                                        fetch_text = str(fetch_result.get("text") or "")[:240]
                                        if fetch_flow:
                                            self._log(
                                                "authorize/continue 浏览器 fallback after_password fetch sentinel "
                                                f"flow={fetch_flow}"
                                            )
                                        self._log(
                                            "authorize/continue 浏览器 fallback after_password fetch -> "
                                            f"status={fetch_status} url={str(fetch_result.get('pageUrl') or page.url)[:120]}"
                                        )
                                        if fetch_status == 200 and isinstance(fetch_result.get("data"), dict):
                                            state = self._state_from_payload(
                                                fetch_result["data"],
                                                current_url=str(fetch_result.get("pageUrl") or page.url or request_url),
                                            )
                                            if not state.page_type:
                                                state = self._state_from_url(
                                                    str(fetch_result.get("pageUrl") or page.url or request_url)
                                                )
                                            Path(result_path).write_text(
                                                json.dumps(
                                                    {
                                                        "attempts": attempts,
                                                        "responses": captured,
                                                        "fetch_result": fetch_result,
                                                        "final_state": {
                                                            "page_type": state.page_type,
                                                            "method": state.method,
                                                            "current_url": state.current_url,
                                                            "continue_url": state.continue_url,
                                                        },
                                                    },
                                                    ensure_ascii=False,
                                                    indent=2,
                                                ),
                                                encoding="utf-8",
                                            )
                                            self._log(
                                                "authorize/continue 浏览器 fallback after_password fetch 成功: "
                                                f"{describe_flow_state(state)} artifact={result_path}"
                                            )
                                            return state
                                        if fetch_status and fetch_status != 200 and fetch_text:
                                            self._log(
                                                "authorize/continue 浏览器 fallback after_password fetch 未直接恢复: "
                                                f"{fetch_status} {fetch_text[:180]}"
                                            )

                        self._sync_playwright_cookies(context.cookies())
                        snap, body, html = _snapshot(f"attempt{attempt_idx+1}_final")
                        if _looks_like_challenge(body, html) or _looks_like_route_error(body, html):
                            self._log(
                                "authorize/continue 浏览器 fallback 最终仍被 challenge/route_error 拦截: "
                                f"url={snap['url'][:120]} title={snap['title'][:80]!r}"
                            )
                            if attempt_idx == 0:
                                continue
                            break

                        state = self._state_from_url(str(page.url or request_url))
                        if state.current_url or state.page_type:
                            Path(result_path).write_text(
                                json.dumps(
                                    {
                                        "attempts": attempts,
                                        "responses": captured,
                                        "final_state": {
                                            "page_type": state.page_type,
                                            "method": state.method,
                                            "current_url": state.current_url,
                                            "continue_url": state.continue_url,
                                        },
                                    },
                                    ensure_ascii=False,
                                    indent=2,
                                ),
                                encoding="utf-8",
                            )
                            self._log(
                                "authorize/continue 浏览器 fallback 成功: "
                                f"{describe_flow_state(state)} artifact={result_path}"
                            )
                            return state

                    Path(result_path).write_text(
                        json.dumps(
                            {"attempts": attempts, "responses": captured},
                            ensure_ascii=False,
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
                    self._log(f"authorize/continue 浏览器 fallback 失败，artifact={result_path}")
                    return None
                finally:
                    browser.close()

        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(run_browser).result(timeout=180)
        except FutureTimeoutError:
            self._log("authorize/continue 浏览器 fallback 超时")
            return None
        except Exception as exc:
            self._log(f"authorize/continue 浏览器 fallback 异常: {exc}")
            return None

    def _headers(
        self,
        url,
        *,
        user_agent=None,
        sec_ch_ua=None,
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
        accept_language = None
        try:
            accept_language = self.session.headers.get("Accept-Language")
        except Exception:
            accept_language = None

        return build_browser_headers(
            url=url,
            user_agent=user_agent or "Mozilla/5.0",
            sec_ch_ua=sec_ch_ua,
            accept=accept,
            accept_language=accept_language or "en-US,en;q=0.9",
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

    def _state_from_url(self, url, method="GET"):
        state = extract_flow_state(
            current_url=normalize_flow_url(url, auth_base=self.oauth_issuer),
            auth_base=self.oauth_issuer,
            default_method=method,
        )
        if method:
            state.method = str(method).upper()
        return state

    def _state_from_payload(self, data, current_url=""):
        self._capture_client_auth_session_from_navigation_payload(
            data,
            source=current_url or "",
        )
        return extract_flow_state(
            data=data,
            current_url=current_url,
            auth_base=self.oauth_issuer,
        )

    def _capture_client_auth_session_from_navigation_payload(self, data, *, source=""):
        if not isinstance(data, dict):
            return None
        payload = data.get("oai-client-auth-session")
        if not isinstance(payload, dict):
            return None
        try:
            cached = dict(payload)
            self.latest_navigation_client_auth_session = cached
            self._log(
                "navigation payload 提供 client auth session: "
                f"source={str(source)[:120]} "
                f"openai_client_id={str(cached.get('openai_client_id') or '')[:48]} "
                f"workspaces={len(list(cached.get('workspaces') or []))}"
            )
            return cached
        except Exception as exc:
            self._log(f"记录 navigation client auth session 失败: {exc}")
            return None

    def _load_workspace_session_data_from_navigation_cache(self):
        payload = dict(getattr(self, "latest_navigation_client_auth_session", {}) or {})
        if not payload:
            return None
        workspaces = list(payload.get("workspaces") or [])
        if not workspaces:
            self._log(
                "navigation client auth session 已缓存，但仍无 workspace: "
                + ",".join(sorted(str(k) for k in payload.keys()))
            )
            return None
        return payload

    def _state_signature(self, state: FlowState):
        return (
            state.page_type or "",
            state.method or "",
            state.continue_url or "",
            state.current_url or "",
        )

    def _extract_code_from_state(self, state: FlowState):
        for candidate in (
            state.continue_url,
            state.current_url,
            (state.payload or {}).get("url", ""),
        ):
            code = self._extract_code_from_url(candidate)
            if code:
                return code
        return None

    def _decode_login_session_cookie(self):
        import base64
        import json

        raw_value = ""
        try:
            for cookie in list(getattr(self.session.cookies, "jar", []) or []):
                if str(getattr(cookie, "name", "") or "").strip() != "login_session":
                    continue
                raw_value = str(getattr(cookie, "value", "") or "").strip()
                if raw_value:
                    break
        except Exception:
            raw_value = ""

        if not raw_value:
            return {}

        encoded = str(raw_value).split(".", 1)[0].strip()
        if not encoded:
            return {}

        padded = encoded + ("=" * (-len(encoded) % 4))
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                payload = decoder(padded)
                parsed = json.loads(payload.decode("utf-8", errors="ignore"))
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                continue
        return {}

    def _state_from_login_session_cookie(self):
        payload = self._decode_login_session_cookie()
        challenge = str(payload.get("login_challenge") or "").strip()
        if not challenge:
            return None
        login_url = f"{self.oauth_issuer}/log-in?login_challenge={challenge}"
        return self._state_from_url(login_url)

    def _state_is_login_password(self, state: FlowState):
        return state.page_type == "login_password"

    def _state_is_email_otp(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        return state.page_type == "email_otp_verification" or "email-verification" in target or "email-otp" in target

    def _state_is_about_you(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        return state.page_type == "about_you" or "about-you" in target

    def _state_is_add_phone(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        return state.page_type == "add_phone" or "add-phone" in target

    def _state_is_chatgpt_auth_error(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        if "chatgpt.com/auth/login_with" in target or "chatgpt.com/auth/error" in target:
            return True
        if (
            "auth.openai.com/auth/login" in target
            and "callbackurl=https%3a%2f%2fchatgpt.com%2f" in target
            and "error=" in target
        ):
            return True
        return state.page_type == "auth_login" and "error=" in target and "callbackurl=" in target

    def _browser_tokens_are_terminal(self, tokens):
        if not isinstance(tokens, dict) or not str(tokens.get("access_token") or "").strip():
            return False
        if str(tokens.get("refresh_token") or "").strip():
            return True
        if self._is_chatgpt_web_client():
            return True
        jwt_payload = decode_jwt_payload(str(tokens.get("access_token") or "").strip())
        auth_payload = jwt_payload.get("https://api.openai.com/auth") or {}
        return bool(auth_payload.get("localhost"))

    def _state_requires_navigation(self, state: FlowState):
        method = (state.method or "GET").upper()
        if method != "GET":
            return False
        target = f"{state.continue_url} {state.current_url}".lower()
        if "/api/accounts/login" in target and "login_challenge=" in target:
            return True
        if self._state_is_chatgpt_auth_error(state):
            return True
        if (
            state.source == "api"
            and state.current_url
            and state.page_type not in {"login_password", "email_otp_verification"}
        ):
            return True
        if state.page_type == "external_url" and state.continue_url:
            return True
        if state.continue_url and state.continue_url != state.current_url:
            return True
        return False

    def _resume_after_browser_bridge(
        self,
        browser_tokens,
        *,
        authorize_url,
        authorize_params,
        code_verifier,
        state,
        referer,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
        reason="browser bridge",
    ):
        if not browser_tokens:
            return False, None, referer
        if self._browser_tokens_are_terminal(browser_tokens):
            self._log(f"✅ {reason} 已恢复目标 token")
            return True, browser_tokens, referer

        self._log(
            f"{reason} 仅恢复到 ChatGPT Web session，继续重试 Codex localhost authorize"
        )
        direct_tokens = self._try_direct_authorize_reentry(
            authorize_url,
            authorize_params,
            code_verifier,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            impersonate=impersonate,
        )
        if direct_tokens:
            if self._browser_tokens_are_terminal(direct_tokens):
                self._log(f"✅ {reason} 后 direct authorize re-entry 恢复目标 token")
                return True, direct_tokens, referer
            self._log(
                f"{reason} 后 direct authorize re-entry 仍只拿到 ChatGPT Web session，继续协议状态机"
            )

        resume_target = (
            str(getattr(self, "last_direct_authorize_login_challenge_url", "") or "").strip()
            or str(getattr(self, "last_direct_authorize_final_url", "") or "").strip()
        )
        if resume_target.startswith(self.oauth_issuer):
            self._log(
                f"{reason} 后 direct authorize re-entry 已回到 auth.openai.com，继续协议状态机"
            )
            next_referer = state.current_url or state.continue_url or referer
            return False, self._state_from_url(resume_target), next_referer

        self._log(f"{reason} 后仍未拿到目标 token")
        return False, None, referer

    def _state_supports_workspace_resolution(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        if state.page_type in {"consent", "workspace_selection", "organization_selection"}:
            return True
        if any(marker in target for marker in ("sign-in-with-chatgpt", "consent", "workspace", "organization")):
            return True
        session_data = self._decode_oauth_session_cookie() or {}
        return bool(session_data.get("workspaces"))

    def _follow_flow_state(self, state: FlowState, referer=None, user_agent=None, impersonate=None, max_hops=16):
        """跟随服务端返回的 continue_url / current_url，返回新的状态或 authorization code。"""
        import re

        current_url = state.continue_url or state.current_url
        last_url = current_url or ""
        referer_url = referer

        if not current_url:
            return None, state

        initial_code = self._extract_code_from_url(current_url)
        if initial_code:
            return initial_code, self._state_from_url(current_url)
        initial_callback = self._extract_chatgpt_callback_url(current_url)
        if initial_callback:
            return None, self._state_from_url(initial_callback)

        for hop in range(max_hops):
            try:
                headers = self._headers(
                    current_url,
                    user_agent=user_agent,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    referer=referer_url,
                    navigation=True,
                )
                kwargs = {"headers": headers, "allow_redirects": False, "timeout": 30}
                if impersonate:
                    kwargs["impersonate"] = impersonate

                self._browser_pause(0.12, 0.3)
                r = self.session.get(current_url, **kwargs)
                last_url = str(r.url)
                self._log(f"follow[{hop + 1}] {r.status_code} {last_url[:120]}")
            except Exception as e:
                maybe_localhost = re.search(r'(https?://localhost[^\s\'\"]+)', str(e))
                if maybe_localhost:
                    location = maybe_localhost.group(1)
                    code = self._extract_code_from_url(location)
                    if code:
                        self._log("从 localhost 异常提取到 authorization code")
                        return code, self._state_from_url(location)
                self._log(f"follow[{hop + 1}] 异常: {str(e)[:160]}")
                return None, self._state_from_url(last_url or current_url)

            code = self._extract_code_from_url(last_url)
            if code:
                return code, self._state_from_url(last_url)
            callback_url = self._extract_chatgpt_callback_url(last_url)
            if callback_url:
                self._log("follow 命中 ChatGPT callback/openai，返回 callback state 交给 session 恢复")
                return None, self._state_from_url(callback_url)

            if r.status_code in (301, 302, 303, 307, 308):
                location = normalize_flow_url(r.headers.get("Location", ""), auth_base=self.oauth_issuer)
                if not location:
                    return None, self._state_from_url(last_url or current_url)
                code = self._extract_code_from_url(location)
                if code:
                    return code, self._state_from_url(location)
                callback_url = self._extract_chatgpt_callback_url(location)
                if callback_url:
                    self._log("follow 重定向命中 ChatGPT callback/openai，返回 callback state 交给 session 恢复")
                    return None, self._state_from_url(callback_url)
                referer_url = last_url or referer_url
                current_url = location
                continue

            content_type = (r.headers.get("content-type", "") or "").lower()
            if "application/json" in content_type:
                try:
                    next_state = self._state_from_payload(r.json(), current_url=last_url or current_url)
                except Exception:
                    next_state = self._state_from_url(last_url or current_url)
            else:
                next_state = self._state_from_url(last_url or current_url)

            return None, next_state

        return None, self._state_from_url(last_url or current_url)

    def _bootstrap_oauth_session(self, authorize_url, authorize_params, device_id=None, user_agent=None, sec_ch_ua=None, impersonate=None):
        """启动 OAuth 会话，确保 auth 域上的 login_session 已建立。"""
        if device_id:
            seed_oai_device_cookie(self.session, device_id)

        has_login_session = False
        authorize_final_url = ""

        try:
            headers = self._headers(
                authorize_url,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                referer="https://chatgpt.com/",
                navigation=True,
            )
            kwargs = {"params": authorize_params, "headers": headers, "allow_redirects": True, "timeout": 30}
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r = self.session.get(authorize_url, **kwargs)
            authorize_final_url = str(r.url)
            redirects = len(getattr(r, "history", []) or [])
            self._log(f"/oauth/authorize -> {r.status_code}, redirects={redirects}")

            has_login_session = any(
                (cookie.name if hasattr(cookie, "name") else str(cookie)) == "login_session"
                for cookie in self.session.cookies
            )
            self._log(f"login_session: {'已获取' if has_login_session else '未获取'}")
        except Exception as e:
            self._log(f"/oauth/authorize 异常: {e}")

        if has_login_session:
            return authorize_final_url

        self._log("未获取到 login_session，尝试 /api/oauth/oauth2/auth...")
        try:
            oauth2_url = f"{self.oauth_issuer}/api/oauth/oauth2/auth"
            kwargs = {
                "params": authorize_params,
                "headers": self._headers(
                    oauth2_url,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    referer="https://chatgpt.com/",
                    navigation=True,
                ),
                "allow_redirects": True,
                "timeout": 30,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r2 = self.session.get(oauth2_url, **kwargs)
            authorize_final_url = str(r2.url)
            redirects2 = len(getattr(r2, "history", []) or [])
            self._log(f"/api/oauth/oauth2/auth -> {r2.status_code}, redirects={redirects2}")

            has_login_session = any(
                (cookie.name if hasattr(cookie, "name") else str(cookie)) == "login_session"
                for cookie in self.session.cookies
            )
            self._log(f"login_session(重试): {'已获取' if has_login_session else '未获取'}")
        except Exception as e:
            self._log(f"/api/oauth/oauth2/auth 异常: {e}")

        return authorize_final_url

    def _submit_authorize_continue(
        self,
        email,
        device_id,
        continue_referer,
        *,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
        authorize_url=None,
        authorize_params=None,
    ):
        """提交邮箱，获取 OAuth 流程的第一页状态。"""
        self._log("步骤2: POST /api/accounts/authorize/continue")

        sentinel_token = None
        sentinel_flow = None
        for candidate_flow in ("authorize_continue", "password_verify", "oauth_create_account"):
            sentinel_token = build_sentinel_token(
                self.session,
                device_id,
                flow=candidate_flow,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                impersonate=impersonate,
            )
            if sentinel_token:
                sentinel_flow = candidate_flow
                break
        if not sentinel_token:
            self._log("无法获取 sentinel token (authorize_continue)")
            return None
        if sentinel_flow != "authorize_continue":
            self._log(f"authorize_continue 使用 sentinel fallback flow={sentinel_flow}")

        request_url = f"{self.oauth_issuer}/api/accounts/authorize/continue"
        headers = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="application/json",
            referer=continue_referer,
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={
                "oai-device-id": device_id,
                "openai-sentinel-token": sentinel_token,
            },
        )
        headers.update(generate_datadog_trace())
        payload = {"username": {"kind": "email", "value": email}}

        try:
            kwargs = {"json": payload, "headers": headers, "timeout": 30, "allow_redirects": False}
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r = self.session.post(request_url, **kwargs)
            self._log(f"/authorize/continue -> {r.status_code}")

            if r.status_code == 400 and "invalid_auth_step" in (r.text or "") and authorize_url and authorize_params:
                self._log("invalid_auth_step，重新 bootstrap...")
                authorize_final_url = self._bootstrap_oauth_session(
                    authorize_url,
                    authorize_params,
                    device_id=device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                )
                continue_referer = (
                    authorize_final_url
                    if authorize_final_url.startswith(self.oauth_issuer)
                    else f"{self.oauth_issuer}/log-in"
                )
                headers["Referer"] = continue_referer
                headers["Sec-Fetch-Site"] = "same-origin"
                headers.update(generate_datadog_trace())
                kwargs = {"json": payload, "headers": headers, "timeout": 30, "allow_redirects": False}
                if impersonate:
                    kwargs["impersonate"] = impersonate
                self._browser_pause()
                r = self.session.post(request_url, **kwargs)
                self._log(f"/authorize/continue(重试) -> {r.status_code}")

            content_type = (r.headers.get("content-type", "") or "").lower()
            body_preview = str(r.text or "")[:400]
            looks_like_challenge = (
                "text/html" in content_type
                or "just a moment" in body_preview.lower()
                or "cloudflare" in body_preview.lower()
                or "unexpected token '<'" in body_preview.lower()
                or "invalid content type: text/html" in body_preview.lower()
            )
            if r.status_code != 200 or "application/json" not in content_type or looks_like_challenge:
                self._log(
                    "提交邮箱失败，改走 authorize/continue 浏览器 fallback: "
                    f"status={r.status_code} content-type={content_type} body={body_preview[:160]!r}"
                )
                browser_state = self._submit_authorize_continue_browser_fallback(
                    email,
                    user_agent=user_agent,
                )
                if browser_state:
                    return browser_state
                self._log(f"提交邮箱失败: {body_preview[:180]}")
                return None

            data = r.json()
            flow_state = self._state_from_payload(data, current_url=str(r.url) or request_url)
            self._log(describe_flow_state(flow_state))
            return flow_state
        except Exception as e:
            self._log(f"提交邮箱异常: {e}")
            browser_state = self._submit_authorize_continue_browser_fallback(
                email,
                user_agent=user_agent,
            )
            if browser_state:
                self._log("提交邮箱异常后已通过 authorize/continue 浏览器 fallback 重建状态")
                return browser_state
            return None

    def _submit_password_verify(self, password, device_id, *, user_agent=None, sec_ch_ua=None, impersonate=None, referer=None):
        """提交密码，获取下一步状态。"""
        self._log("步骤3: POST /api/accounts/password/verify")

        sentinel_pwd = build_sentinel_token(
            self.session,
            device_id,
            flow="password_verify",
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            impersonate=impersonate,
        )
        if not sentinel_pwd:
            self._log("无法获取 sentinel token (password_verify)")
            return None

        request_url = f"{self.oauth_issuer}/api/accounts/password/verify"
        headers = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="application/json",
            referer=referer or f"{self.oauth_issuer}/log-in/password",
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={
                "oai-device-id": device_id,
                "openai-sentinel-token": sentinel_pwd,
            },
        )
        headers.update(generate_datadog_trace())

        try:
            kwargs = {"json": {"password": password}, "headers": headers, "timeout": 30, "allow_redirects": False}
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r = self.session.post(request_url, **kwargs)
            self._log(f"/password/verify -> {r.status_code}")

            content_type = (r.headers.get("content-type", "") or "").lower()
            body_preview = str(r.text or "")[:400]
            looks_like_challenge = (
                "text/html" in content_type
                or "just a moment" in body_preview.lower()
                or "cloudflare" in body_preview.lower()
                or "unexpected token '<'" in body_preview.lower()
                or "invalid content type: text/html" in body_preview.lower()
            )
            if r.status_code != 200 or "application/json" not in content_type or looks_like_challenge:
                self._log(
                    "密码验证失败，改走 authorize/continue 浏览器 fallback: "
                    f"status={r.status_code} content-type={content_type} body={body_preview[:160]!r}"
                )
                browser_state = self._submit_password_verify_browser_fallback(
                    password,
                    device_id,
                    user_agent=user_agent,
                    referer=referer,
                )
                if browser_state:
                    return browser_state
                browser_state = self._submit_authorize_continue_browser_fallback(
                    str(getattr(self, "current_email", "") or "").strip(),
                    user_agent=user_agent,
                )
                if browser_state:
                    return browser_state
                self._log(f"密码验证失败: {body_preview[:180]}")
                return None

            data = r.json()
            flow_state = self._state_from_payload(data, current_url=str(r.url) or request_url)
            self.password_verify_led_to_email_otp = self._state_is_email_otp(flow_state)
            if bool(getattr(self, "prefer_email_otp_first", False)) and self._state_is_about_you(flow_state):
                self.direct_authorize_before_about_you_once = True
                self._log(
                    "password_verify 命中 about_you，下一次 about_you 先尝试 direct authorize re-entry"
                )
            if self.password_verify_led_to_email_otp:
                self._log("password_verify 已进入 email_otp_verification，后续优先等待真实邮箱 OTP")
            self._log(f"verify {describe_flow_state(flow_state)}")
            return flow_state
        except Exception as e:
            self._log(f"密码验证异常: {e}")
            return None

    def _submit_password_verify_browser_fallback(self, password, device_id, *, user_agent=None, referer=None):
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
        except Exception as exc:
            self._log(f"password/verify 浏览器 fallback 不可用: {exc}")
            return None

        password_value = str(password or "").strip()
        if not password_value or not device_id:
            return None

        launch_kwargs = {
            "headless": self.browser_mode != "headed",
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}
        launch_kwargs = prepare_playwright_launch_kwargs(launch_kwargs, self.browser_mode, self._log)

        request_url = f"{self.oauth_issuer}/api/accounts/password/verify"
        page_url = str(referer or f"{self.oauth_issuer}/log-in/password").strip() or f"{self.oauth_issuer}/log-in/password"
        result_path = f"/tmp/oauth_password_verify_browser_{int(time.time() * 1000)}.json"

        def run_browser():
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**launch_kwargs)
                try:
                    context = harden_playwright_context(
                        browser.new_context(**self._playwright_context_kwargs(user_agent=user_agent))
                    )
                    self._add_cookies_to_playwright_context(
                        context,
                        self._cookies_for_playwright(),
                        "password/verify 浏览器 fallback",
                    )
                    page = context.new_page()
                    try:
                        page.goto(page_url, wait_until="domcontentloaded", timeout=45000)
                    except PlaywrightTimeoutError as exc:
                        self._log(f"password/verify 浏览器 fallback 打开超时: {exc}")
                    except Exception as exc:
                        self._log(f"password/verify 浏览器 fallback 打开异常: {exc}")
                    page.wait_for_timeout(2200)

                    def browser_fetch():
                        try:
                            return page.evaluate(
                                """
                                async ({password, deviceId}) => {
                                  try {
                                    let token = '';
                                    let tokenFlow = '';
                                    const flows = ['password_verify', 'authorize_continue', 'oauth_create_account'];
                                    if (window.SentinelSDK && typeof window.SentinelSDK.token === 'function') {
                                      for (const flow of flows) {
                                        try {
                                          const candidate = await window.SentinelSDK.token(flow);
                                          if (candidate) {
                                            token = candidate;
                                            tokenFlow = flow;
                                            break;
                                          }
                                        } catch (_) {}
                                      }
                                    }
                                    const headers = {
                                      accept: 'application/json, text/plain, */*',
                                      'content-type': 'application/json',
                                      'oai-device-id': deviceId,
                                    };
                                    if (token) headers['openai-sentinel-token'] = token;
                                    const response = await fetch('/api/accounts/password/verify', {
                                      method: 'POST',
                                      credentials: 'include',
                                      headers,
                                      body: JSON.stringify({password}),
                                    });
                                    const text = await response.text();
                                    let data = null;
                                    try { data = JSON.parse(text); } catch (_) {}
                                    return {
                                      ok: response.ok,
                                      status: response.status,
                                      url: response.url,
                                      text: text.slice(0, 1200),
                                      data,
                                      tokenFlow,
                                      pageUrl: window.location.href,
                                    };
                                  } catch (error) {
                                    return {error: String(error)};
                                  }
                                }
                                """,
                                {"password": password_value, "deviceId": device_id},
                            )
                        except Exception as exc:
                            return {"error": str(exc)}

                    fetch_result = browser_fetch()
                    self._sync_playwright_cookies(context.cookies())
                    if isinstance(fetch_result, dict):
                        if fetch_result.get("error"):
                            self._log(f"password/verify 浏览器 fallback fetch 异常: {fetch_result['error']}")
                        else:
                            fetch_status = fetch_result.get("status")
                            fetch_text = str(fetch_result.get("text") or "")[:240]
                            fetch_flow = str(fetch_result.get("tokenFlow") or "").strip()
                            if fetch_flow:
                                self._log(
                                    "password/verify 浏览器 fallback fetch sentinel "
                                    f"flow={fetch_flow}"
                                )
                            self._log(
                                "password/verify 浏览器 fallback fetch -> "
                                f"status={fetch_status} url={str(fetch_result.get('pageUrl') or page.url)[:120]}"
                            )
                            if fetch_status == 200 and isinstance(fetch_result.get("data"), dict):
                                state = self._state_from_payload(
                                    fetch_result["data"],
                                    current_url=str(fetch_result.get("pageUrl") or page.url or request_url),
                                )
                                if not state.page_type:
                                    state = self._state_from_url(
                                        str(fetch_result.get("pageUrl") or page.url or request_url)
                                    )
                                Path(result_path).write_text(
                                    json.dumps(
                                        {
                                            "fetch_result": fetch_result,
                                            "final_state": {
                                                "page_type": state.page_type,
                                                "method": state.method,
                                                "current_url": state.current_url,
                                                "continue_url": state.continue_url,
                                            },
                                        },
                                        ensure_ascii=False,
                                        indent=2,
                                    ),
                                    encoding="utf-8",
                                )
                                self._log(
                                    "password/verify 浏览器 fallback 成功: "
                                    f"{describe_flow_state(state)} artifact={result_path}"
                                )
                                return state
                            if fetch_status and fetch_status != 200 and fetch_text:
                                self._log(
                                    "password/verify 浏览器 fallback fetch 未直接恢复: "
                                    f"{fetch_status} {fetch_text[:180]}"
                                )

                    try:
                        submit_result = page.evaluate(
                            """
                            (value) => {
                              const isVisible = (el) => {
                                if (!el) return false;
                                const style = window.getComputedStyle(el);
                                const rect = el.getBoundingClientRect();
                                return !!rect.width && !!rect.height && style.visibility !== 'hidden' && style.display !== 'none';
                              };
                              const textOf = (el) => String(el?.innerText || el?.textContent || el?.value || '').trim().toLowerCase();
                              const input = Array.from(document.querySelectorAll(
                                "input[type='password'], input[name='password'], input[autocomplete='current-password'], input[autocomplete='new-password']"
                              )).find((el) => isVisible(el) && !el.disabled);
                              if (!input) return {ok: false, reason: 'no_input'};
                              input.focus();
                              input.value = '';
                              input.dispatchEvent(new Event('input', {bubbles: true}));
                              input.value = String(value || '');
                              input.dispatchEvent(new Event('input', {bubbles: true}));
                              input.dispatchEvent(new Event('change', {bubbles: true}));
                              const form = input.closest('form');
                              const buttons = Array.from((form || document).querySelectorAll('button, input[type=\"submit\"], [role=\"button\"]'));
                              const submit = buttons.find((el) => {
                                if (!isVisible(el) || el.disabled) return false;
                                const label = textOf(el);
                                return ['continue', 'next', 'log in', 'login'].some((part) => label.includes(part));
                              });
                              if (form && typeof form.requestSubmit === 'function') {
                                form.requestSubmit();
                                return {ok: true, via: 'form_request_submit'};
                              }
                              if (submit) {
                                submit.click();
                                return {ok: true, via: 'button', label: textOf(submit)};
                              }
                              input.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true}));
                              input.dispatchEvent(new KeyboardEvent('keyup', {key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true}));
                              return {ok: true, via: 'enter_only'};
                            }
                            """,
                            password_value,
                        )
                    except Exception as exc:
                        self._log(f"password/verify 浏览器 fallback 页面提交流程异常: {exc}")
                        submit_result = {"ok": False, "error": str(exc)}

                    if (submit_result or {}).get("ok"):
                        self._log(
                            "password/verify 浏览器 fallback 页面提交 "
                            f"via={str((submit_result or {}).get('via') or '')}"
                        )
                        page.wait_for_timeout(3500)
                        self._sync_playwright_cookies(context.cookies())
                        state = self._state_from_url(str(page.url or request_url))
                        if state.page_type and not self._state_is_login_password(state):
                            self._log(
                                "password/verify 浏览器 fallback 页面提交流程成功: "
                                f"{describe_flow_state(state)}"
                            )
                            return state
                finally:
                    browser.close()
            return None

        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(run_browser).result(timeout=180)
        except FutureTimeoutError:
            self._log("password/verify 浏览器 fallback 超时")
            return None
        except Exception as exc:
            self._log(f"password/verify 浏览器 fallback 异常: {exc}")
            return None

    def _submit_passwordless_send_otp(
        self,
        email,
        device_id,
        *,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
        referer=None,
        retries=3,
    ):
        """优先走 passwordless OTP，适配 Outlook plus-alias existing-account 恢复。"""
        self._log("步骤3: POST /api/accounts/passwordless/send-otp")
        self.last_passwordless_send_otp_error_code = ""

        request_url = f"{self.oauth_issuer}/api/accounts/passwordless/send-otp"
        headers = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="application/json, text/plain, */*",
            referer=referer or f"{self.oauth_issuer}/log-in/password",
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={
                "oai-device-id": device_id,
            },
        )
        headers.update(generate_datadog_trace())

        last_status = None
        for attempt in range(1, max(1, int(retries or 1)) + 1):
            try:
                kwargs = {"headers": headers, "timeout": 30, "allow_redirects": False}
                if impersonate:
                    kwargs["impersonate"] = impersonate
                self._browser_pause()
                response = self.session.post(request_url, **kwargs)
                last_status = response.status_code
                self._log(f"/passwordless/send-otp -> {response.status_code} attempt={attempt}/{retries}")
                if response.status_code == 200:
                    self.last_passwordless_send_otp_error_code = ""
                    return self._state_from_url(f"{self.oauth_issuer}/email-verification")
                try:
                    error_data = response.json()
                except Exception:
                    error_data = {}
                error_code = str(((error_data or {}).get("error") or {}).get("code") or "").strip()
                self.last_passwordless_send_otp_error_code = error_code
                self._log(f"passwordless send-otp 失败: {response.text[:180]}")
                if response.status_code >= 500 and attempt < retries:
                    time.sleep(min(10, 2 * attempt))
                    continue
                return None
            except Exception as exc:
                self._log(f"passwordless send-otp 异常: {exc}")
                self.last_passwordless_send_otp_error_code = ""
                if attempt < retries:
                    time.sleep(min(10, 2 * attempt))
                    continue
                break

        self._log(f"passwordless send-otp 最终失败: status={last_status}")
        return None
    
    def _submit_about_you(self, first_name, last_name, birthdate, device_id, *, user_agent=None, sec_ch_ua=None, impersonate=None, referer=None):
        """在 OAuth 登录恢复流程中提交 about-you 资料。"""
        self._log("步骤4: POST /api/accounts/create_account")

        sentinel_token = self._mint_browser_sentinel_token(
            referer or f"{self.oauth_issuer}/about-you",
            "oauth_create_account",
            user_agent=user_agent,
        )
        if not sentinel_token:
            sentinel_token = build_sentinel_token(
                self.session,
                device_id,
                flow="oauth_create_account",
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                impersonate=impersonate,
            )
        request_url = f"{self.oauth_issuer}/api/accounts/create_account"
        headers = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="application/json",
            referer=referer or f"{self.oauth_issuer}/about-you",
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={"oai-device-id": device_id},
        )
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        headers.update(generate_datadog_trace())
        payload = {
            "name": f"{first_name} {last_name}".strip(),
            "birthdate": birthdate,
        }
        try:
            kwargs = {"json": payload, "headers": headers, "timeout": 30, "allow_redirects": False}
            if impersonate:
                kwargs["impersonate"] = impersonate
            self._browser_pause()
            r = self.session.post(request_url, **kwargs)
            self._log(f"/create_account -> {r.status_code}")
            if r.status_code != 200:
                lowered = (r.text or "").lower()
                if r.status_code in {400, 403}:
                    self._log(f"about_you 协议提交失败，尝试浏览器 fallback: {r.status_code}")
                    try:
                        with ThreadPoolExecutor(max_workers=1) as executor:
                            browser_result = executor.submit(
                                self._submit_about_you_browser_fallback,
                                first_name,
                                last_name,
                                birthdate,
                                referer=referer or f"{self.oauth_issuer}/about-you",
                                user_agent=user_agent,
                            ).result(timeout=180)
                    except FutureTimeoutError:
                        browser_result = {"ok": False, "error": "browser_fallback_timeout"}
                    except Exception as exc:
                        browser_result = {
                            "ok": False,
                            "error": "browser_fallback_exception",
                            "exception": repr(exc),
                        }
                    browser_error = browser_result.get("error") or ""
                    browser_status = browser_result.get("status")
                    browser_text = str(browser_result.get("text") or browser_result.get("body") or "")[:200]
                    browser_state = browser_result.get("state")
                    browser_tokens = browser_result.get("tokens")
                    if isinstance(browser_tokens, dict) and browser_tokens.get("access_token"):
                        self._log("oauth about_you browser fallback 已直接恢复 ChatGPT session tokens")
                        return browser_tokens
                    if browser_result.get("ok") and browser_state is not None:
                        self._log(f"oauth about_you browser fallback 成功 {describe_flow_state(browser_state)}")
                        return browser_state
                    if browser_error == "warning_banner_guest_session":
                        self._set_login_failure_reason(
                            self._about_you_browser_failure_reason(error=browser_error)
                        )
                        self._log(
                            "oauth about_you browser fallback 已确认落入 WARNING_BANNER guest session，"
                            "停止当前 app_X 恢复并交还上层 direct fallback"
                        )
                        return None
                    if browser_error in {"user_already_exists", "registration_disallowed", "invalid_auth_step"} and browser_state is not None:
                        self._log(f"oauth about_you browser fallback 命中 {browser_error}，继续 existing-account 分支")
                        return browser_state
                    if browser_status:
                        self._set_login_failure_reason(
                            self._about_you_browser_failure_reason(status=browser_status)
                        )
                        self._log(f"oauth about_you browser fallback 失败: {browser_status} - {browser_text}")
                    elif browser_error:
                        self._set_login_failure_reason(
                            self._about_you_browser_failure_reason(error=browser_error)
                        )
                        detail = browser_result.get("exception") or browser_result.get("page_url") or ""
                        suffix = f" ({detail})" if detail else ""
                        self._log(f"oauth about_you browser fallback 失败: {browser_error}{suffix}")
                if r.status_code == 400 and any(marker in lowered for marker in ("already_exists", "already exists", "user_already_exists")):
                    self._set_login_failure_reason(
                        self._about_you_protocol_failure_reason(
                            status=r.status_code,
                            lowered_text=lowered,
                        )
                    )
                    self._log("about_you 提示 already_exists，浏览器 fallback 未恢复 session，最后回退 existing-account 分支")
                    return self._chatgpt_login_with_state()
                if r.status_code == 400 and "registration_disallowed" in lowered:
                    self._set_login_failure_reason(
                        self._about_you_protocol_failure_reason(
                            status=r.status_code,
                            lowered_text=lowered,
                        )
                    )
                    self._log("about_you 命中 registration_disallowed，浏览器 fallback 未恢复 session，最后回退 existing-account 分支")
                    return self._chatgpt_login_with_state()
                self._set_login_failure_reason(
                    self._about_you_protocol_failure_reason(
                        status=r.status_code,
                        lowered_text=lowered,
                    )
                )
                self._log(f"about_you 提交失败: {r.text[:180]}")
                return None
            data = r.json()
            state = self._state_from_payload(data, current_url=str(r.url) or request_url)
            self._log(f"about_you -> {describe_flow_state(state)}")
            return state
        except Exception as e:
            self._log(f"about_you 提交异常: {e}")
            return None

    def login_and_get_tokens(self, email, password, device_id, user_agent=None, sec_ch_ua=None, impersonate=None, skymail_client=None, profile=None):
        """
        完整的 OAuth 登录流程，获取 tokens
        
        Args:
            email: 邮箱
            password: 密码
            device_id: 设备 ID
            user_agent: User-Agent
            sec_ch_ua: sec-ch-ua header
            impersonate: curl_cffi impersonate 参数
            skymail_client: Skymail 客户端（用于获取 OTP，如果需要）
            profile: 可选的资料字典，包含 first_name/last_name/birthdate，用于恢复到 about_you 时补完资料
            
        Returns:
            dict: tokens 字典，包含 access_token, refresh_token, id_token
        """
        self.current_email = email or getattr(self, "current_email", "")
        self.current_password = password or getattr(self, "current_password", "")
        self.current_device_id = device_id or getattr(self, "current_device_id", "")
        self.current_profile = dict(profile or getattr(self, "current_profile", {}) or {})
        self.current_skymail_client = skymail_client or getattr(self, "current_skymail_client", None)
        self.password_verify_led_to_email_otp = False
        self.last_login_failure_reason = ""
        self.last_flow_state_description = ""
        self.existing_account_guest_session_loop_count = 0
        self._log("开始 OAuth 登录流程...")

        code_verifier, code_challenge = generate_pkce()
        oauth_state = secrets.token_urlsafe(32)
        chatgpt_web_client = self._is_chatgpt_web_client()
        authorize_params = {
            "response_type": "code",
            "client_id": self.oauth_client_id,
            "redirect_uri": self.oauth_redirect_uri,
            "scope": self.oauth_scope,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": oauth_state,
        }
        if self.oauth_prompt not in (None, ""):
            authorize_params["prompt"] = str(self.oauth_prompt)
        if self.oauth_audience:
            authorize_params["audience"] = self.oauth_audience
        if isinstance(self.oauth_extra_authorize_params, dict):
            for key, value in self.oauth_extra_authorize_params.items():
                if value is not None:
                    authorize_params[str(key)] = value
        authorize_url = f"{self.oauth_issuer}/oauth/authorize"
        self.current_chatgpt_authorize_url = f"{authorize_url}?{urlencode(authorize_params)}"

        self._seed_chatgpt_web_cookies_from_seed()
        seed_oai_device_cookie(self.session, device_id)

        self._log("步骤1: Bootstrap OAuth session...")
        authorize_final_url = self._bootstrap_oauth_session(
            authorize_url,
            authorize_params,
            device_id=device_id,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            impersonate=impersonate,
        )
        if not authorize_final_url:
            self._log("Bootstrap 失败")
            self._set_login_failure_reason("bootstrap_failed")
            return None
        if any(
            marker in str(authorize_final_url or "").lower()
            for marker in ("/api/accounts/authorize", "/oauth/authorize", "/api/oauth/oauth2/auth")
        ):
            self.current_chatgpt_authorize_url = str(authorize_final_url or "").strip()

        continue_referer = (
            authorize_final_url
            if authorize_final_url.startswith(self.oauth_issuer)
            else f"{self.oauth_issuer}/log-in"
        )

        state = self._submit_authorize_continue(
            email,
            device_id,
            continue_referer,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            impersonate=impersonate,
            authorize_url=authorize_url,
            authorize_params=authorize_params,
        )
        if not state:
            self._set_login_failure_reason("authorize_continue_failed")
            return None

        self._log(f"OAuth 状态起点: {describe_flow_state(state)}")
        self._remember_flow_state(state)
        seen_states = {}
        authorize_reentry_used = 0
        referer = continue_referer

        for step in range(20):
            self._remember_flow_state(state)
            current_target = str(state.continue_url or state.current_url or "").strip()
            if any(
                marker in current_target.lower()
                for marker in ("/api/accounts/authorize", "/oauth/authorize", "/api/oauth/oauth2/auth")
            ):
                self.current_chatgpt_authorize_url = current_target
            signature = self._state_signature(state)
            seen_states[signature] = seen_states.get(signature, 0) + 1
            if seen_states[signature] > 2:
                self._log(f"OAuth 状态重复过多，尝试 direct authorize re-entry: {describe_flow_state(state)}")
                direct_tokens = self._try_direct_authorize_reentry(
                    authorize_url,
                    authorize_params,
                    code_verifier,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                )
                if direct_tokens:
                    self._log("✅ 通过 direct authorize re-entry 恢复 token")
                    return direct_tokens
                resume_target = (
                    str(getattr(self, "last_direct_authorize_login_challenge_url", "") or "").strip()
                    or str(getattr(self, "last_direct_authorize_final_url", "") or "").strip()
                )
                if resume_target.startswith(self.oauth_issuer):
                    self._log(
                        "direct authorize re-entry 已落到 auth.openai.com，"
                        "切换到新状态继续协议状态机"
                    )
                    referer = state.current_url or state.continue_url or referer
                    state = self._state_from_url(resume_target)
                    seen_states = {}
                    continue
                self._log(f"OAuth 状态卡住: {describe_flow_state(state)}")
                self._set_login_failure_reason(
                    self._terminal_flow_failure_reason(
                        "state_stuck",
                        describe_flow_state(state),
                    ),
                    overwrite=False,
                )
                return None

            callback_tokens = self._try_chatgpt_callback_session_from_state(
                state,
                user_agent=user_agent,
                impersonate=impersonate,
                referer=referer,
                code_verifier=code_verifier,
                prefer_token_exchange=chatgpt_web_client,
            )
            if callback_tokens:
                self._log("✅ 通过 callback/openai + /api/auth/session 恢复 token")
                return callback_tokens

            code = self._extract_code_from_state(state)
            if code:
                self._log(f"获取到 authorization code: {code[:20]}...")
                self._log("步骤7: POST /oauth/token")
                tokens = self._exchange_code_for_tokens(code, code_verifier, user_agent, impersonate)
                if tokens:
                    self._log("✅ OAuth 登录成功")
                else:
                    self._log("换取 tokens 失败")
                return tokens

            if self._state_is_login_password(state):
                next_state = None
                if password:
                    self._log("检测到 login_password，优先尝试旧密码验证")
                    next_state = self._submit_password_verify(
                        password,
                        device_id,
                        user_agent=user_agent,
                        sec_ch_ua=sec_ch_ua,
                        impersonate=impersonate,
                        referer=state.current_url or state.continue_url or referer,
                    )
                if not next_state and skymail_client:
                    self._log("旧密码验证不可用，回退到 passwordless OTP")
                    next_state = self._submit_passwordless_send_otp(
                        email,
                        device_id,
                        user_agent=user_agent,
                        sec_ch_ua=sec_ch_ua,
                        impersonate=impersonate,
                        referer=state.current_url or state.continue_url or referer,
                    )
                if not next_state:
                    self._set_login_failure_reason(
                        self._terminal_flow_failure_reason("login_password_no_next_state"),
                        overwrite=False,
                    )
                    return None
                referer = state.current_url or referer
                state = next_state
                continue

            if self._state_is_email_otp(state):
                next_state = None
                challenge_url = str(getattr(self, "last_direct_authorize_login_challenge_url", "") or "").strip()
                prefer_email_otp_first = bool(getattr(self, "prefer_email_otp_first", False))
                force_email_otp_after_password = bool(
                    getattr(self, "password_verify_led_to_email_otp", False)
                )
                if (
                    prefer_email_otp_first
                    and bool(getattr(self, "reuse_existing_email_code_once", False))
                    and skymail_client
                ):
                    used_codes = set(getattr(skymail_client, "_used_codes", set()) or set())
                    if used_codes:
                        self._log(
                            "existing-account 恢复链允许复用最近邮箱验证码一次，"
                            f"先清空已用集合: {sorted(used_codes)}"
                        )
                        skymail_client._used_codes = set()
                    if hasattr(skymail_client, "_baseline_id"):
                        old_baseline = str(getattr(skymail_client, "_baseline_id", "") or "")
                        setattr(skymail_client, "_baseline_id", "")
                        if old_baseline:
                            self._log(
                                "existing-account 恢复链允许回看最新邮箱验证码，"
                                f"清空 baseline_id: {old_baseline}"
                            )
                    elif hasattr(skymail_client, "baseline"):
                        old_baseline = str(getattr(skymail_client, "baseline", "") or "")
                        setattr(skymail_client, "baseline", "0")
                        if old_baseline:
                            self._log(
                                "existing-account 恢复链允许回看最新邮箱验证码，"
                                f"清空 baseline: {old_baseline}"
                            )
                    self.ignore_otp_sent_at_once = True
                    self._log("existing-account 恢复链本轮忽略 otp_sent_at 锚点，允许回看最近验证码")
                    self.reuse_existing_email_code_once = False
                if prefer_email_otp_first and skymail_client:
                    self._log(
                        "检测到 email_otp_verification，当前是 existing-account 恢复链，"
                        "优先尝试真实邮箱 OTP"
                    )
                    next_state = self._handle_otp_verification(
                        email,
                        device_id,
                        user_agent,
                        sec_ch_ua,
                        impersonate,
                        skymail_client,
                        state,
                    )
                if not next_state and force_email_otp_after_password and skymail_client:
                    self._log(
                        "检测到上一跳 password_verify 已触发邮箱 OTP，"
                        "跳过再次验密码，先等待真实邮箱 OTP"
                    )
                    next_state = self._handle_otp_verification(
                        email,
                        device_id,
                        user_agent,
                        sec_ch_ua,
                        impersonate,
                        skymail_client,
                        state,
                    )
                if not next_state and challenge_url and skymail_client:
                    self._log(
                        "检测到 email_otp_verification 且存在 login_challenge，优先尝试真实邮箱 OTP，"
                        "避免旧密码把流程再次送回 about_you"
                    )
                    next_state = self._handle_otp_verification(
                        email,
                        device_id,
                        user_agent,
                        sec_ch_ua,
                        impersonate,
                        skymail_client,
                        state,
                    )
                if not next_state and password and not force_email_otp_after_password:
                    self._log("检测到 email_otp_verification，尝试旧密码验证")
                    next_state = self._submit_password_verify(
                        password,
                        device_id,
                        user_agent=user_agent,
                        sec_ch_ua=sec_ch_ua,
                        impersonate=impersonate,
                        referer=state.current_url or state.continue_url or referer,
                    )
                if not next_state and skymail_client:
                    self._log("旧密码验证未恢复，回退到邮箱 OTP")
                    next_state = self._handle_otp_verification(
                        email,
                        device_id,
                        user_agent,
                        sec_ch_ua,
                        impersonate,
                        skymail_client,
                        state,
                    )
                if not next_state and not chatgpt_web_client:
                    self._log(
                        "邮箱 OTP/重发链未恢复 Codex localhost OAuth，"
                        "尝试 direct authorize re-entry"
                    )
                    direct_tokens = self._try_direct_authorize_reentry(
                        authorize_url,
                        authorize_params,
                        code_verifier,
                        user_agent=user_agent,
                        sec_ch_ua=sec_ch_ua,
                        impersonate=impersonate,
                    )
                    if direct_tokens:
                        self._log("✅ email_otp 失败后 direct authorize re-entry 恢复 token")
                        return direct_tokens
                    resume_target = str(
                        getattr(self, "last_direct_authorize_final_url", "") or ""
                    ).strip()
                    if (
                        not resume_target.startswith(self.oauth_issuer)
                        and challenge_url.startswith(self.oauth_issuer)
                    ):
                        resume_target = challenge_url
                    if resume_target.startswith(self.oauth_issuer) and not bool(
                        getattr(self, "email_otp_direct_authorize_resume_once", False)
                    ):
                        self.email_otp_direct_authorize_resume_once = True
                        self._log(
                            "email_otp 后 direct authorize re-entry 已落到 auth.openai.com，"
                            "继续协议状态机"
                        )
                        next_state = self._state_from_url(resume_target)
                if not next_state:
                    self._log("当前流程需要邮箱 OTP/密码恢复，但没有可用结果")
                    return None
                if not next_state:
                    return None
                if isinstance(next_state, dict) and next_state.get("access_token"):
                    return next_state
                referer = state.current_url or referer
                state = next_state
                continue

            if (state.page_type or "") in {
                "log_in",
                "log_in_or_create_account",
                "log_in_or_sign_up",
            }:
                challenge_url = str(getattr(self, "last_direct_authorize_login_challenge_url", "") or "").strip()
                if challenge_url:
                    self._log(f"检测到 log_in，当前保留 login_challenge={challenge_url[:180]}")
                self._log(f"检测到 {(state.page_type or 'log_in')}，重新提交 authorize/continue")
                next_state = self._submit_authorize_continue(
                    email,
                    device_id,
                    state.current_url or referer or f"{self.oauth_issuer}/log-in",
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                    authorize_url=authorize_url,
                    authorize_params=authorize_params,
                )
                if not next_state:
                    return None
                referer = state.current_url or referer
                state = next_state
                continue

            if self._state_supports_workspace_resolution(state):
                code, next_state = self._resolve_consent_state(
                    state,
                    referer=referer,
                    device_id=device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                )
                if code:
                    self._log(f"获取到 authorization code: {code[:20]}...")
                    self._log("步骤7: POST /oauth/token")
                    tokens = self._exchange_code_for_tokens(code, code_verifier, user_agent, impersonate)
                    if tokens:
                        self._log("✅ OAuth 登录成功")
                    else:
                        self._log("换取 tokens 失败")
                    return tokens
                if next_state:
                    if next_state.page_type == "consent":
                        self._log("consent 缺少 workspace，先尝试 direct authorize re-entry")
                        direct_tokens = self._try_direct_authorize_reentry(
                            authorize_url,
                            authorize_params,
                            code_verifier,
                            user_agent=user_agent,
                            sec_ch_ua=sec_ch_ua,
                            impersonate=impersonate,
                        )
                        if direct_tokens:
                            self._log("✅ 通过 direct authorize re-entry 恢复 token")
                            return direct_tokens
                        self._log("consent 缺少 workspace，尝试浏览器直落 ChatGPT session")
                        browser_tokens = self._browser_hydrate_chatgpt_session(
                            consent_url=next_state.current_url or next_state.continue_url or f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent",
                            user_agent=user_agent,
                        )
                        if browser_tokens:
                            done, browser_result, referer = self._resume_after_browser_bridge(
                                browser_tokens,
                                authorize_url=authorize_url,
                                authorize_params=authorize_params,
                                code_verifier=code_verifier,
                                state=state,
                                referer=referer,
                                user_agent=user_agent,
                                sec_ch_ua=sec_ch_ua,
                                impersonate=impersonate,
                                reason="consent 缺少 workspace 的浏览器 ChatGPT bridge",
                            )
                            if done:
                                return browser_result
                            if browser_result is not None:
                                state = browser_result
                                continue
                    referer = state.current_url or referer
                    state = next_state
                    self._log(f"workspace state -> {describe_flow_state(state)}")
                    continue

            if self._state_is_about_you(state):
                reentry_target = str(getattr(self, "current_chatgpt_authorize_url", "") or "").strip()
                existing_account_about_you_recovery = bool(
                    getattr(self, "prefer_email_otp_first", False)
                )
                if existing_account_about_you_recovery:
                    self._log(
                        "OAuth 主流程命中 about_you，当前属于 existing-account 恢复链，"
                        "直接提交 create_account/browser fallback，避免额外 email_otp 循环"
                    )
                if bool(getattr(self, "direct_authorize_before_about_you_once", False)):
                    self.direct_authorize_before_about_you_once = False
                    self._log(
                        "existing-account 恢复链的 about_you 先尝试 direct authorize re-entry，"
                        "避免再次死在 create_account/already_exists"
                    )
                    direct_tokens = self._try_direct_authorize_reentry(
                        authorize_url,
                        authorize_params,
                        code_verifier,
                        user_agent=user_agent,
                        sec_ch_ua=sec_ch_ua,
                        impersonate=impersonate,
                    )
                    if direct_tokens:
                        self._log("✅ about_you 前置 direct authorize re-entry 恢复 token 成功")
                        return direct_tokens
                    bridge_target = (
                        str(getattr(self, "last_direct_authorize_login_challenge_url", "") or "").strip()
                        or str(getattr(self, "last_direct_authorize_final_url", "") or "").strip()
                        or "https://chatgpt.com/auth/login_with"
                    )
                    self._log(
                        "about_you 前置 direct authorize re-entry 未直接恢复 token，"
                        "改走浏览器 ChatGPT bridge"
                    )
                    browser_tokens = self._browser_hydrate_chatgpt_session(
                        consent_url=bridge_target,
                        user_agent=user_agent,
                    )
                    if browser_tokens:
                        done, browser_result, referer = self._resume_after_browser_bridge(
                            browser_tokens,
                            authorize_url=authorize_url,
                            authorize_params=authorize_params,
                            code_verifier=code_verifier,
                            state=state,
                            referer=referer,
                            user_agent=user_agent,
                            sec_ch_ua=sec_ch_ua,
                            impersonate=impersonate,
                            reason="about_you 前置 direct authorize + 浏览器 bridge",
                        )
                        if done:
                            return browser_result
                        if browser_result is not None:
                            state = browser_result
                            continue
                    challenge_url = str(getattr(self, "last_direct_authorize_login_challenge_url", "") or "").strip()
                    if challenge_url:
                        failure_reason = str(getattr(self, "last_login_failure_reason", "") or "").strip().lower()
                        if (
                            existing_account_about_you_recovery
                            and "warning_banner_guest_session" in failure_reason
                        ):
                            self.existing_account_guest_session_loop_count += 1
                            self._log(
                                "existing-account 恢复链命中 WARNING_BANNER guest session 循环 "
                                f"{self.existing_account_guest_session_loop_count}/2"
                            )
                            if self.existing_account_guest_session_loop_count >= 2:
                                self._set_login_failure_reason(
                                    "existing_account_guest_session_loop"
                                )
                                self._log(
                                    "existing-account 恢复链已连续两次回到 WARNING_BANNER guest session，"
                                    "停止继续空转"
                                )
                                return None
                        self._log(
                            "about_you 前置 direct authorize + 浏览器 bridge 均未恢复 token，"
                            "当前会话已转入 login_challenge，继续 existing-account 状态机"
                        )
                        referer = state.current_url or state.continue_url or referer
                        state = self._state_from_url(challenge_url)
                        continue
                if not profile or not profile.get("birthdate"):
                    self._log("当前流程需要 about_you 资料，但调用方未提供 profile")
                    self._set_login_failure_reason("about_you_missing_profile")
                    return None
                next_state = self._submit_about_you(
                    profile.get("first_name", ""),
                    profile.get("last_name", ""),
                    profile.get("birthdate", ""),
                    device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                    referer=state.current_url or state.continue_url or referer,
                )
                if not next_state:
                    self._set_login_failure_reason(
                        "about_you_submit_failed",
                        overwrite=False,
                    )
                    return None
                if isinstance(next_state, dict) and next_state.get("access_token"):
                    self._log("✅ about_you 分支已直接恢复 ChatGPT session/token")
                    return next_state
                reentry_target = str(getattr(self, "current_chatgpt_authorize_url", "") or "").strip()
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
                    self._log(
                        "about_you 后落到 ChatGPT auth_login_with/auth_error，"
                        "回放原始 authorize URL"
                    )
                    referer = state.current_url or state.continue_url or referer
                    state = self._state_from_url(reentry_target)
                    continue
                referer = state.current_url or referer
                state = next_state
                continue

            if self._state_is_add_phone(state):
                self._log(
                    "检测到 add_phone，当前更像登录后补充资料页而不是 OAuth 终点，"
                    "先尝试跟随 add_phone 自身导航"
                )
                code, next_state = self._follow_flow_state(
                    state,
                    referer=referer,
                    user_agent=user_agent,
                    impersonate=impersonate,
                )
                if code:
                    self._log(f"add_phone 跟随后获取到 authorization code: {code[:20]}...")
                    self._log("步骤7: POST /oauth/token")
                    tokens = self._exchange_code_for_tokens(code, code_verifier, user_agent, impersonate)
                    if tokens:
                        self._log("✅ add_phone 跟随后 OAuth 登录成功")
                    else:
                        self._log("add_phone 跟随后换取 tokens 失败")
                    return tokens
                if next_state and self._state_signature(next_state) != self._state_signature(state):
                    self._log(f"add_phone follow -> {describe_flow_state(next_state)}")
                    if (
                        self._state_is_about_you(next_state)
                        and bool(getattr(self, "prefer_email_otp_first", False))
                    ):
                        self.direct_authorize_before_about_you_once = True
                        self._log(
                            "add_phone follow 命中 about_you，"
                            "下一次 about_you 先尝试 direct authorize re-entry"
                        )
                    referer = state.current_url or state.continue_url or referer
                    state = next_state
                    continue

                if bool(getattr(self, "prefer_email_otp_first", False)):
                    self._log(
                        "add_phone 在当前 existing-account 恢复链上是硬门："
                        "当前前端 route 只暴露 /api/accounts/add-phone/send + Continue CTA，"
                        "没有可复用的 skip path；在未提供手机号能力时直接判为 blocker"
                    )
                    self._set_login_failure_reason("existing_account_add_phone_required")
                    return None

                self._log("add_phone 跟随后仍未脱离当前分支，先探测 /about-you")
                _, about_you_state = self._follow_flow_state(
                    self._state_from_url(f"{self.oauth_issuer}/about-you"),
                    referer=state.current_url or state.continue_url or referer,
                    user_agent=user_agent,
                    impersonate=impersonate,
                    max_hops=6,
                )
                if (
                    about_you_state
                    and self._state_signature(about_you_state) != self._state_signature(state)
                ):
                    self._log(f"add_phone about_you probe -> {describe_flow_state(about_you_state)}")
                    if bool(getattr(self, "prefer_email_otp_first", False)):
                        self.direct_authorize_before_about_you_once = True
                        self._log(
                            "add_phone about_you probe 命中 existing-account 恢复链，"
                            "下一次 about_you 先尝试 direct authorize re-entry"
                        )
                    referer = state.current_url or state.continue_url or referer
                    state = about_you_state
                    continue

                self._log("add_phone 跟随后仍未脱离当前分支，改试 direct authorize re-entry")
                direct_tokens = self._try_direct_authorize_reentry(
                    authorize_url,
                    authorize_params,
                    code_verifier,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                )
                if direct_tokens:
                    self._log("✅ add_phone 后通过 direct authorize re-entry 恢复 token")
                    return direct_tokens

                resume_target = (
                    str(getattr(self, "last_direct_authorize_login_challenge_url", "") or "").strip()
                    or str(getattr(self, "last_direct_authorize_final_url", "") or "").strip()
                )
                if resume_target.startswith(self.oauth_issuer):
                    self._log(
                        "add_phone 后 direct authorize re-entry 已回到 auth.openai.com，"
                        "切换到新状态继续协议状态机"
                    )
                    referer = state.current_url or state.continue_url or referer
                    state = self._state_from_url(resume_target)
                    continue

                reentry_target = str(getattr(self, "current_chatgpt_authorize_url", "") or "").strip()
                if reentry_target and authorize_reentry_used < 2:
                    authorize_reentry_used += 1
                    self._log("add_phone 后回放原始 authorize URL 再试一次")
                    referer = state.current_url or state.continue_url or referer
                    state = self._state_from_url(reentry_target)
                    continue

                self._log(f"add_phone 仍未恢复 token: {describe_flow_state(state)}")
                return None

            target = current_target
            lowered_target = target.lower()
            if self._state_is_chatgpt_auth_error(state):
                reentry_target = str(getattr(self, "current_chatgpt_authorize_url", "") or "").strip()
                if reentry_target:
                    self._log("检测到 ChatGPT auth callback/error，优先回放原始 authorize URL")
                    referer = state.current_url or state.continue_url or referer
                    state = self._state_from_url(reentry_target)
                    continue
                self._log("检测到 ChatGPT auth callback/error，先尝试 direct authorize re-entry")
                direct_tokens = self._try_direct_authorize_reentry(
                    authorize_url,
                    authorize_params,
                    code_verifier,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                )
                if direct_tokens:
                    self._log("✅ 通过 ChatGPT auth callback/error direct authorize re-entry 恢复 token")
                    return direct_tokens
                resume_target = str(getattr(self, "last_direct_authorize_final_url", "") or "").strip()
                if resume_target.startswith(self.oauth_issuer):
                    self._log("direct authorize re-entry 已落到 auth.openai.com，继续协议状态机")
                    referer = state.current_url or state.continue_url or referer
                    state = self._state_from_url(resume_target)
                    continue
                self._log("direct authorize re-entry 未恢复 token，最后回退浏览器 next-auth bridge")
                browser_tokens = self._browser_hydrate_chatgpt_session(
                    consent_url=target or "https://chatgpt.com/auth/login_with",
                    user_agent=user_agent,
                )
                if browser_tokens:
                    done, browser_result, referer = self._resume_after_browser_bridge(
                        browser_tokens,
                        authorize_url=authorize_url,
                        authorize_params=authorize_params,
                        code_verifier=code_verifier,
                        state=state,
                        referer=referer,
                        user_agent=user_agent,
                        sec_ch_ua=sec_ch_ua,
                        impersonate=impersonate,
                        reason="auth_callback_error 浏览器 bridge",
                    )
                    if done:
                        return browser_result
                    if browser_result is not None:
                        state = browser_result
                        continue
                self._log("ChatGPT auth callback/error 浏览器 bridge 未恢复 token")
                return None

            if self._state_requires_navigation(state):
                code, next_state = self._follow_flow_state(
                    state,
                    referer=referer,
                    user_agent=user_agent,
                    impersonate=impersonate,
                )
                if code:
                    self._log(f"获取到 authorization code: {code[:20]}...")
                    self._log("步骤7: POST /oauth/token")
                    tokens = self._exchange_code_for_tokens(code, code_verifier, user_agent, impersonate)
                    if tokens:
                        self._log("✅ OAuth 登录成功")
                    else:
                        self._log("换取 tokens 失败")
                    return tokens
                referer = state.current_url or referer
                state = next_state
                self._log(f"follow state -> {describe_flow_state(state)}")
                continue

            self._log(f"未支持的 OAuth 状态: {describe_flow_state(state)}")
            return None

            self._log("OAuth 状态机超出最大步数")
            self._set_login_failure_reason(
                self._terminal_flow_failure_reason(
                    "oauth_state_machine_exceeded_max_steps",
                    self.last_flow_state_description,
                ),
                overwrite=False,
            )
            return None
    
    def _extract_code_from_url(self, url):
        """从 URL 中提取 code"""
        if not url or "code=" not in url:
            return None
        if self._extract_chatgpt_callback_url(url):
            return None
        try:
            return parse_qs(urlparse(url).query).get("code", [None])[0]
        except Exception:
            return None
    
    def _oauth_follow_for_code(self, start_url, referer, user_agent, impersonate, max_hops=16):
        """跟随 URL 获取 authorization code（手动跟随重定向）"""
        code, next_state = self._follow_flow_state(
            self._state_from_url(start_url),
            referer=referer,
            user_agent=user_agent,
            impersonate=impersonate,
            max_hops=max_hops,
        )
        return code, (next_state.current_url or next_state.continue_url or start_url)

    def _resolve_consent_state(
        self,
        state,
        *,
        referer,
        device_id,
        user_agent,
        sec_ch_ua,
        impersonate,
    ):
        """对齐成熟实现：先 follow consent/continue 提 code，再做 workspace/org，最后回退固定 consent。"""
        del sec_ch_ua  # 当前分支未单独使用；保留签名与调用方一致，避免后续再改接口。

        chatgpt_web_client = self._is_chatgpt_web_client()
        default_consent = (
            state.continue_url
            or state.current_url
            or (
                "https://chatgpt.com/auth/login_with"
                if chatgpt_web_client
                else f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
            )
        )
        consent_url = normalize_flow_url(default_consent, auth_base=self.oauth_issuer)
        fallback_consent = "" if chatgpt_web_client else f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
        follow_referer = referer or f"{self.oauth_issuer}/log-in/password"

        direct_code = self._extract_code_from_url(consent_url)
        if direct_code:
            return direct_code, self._state_from_url(consent_url)

        self._log("步骤5: 跟随 consent/continue 尝试提取 code")
        code, next_url = self._oauth_follow_for_code(
            consent_url,
            follow_referer,
            user_agent,
            impersonate,
        )
        if code:
            return code, self._state_from_url(next_url)

        next_state = self._state_from_url(next_url or consent_url)
        if (not chatgpt_web_client) and self._state_supports_workspace_resolution(next_state):
            self._log("步骤6: 执行 workspace/org 选择")
            code, resolved_state = self._oauth_submit_workspace_and_org(
                next_state.continue_url or next_state.current_url or consent_url,
                device_id,
                user_agent,
                impersonate,
            )
            if code:
                return code, resolved_state
            if resolved_state:
                next_state = resolved_state

        if fallback_consent and consent_url != fallback_consent:
            self._log("步骤6: 回退固定 consent 路径重试")
            code, resolved_state = self._oauth_submit_workspace_and_org(
                fallback_consent,
                device_id,
                user_agent,
                impersonate,
            )
            if code:
                return code, resolved_state
            if resolved_state:
                next_state = resolved_state

            code, fallback_next_url = self._oauth_follow_for_code(
                fallback_consent,
                follow_referer,
                user_agent,
                impersonate,
            )
            if code:
                return code, self._state_from_url(fallback_next_url)
            if fallback_next_url:
                next_state = self._state_from_url(fallback_next_url)

        return None, next_state

    def _oauth_submit_workspace_and_org(self, consent_url, device_id, user_agent, impersonate, max_retries=3):
        """提交 workspace 和 organization 选择（带重试）"""
        session_data = None

        for attempt in range(max_retries):
            session_data = self._load_workspace_session_data(
                consent_url=consent_url,
                user_agent=user_agent,
                impersonate=impersonate,
            )
            if session_data:
                break

            if attempt < max_retries - 1:
                self._log(f"无法获取 consent session 数据 (尝试 {attempt + 1}/{max_retries})")
                time.sleep(0.3)
            else:
                self._log("无法获取 consent session 数据")
                return None, None

        workspaces = session_data.get("workspaces", [])
        if not workspaces:
            self._log("session 中没有 workspace 信息")
            return None, None
        
        workspace_id = (workspaces[0] or {}).get("id")
        if not workspace_id:
            self._log("workspace_id 为空")
            return None, None
        
        self._log(f"选择 workspace: {workspace_id}")
        
        headers = self._headers(
            f"{self.oauth_issuer}/api/accounts/workspace/select",
            user_agent=user_agent,
            accept="application/json",
            referer=consent_url,
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={
                "oai-device-id": device_id,
            },
        )
        headers.update(generate_datadog_trace())
        
        try:
            kwargs = {
                "json": {"workspace_id": workspace_id},
                "headers": headers,
                "allow_redirects": False,
                "timeout": 30
            }
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r = self.session.post(
                f"{self.oauth_issuer}/api/accounts/workspace/select",
                    **kwargs
            )
            
            self._log(f"workspace/select -> {r.status_code}")
            if r.status_code != 200:
                try:
                    self._log(
                        "workspace/select 非 200 body: "
                        f"{str(r.text or '')[:240]}"
                    )
                except Exception:
                    pass
                lowered_body = ""
                try:
                    lowered_body = json.dumps(r.json(), ensure_ascii=False).lower()
                except Exception:
                    lowered_body = str(r.text or "").lower()
                if (
                    r.status_code in (400, 409)
                    and any(marker in lowered_body for marker in ("invalid_state", "invalid_auth_step"))
                ):
                    login_state = self._state_from_login_session_cookie()
                    if login_state:
                        self._log(
                            "workspace/select 命中 invalid_state/invalid_auth_step，"
                            f"改按 login_session challenge 恢复 -> {describe_flow_state(login_state)}"
                        )
                        return None, login_state
            
            # 检查重定向
            if r.status_code in (301, 302, 303, 307, 308):
                location = normalize_flow_url(r.headers.get("Location", ""), auth_base=self.oauth_issuer)
                if "code=" in location:
                    code = self._extract_code_from_url(location)
                    if code:
                        self._log("从 workspace/select 重定向获取到 code")
                        return code, self._state_from_url(location)
                if location:
                    return None, self._state_from_url(location)
            
            # 如果返回 200，检查响应中的 orgs
            if r.status_code == 200:
                try:
                    data = r.json()
                    orgs = data.get("data", {}).get("orgs", [])
                    workspace_state = self._state_from_payload(data, current_url=str(r.url))
                    continue_url = workspace_state.continue_url
                    
                    if orgs:
                        org_id = (orgs[0] or {}).get("id")
                        projects = (orgs[0] or {}).get("projects", [])
                        project_id = (projects[0] or {}).get("id") if projects else None
                        
                        if org_id:
                            self._log(f"选择 organization: {org_id}")
                            
                            org_body = {"org_id": org_id}
                            if project_id:
                                org_body["project_id"] = project_id
                            
                            org_referer = continue_url if continue_url and continue_url.startswith("http") else consent_url
                            headers = self._headers(
                                f"{self.oauth_issuer}/api/accounts/organization/select",
                                user_agent=user_agent,
                                accept="application/json",
                                referer=org_referer,
                                origin=self.oauth_issuer,
                                content_type="application/json",
                                fetch_site="same-origin",
                                extra_headers={
                                    "oai-device-id": device_id,
                                },
                            )
                            headers.update(generate_datadog_trace())
                            
                            kwargs = {
                                "json": org_body,
                                "headers": headers,
                                "allow_redirects": False,
                                "timeout": 30
                            }
                            if impersonate:
                                kwargs["impersonate"] = impersonate

                            self._browser_pause()
                            r_org = self.session.post(
                                f"{self.oauth_issuer}/api/accounts/organization/select",
                                **kwargs
                            )
                            
                            self._log(f"organization/select -> {r_org.status_code}")
                            if r_org.status_code != 200:
                                try:
                                    self._log(
                                        "organization/select 非 200 body: "
                                        f"{str(r_org.text or '')[:240]}"
                                    )
                                except Exception:
                                    pass
                            
                            # 检查重定向
                            if r_org.status_code in (301, 302, 303, 307, 308):
                                location = normalize_flow_url(r_org.headers.get("Location", ""), auth_base=self.oauth_issuer)
                                if "code=" in location:
                                    code = self._extract_code_from_url(location)
                                    if code:
                                        self._log("从 organization/select 重定向获取到 code")
                                        return code, self._state_from_url(location)
                                if location:
                                    return None, self._state_from_url(location)
                            
                            # 检查 continue_url
                            if r_org.status_code == 200:
                                try:
                                    org_state = self._state_from_payload(r_org.json(), current_url=str(r_org.url))
                                    self._log(f"organization/select -> {describe_flow_state(org_state)}")
                                    if self._extract_code_from_state(org_state):
                                        return self._extract_code_from_state(org_state), org_state
                                    return None, org_state
                                except Exception as e:
                                    self._log(f"解析 organization/select 响应异常: {e}")
                    
                    # 如果有 continue_url，跟随它
                    if continue_url:
                        code, _ = self._oauth_follow_for_code(continue_url, consent_url, user_agent, impersonate)
                        if code:
                            return code, self._state_from_url(continue_url)
                    return None, workspace_state
                        
                except Exception as e:
                    self._log(f"处理 workspace/select 响应异常: {e}")
        
        except Exception as e:
            self._log(f"workspace/select 异常: {e}")
        
        return None, None

    def _load_workspace_session_data(self, consent_url, user_agent, impersonate):
        """优先从 cookie 解码 session，失败时回退到 consent HTML 中提取 workspace 数据。"""
        navigation_session = self._load_workspace_session_data_from_navigation_cache()
        if navigation_session:
            self._log(
                "优先使用 navigation client auth session cache: "
                f"workspaces={len(list(navigation_session.get('workspaces') or []))}"
            )
            return navigation_session

        session_data = self._decode_oauth_session_cookie()
        if session_data and session_data.get("workspaces"):
            return session_data
        if session_data:
            try:
                self._log(
                    "consent session cookie keys: "
                    + ",".join(sorted(str(key) for key in session_data.keys()))
                )
            except Exception:
                pass
        else:
            self._log("consent session cookie 不存在或无法解码")

        try:
            cookie_rows = []
            for cookie in self.session.cookies:
                cookie_rows.append(
                    f"{getattr(cookie, 'name', '')}@{getattr(cookie, 'domain', '')}"
                )
            if cookie_rows:
                self._log("当前 cookies: " + ", ".join(cookie_rows[:12]))
        except Exception:
            pass

        seeded_session = self._load_workspace_session_data_from_seed()
        if seeded_session and seeded_session.get("workspaces"):
            self._log(
                "先用已有 ChatGPT Web token seed 提供 workspace，"
                "再尝试从 consent HTML 刷新 session_id"
            )

        dump_data = self._fetch_client_auth_session_dump(
            consent_url=consent_url,
            user_agent=user_agent,
            impersonate=impersonate,
        )
        if dump_data and dump_data.get("session_payload"):
            merged_dump = dict(seeded_session or {})
            for key, value in dict(dump_data.get("session_payload") or {}).items():
                if value in (None, "", {}, []):
                    continue
                merged_dump[key] = value
            if merged_dump.get("workspaces"):
                self._maybe_seed_oauth_session_cookie(
                    merged_dump,
                    existing_session=session_data,
                    reason="merge_dump_workspace",
                )
                self._log(
                    "从 client_auth_session_dump 刷新 session/workspace 数据: "
                    f"workspaces={len(merged_dump.get('workspaces', []))}"
                )
                seeded_session = merged_dump

        html = self._fetch_consent_page_html(consent_url, user_agent, impersonate)
        if not html:
            self._log("consent HTML 为空")
            if seeded_session and seeded_session.get("workspaces"):
                return seeded_session
            return session_data

        parsed = self._extract_session_data_from_consent_html(html)
        if parsed and (
            parsed.get("workspaces")
            or parsed.get("session_id")
            or parsed.get("auth_session_logging_id")
            or parsed.get("openai_client_id")
        ):
            merged = dict(seeded_session or {})
            for key, value in dict(parsed or {}).items():
                if value in (None, "", {}, []):
                    continue
                merged[key] = value
            if merged.get("workspaces"):
                self._maybe_seed_oauth_session_cookie(
                    merged,
                    existing_session=session_data,
                    reason="merge_consent_html_workspace",
                )
                self._log(
                    "从 consent HTML 提取并刷新 session/workspace 数据: "
                    f"workspaces={len(merged.get('workspaces', []))}"
                )
                return merged

        if seeded_session and seeded_session.get("workspaces"):
            return seeded_session

        backend_session = self._load_workspace_session_data_from_backend_check(
            user_agent=user_agent,
            impersonate=impersonate,
        )
        if backend_session and backend_session.get("workspaces"):
            self._log(
                "从 ChatGPT backend accounts/check 提取到 "
                f"{len(backend_session.get('workspaces', []))} 个 workspace"
            )
            return backend_session

        preview = " ".join(str(html).split())[:280]
        if preview:
            self._log(f"consent HTML 预览: {preview}")
        try:
            dump_path = f"/tmp/oauth_consent_debug_{int(time.time() * 1000)}.html"
            with open(dump_path, "w", encoding="utf-8") as fh:
                fh.write(html)
            self._log(f"consent HTML 已落盘: {dump_path}")
        except Exception as exc:
            self._log(f"consent HTML 落盘失败: {exc}")

        return session_data

    def _load_workspace_session_data_from_backend_check(self, user_agent, impersonate):
        session_data = self._fetch_chatgpt_session(user_agent=user_agent)
        normalized = self._normalize_chatgpt_session_tokens(session_data) if session_data else None
        access_token = str((normalized or {}).get("access_token") or "").strip()
        if not access_token:
            seeded_session = self._build_seeded_chatgpt_session()
            normalized = self._normalize_chatgpt_session_tokens(seeded_session) if seeded_session else None
            access_token = str((normalized or {}).get("access_token") or "").strip()
            if access_token:
                self._log("backend accounts/check fallback: 改用已有 ChatGPT Web token seed")
        if not access_token:
            self._log("backend accounts/check fallback: chatgpt session 不可用")
            return None

        if not normalized:
            normalized = {}

        url = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
        headers = self._headers(
            url,
            user_agent=user_agent,
            accept="application/json",
            referer="https://chatgpt.com/codex",
            fetch_site="same-origin",
            extra_headers={
                "authorization": f"Bearer {access_token}",
                "oai-device-id": self._effective_device_id(),
            },
        )

        try:
            kwargs = {"headers": headers, "timeout": 30}
            if impersonate:
                kwargs["impersonate"] = impersonate
            self._browser_pause(0.12, 0.25)
            response = self.session.get(url, **kwargs)
            self._log(f"backend accounts/check fallback -> {response.status_code}")
            if response.status_code != 200:
                self._log(f"backend accounts/check fallback body: {response.text[:200]}")
                return None
            data = response.json()
        except Exception as exc:
            self._log(f"backend accounts/check fallback 异常: {exc}")
            return None

        accounts = data.get("accounts") or {}
        workspaces = []
        seen = set()
        for item in accounts.values():
            account = (item or {}).get("account") or {}
            workspace_id = str(account.get("account_id") or "").strip()
            if not workspace_id or workspace_id in seen:
                continue
            seen.add(workspace_id)
            workspace = {"id": workspace_id}
            organization_id = str(account.get("organization_id") or "").strip()
            if organization_id:
                workspace["organization_id"] = organization_id
            workspaces.append(workspace)

        if not workspaces:
            self._log("backend accounts/check fallback 未返回可用 workspace")
            return None

        cookie_session = self._decode_oauth_session_cookie() or {}
        session_payload = {
            "session_id": str(cookie_session.get("session_id") or "").strip(),
            "openai_client_id": str(
                cookie_session.get("openai_client_id") or self.oauth_client_id or ""
            ).strip(),
            "workspaces": workspaces,
        }
        self._maybe_seed_oauth_session_cookie(
            session_payload,
            existing_session=cookie_session,
            reason="backend_accounts_check_workspace",
        )
        return session_payload

    def _fetch_consent_page_html(self, consent_url, user_agent, impersonate):
        """获取 consent 页 HTML，用于解析 React Router stream 中的 session 数据。"""
        try:
            headers = self._headers(
                consent_url,
                user_agent=user_agent,
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                referer=f"{self.oauth_issuer}/email-verification",
                navigation=True,
            )
            kwargs = {"headers": headers, "allow_redirects": False, "timeout": 30}
            if impersonate:
                kwargs["impersonate"] = impersonate
            self._browser_pause(0.12, 0.3)
            r = self.session.get(consent_url, **kwargs)
            self._log(
                f"consent GET -> {r.status_code} {str(r.url)[:120]} "
                f"content-type={(r.headers.get('content-type', '') or '')[:80]}"
            )
            if r.status_code == 200 and "text/html" in (r.headers.get("content-type", "").lower()):
                return r.text
        except Exception as exc:
            self._log(f"获取 consent HTML 异常: {exc}")
        return ""

    def _fetch_client_auth_session_dump(self, consent_url, user_agent, impersonate):
        dump_url = f"{self.oauth_issuer}/api/accounts/client_auth_session_dump"
        referer = (
            str(consent_url or "").strip()
            or f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
        )
        try:
            headers = self._headers(
                dump_url,
                user_agent=user_agent,
                accept="application/json",
                referer=referer,
                fetch_site="same-origin",
                extra_headers={
                    "oai-device-id": self._effective_device_id(),
                },
            )
            kwargs = {"headers": headers, "timeout": 30}
            if impersonate:
                kwargs["impersonate"] = impersonate
            self._browser_pause(0.1, 0.2)
            response = self.session.get(dump_url, **kwargs)
            self._log(f"client_auth_session_dump -> {response.status_code}")
            if response.status_code != 200:
                try:
                    self._log(
                        "client_auth_session_dump 非 200 body: "
                        f"{str(response.text or '')[:240]}"
                    )
                except Exception:
                    pass
                return None
            data = response.json()
        except Exception as exc:
            self._log(f"client_auth_session_dump 异常: {exc}")
            return None

        session_payload = dict(data.get("client_auth_session") or {})
        session_id = str(data.get("session_id") or "").strip()
        checksum = str(data.get("checksum") or "").strip()
        if session_id and not str(session_payload.get("session_id") or "").strip():
            session_payload["session_id"] = session_id
        if not session_payload:
            self._log("client_auth_session_dump 缺少 client_auth_session")
            return None

        self._log(
            "client_auth_session_dump 已获取: "
            f"session_id={(session_payload.get('session_id') or '')[:48]} "
            f"auth_session_logging_id={(session_payload.get('auth_session_logging_id') or '')[:48]} "
            f"checksum={checksum[:24]}"
        )
        return {
            "session_payload": session_payload,
            "checksum": checksum,
            "session_id": session_id,
        }

    def _extract_session_data_from_consent_html(self, html):
        """从 consent HTML 的 React Router stream 中提取 workspace session 数据。"""
        import json
        import re

        if not html:
            return None

        def _first_match(patterns, text):
            for pattern in patterns:
                m = re.search(pattern, text, re.S)
                if m:
                    return m.group(1)
            return ""

        def _build_from_text(text):
            if not text:
                return None

            normalized = text.replace('\\"', '"')

            session_id = _first_match(
                [
                    r'"session_id","([^"]+)"',
                    r'"session_id":"([^"]+)"',
                ],
                normalized,
            )
            client_id = _first_match(
                [
                    r'"openai_client_id","([^"]+)"',
                    r'"openai_client_id":"([^"]+)"',
                ],
                normalized,
            )
            auth_session_logging_id = _first_match(
                [
                    r'"auth_session_logging_id","([^"]+)"',
                    r'"auth_session_logging_id":"([^"]+)"',
                ],
                normalized,
            )

            workspaces = []
            start = normalized.find('"workspaces"')
            if start < 0:
                start = normalized.find('workspaces')
            if start >= 0:
                end = normalized.find('"openai_client_id"', start)
                if end < 0:
                    end = normalized.find('openai_client_id', start)
                if end < 0:
                    end = min(len(normalized), start + 4000)
                else:
                    end = min(len(normalized), end + 600)

                workspace_chunk = normalized[start:end]
                ids = re.findall(r'"id"(?:,|:)"([0-9a-fA-F-]{36})"', workspace_chunk)
                kinds = re.findall(r'"kind"(?:,|:)"([^"]+)"', workspace_chunk)
                seen = set()
                for idx, wid in enumerate(ids):
                    if wid in seen:
                        continue
                    seen.add(wid)
                    item = {"id": wid}
                    if idx < len(kinds):
                        item["kind"] = kinds[idx]
                    workspaces.append(item)

            if not workspaces and not session_id and not client_id and not auth_session_logging_id:
                return None

            return {
                "session_id": session_id,
                "openai_client_id": client_id,
                "auth_session_logging_id": auth_session_logging_id,
                "workspaces": workspaces,
            }

        candidates = [html]

        for quoted in re.findall(
            r'streamController\.enqueue\(("(?:\\.|[^"\\])*")\)',
            html,
            re.S,
        ):
            try:
                decoded = json.loads(quoted)
            except Exception:
                continue
            if decoded:
                candidates.append(decoded)

        if '\\"' in html:
            candidates.append(html.replace('\\"', '"'))

        for candidate in candidates:
            parsed = _build_from_text(candidate)
            if parsed and (
                parsed.get("workspaces")
                or parsed.get("session_id")
                or parsed.get("auth_session_logging_id")
                or parsed.get("openai_client_id")
            ):
                return parsed

        return None
    
    def _decode_oauth_session_cookie(self):
        """解码 oai-client-auth-session cookie"""
        import json
        import base64

        try:
            for cookie in self.session.cookies:
                try:
                    name = cookie.name if hasattr(cookie, 'name') else str(cookie)
                    if name == "oai-client-auth-session":
                        value = cookie.value if hasattr(cookie, 'value') else self.session.cookies.get(name)
                        if value:
                            direct_data = None
                            padded = value + "=" * (-len(value) % 4)
                            try:
                                try:
                                    decoded = base64.b64decode(padded).decode('utf-8')
                                except Exception:
                                    decoded = base64.urlsafe_b64decode(padded).decode('utf-8')
                                direct_data = json.loads(decoded)
                                if isinstance(direct_data, dict) and direct_data.get("workspaces"):
                                    return direct_data
                            except Exception:
                                direct_data = None

                            first_dict = direct_data if isinstance(direct_data, dict) else None
                            for seg in str(value).split("."):
                                raw = (seg or "").strip()
                                if not raw:
                                    continue
                                try:
                                    seg_padded = raw + "=" * ((4 - (len(raw) % 4)) % 4)
                                    decoded_seg = base64.urlsafe_b64decode(seg_padded.encode("ascii")).decode("utf-8", errors="ignore")
                                    seg_data = json.loads(decoded_seg)
                                    if not isinstance(seg_data, dict):
                                        continue
                                    if seg_data.get("workspaces"):
                                        if first_dict:
                                            merged = dict(first_dict)
                                            merged.update(seg_data)
                                            return merged
                                        return seg_data
                                    if first_dict is None:
                                        first_dict = seg_data
                                except Exception:
                                    continue
                            if first_dict is not None:
                                return first_dict
                except Exception:
                    continue
        except Exception:
            pass

        return None

    def _maybe_seed_oauth_session_cookie(self, session_payload, *, existing_session=None, reason=""):
        payload = dict(session_payload or {})
        if not payload:
            return False

        existing = dict(existing_session or self._decode_oauth_session_cookie() or {})
        existing_sid = str(existing.get("session_id") or "").strip()
        if existing_sid:
            merged = dict(existing)
            updated = False

            for key, value in payload.items():
                if value in (None, "", {}, []):
                    continue
                if key == "session_id":
                    incoming_sid = str(value or "").strip()
                    if incoming_sid and incoming_sid == existing_sid and merged.get("session_id") != incoming_sid:
                        merged["session_id"] = incoming_sid
                        updated = True
                    continue
                if key == "workspaces":
                    workspaces = list(value or [])
                    if workspaces and merged.get("workspaces") != workspaces:
                        merged["workspaces"] = workspaces
                        updated = True
                    continue
                if merged.get(key) != value:
                    merged[key] = value
                    updated = True

            suffix = f" ({reason})" if reason else ""
            if updated:
                self._log("已有真实 session_id，合并补全 oai-client-auth-session" + suffix)
                return self._seed_oauth_session_cookie(merged)
            self._log("保留现有 oai-client-auth-session，不覆写真实 session_id" + suffix)
            return False
        return self._seed_oauth_session_cookie(payload)

    def _seed_oauth_session_cookie(self, session_payload):
        import base64
        import json

        payload = dict(self._decode_oauth_session_cookie() or {})
        payload.update(dict(session_payload or {}))
        if not payload:
            return False

        try:
            encoded = base64.urlsafe_b64encode(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("ascii").rstrip("=")
            for domain in ("auth.openai.com", ".auth.openai.com"):
                try:
                    self.session.cookies.set(
                        "oai-client-auth-session",
                        encoded,
                        domain=domain,
                        path="/",
                        secure=True,
                    )
                except Exception:
                    self.session.cookies.set(
                        "oai-client-auth-session",
                        encoded,
                        domain=domain,
                        path="/",
                    )
            self._log(
                "已回填 oai-client-auth-session workspaces="
                + ",".join(str((item or {}).get("id") or "") for item in payload.get("workspaces", [])[:5])
            )
            return True
        except Exception as exc:
            self._log(f"回填 oai-client-auth-session 失败: {exc}")
            return False
    
    def _exchange_code_for_tokens(self, code, code_verifier, user_agent, impersonate):
        """用 authorization code 换取 tokens"""
        url = f"{self.oauth_issuer}/oauth/token"
        
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.oauth_redirect_uri,
            "client_id": self.oauth_client_id,
            "code_verifier": code_verifier,
        }
        
        headers = self._headers(
            url,
            user_agent=user_agent,
            accept="application/json",
            referer=f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent",
            origin=self.oauth_issuer,
            content_type="application/x-www-form-urlencoded",
            fetch_site="same-origin",
        )
        
        try:
            kwargs = {"data": payload, "headers": headers, "timeout": 60}
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r = self.session.post(url, **kwargs)
            
            if r.status_code == 200:
                return r.json()
            else:
                self._log(f"换取 tokens 失败: {r.status_code} - {r.text[:200]}")
                
        except Exception as e:
            self._log(f"换取 tokens 异常: {e}")
        
        return None
    
    def _handle_otp_verification(
        self,
        email,
        device_id,
        user_agent,
        sec_ch_ua,
        impersonate,
        skymail_client,
        state,
        allow_resend=True,
    ):
        """处理 OAuth 阶段的邮箱 OTP 验证，返回服务端声明的下一步状态。"""
        self._log("步骤4: 检测到邮箱 OTP 验证")

        request_url = f"{self.oauth_issuer}/api/accounts/email-otp/validate"
        headers_otp = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="application/json",
            referer=state.current_url or state.continue_url or f"{self.oauth_issuer}/email-verification",
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={
                "oai-device-id": device_id,
            },
        )
        headers_otp.update(generate_datadog_trace())

        if not hasattr(skymail_client, "_used_codes"):
            skymail_client._used_codes = set()

        tried_codes = set(getattr(skymail_client, "_used_codes", set()))
        slow_mail_domains = ("@outlook.com", "@hotmail.com", "@live.com")
        existing_account_mode = bool(getattr(self, "prefer_email_otp_first", False))
        if str(email or "").lower().endswith(slow_mail_domains):
            otp_wait_budget = 360
        elif existing_account_mode:
            otp_wait_budget = 90
        else:
            otp_wait_budget = 45
        otp_deadline = time.time() + otp_wait_budget
        otp_sent_at = time.time()
        if bool(getattr(self, "ignore_otp_sent_at_once", False)):
            otp_sent_at = None
            self.ignore_otp_sent_at_once = False
            self._log("本轮 OTP 检查忽略 otp_sent_at 锚点，允许回看最近验证码")

        def existing_account_chain_active():
            return existing_account_mode

        def otp_response_looks_like_challenge(*parts):
            lowered = "\n".join(str(part or "").lower() for part in parts)
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

        def mark_about_you_direct_authorize_reentry(recovered_state, reason):
            if not recovered_state or not self._state_is_about_you(recovered_state):
                return
            if not existing_account_chain_active():
                return
            self.direct_authorize_before_about_you_once = True
            self._log(
                f"{reason} 命中 about_you，下一次 about_you 先尝试 direct authorize re-entry"
            )

        def validate_otp(code):
            tried_codes.add(code)
            self._log(f"尝试 OTP: {code}")

            def probe_state_after_timeout():
                probe_candidates = [
                    state.current_url or state.continue_url or f"{self.oauth_issuer}/email-verification",
                    f"{self.oauth_issuer}/email-verification",
                    f"{self.oauth_issuer}/about-you",
                    "https://chatgpt.com/",
                ]
                for probe_url in probe_candidates:
                    if not probe_url:
                        continue
                    try:
                        probe_headers = self._headers(
                            probe_url,
                            user_agent=user_agent,
                            sec_ch_ua=sec_ch_ua,
                            accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            referer=state.current_url or state.continue_url or f"{self.oauth_issuer}/email-verification",
                            navigation=True,
                        )
                        probe_kwargs = {
                            "headers": probe_headers,
                            "allow_redirects": True,
                            "timeout": 30,
                        }
                        if impersonate:
                            probe_kwargs["impersonate"] = impersonate
                        resp = self.session.get(probe_url, **probe_kwargs)
                    except Exception as probe_exc:
                        self._log(f"OTP 超时后探测状态异常 {probe_url}: {probe_exc}")
                        continue

                    recovered_state = self._state_from_url(str(resp.url) or probe_url)
                    self._log(
                        "OTP 超时后探测状态 -> "
                        f"{probe_url} => {describe_flow_state(recovered_state)}"
                    )
                    if (
                        recovered_state.page_type
                        and recovered_state.page_type != "email_otp_verification"
                    ):
                        return recovered_state
                return None

            try:
                kwargs = {
                    "json": {"code": code},
                    "headers": headers_otp,
                    "timeout": 30,
                    "allow_redirects": False,
                }
                if impersonate:
                    kwargs["impersonate"] = impersonate

                self._browser_pause(0.12, 0.25)
                resp_otp = self.session.post(request_url, **kwargs)
            except Exception as e:
                self._log(f"email-otp/validate 异常: {e}")
                recovered_state = probe_state_after_timeout()
                if recovered_state is not None:
                    mark_about_you_direct_authorize_reentry(
                        recovered_state,
                        "OTP 异常后恢复状态",
                    )
                    skymail_client._used_codes.add(code)
                    self._log(f"OTP 超时后恢复状态成功 {describe_flow_state(recovered_state)}")
                    return recovered_state
                return None

            self._log(f"/email-otp/validate -> {resp_otp.status_code}")
            if resp_otp.status_code in {301, 302, 303, 307, 308}:
                next_url = normalize_flow_url(
                    resp_otp.headers.get("Location", ""),
                    auth_base=self.oauth_issuer,
                ) or str(resp_otp.url or request_url)
                next_state = self._state_from_url(next_url)
                self._remember_successful_email_otp(code)
                mark_about_you_direct_authorize_reentry(
                    next_state,
                    "OTP 验证跳转",
                )
                self._log(f"OTP 验证跳转 {describe_flow_state(next_state)}")
                skymail_client._used_codes.add(code)
                return next_state
            if resp_otp.status_code != 200:
                self._log(f"OTP 无效: {resp_otp.text[:160]}")
                if (
                    resp_otp.status_code == 403
                    and otp_response_looks_like_challenge(resp_otp.text)
                    and existing_account_chain_active()
                ):
                    bridge_target = (
                        state.current_url
                        or state.continue_url
                        or f"{self.oauth_issuer}/email-verification"
                    )
                    self._log(
                        "OTP 403 challenge，尝试浏览器内 existing-account bridge/OTP 恢复"
                    )
                    browser_tokens = self._browser_hydrate_chatgpt_session(
                        consent_url=bridge_target,
                        user_agent=user_agent,
                    )
                    if isinstance(browser_tokens, dict) and browser_tokens.get("access_token"):
                        skymail_client._used_codes.add(code)
                        self._log("✅ OTP 403 challenge 已通过浏览器恢复 ChatGPT session/token")
                        return browser_tokens
                recovered_state = probe_state_after_timeout()
                if recovered_state is not None:
                    mark_about_you_direct_authorize_reentry(
                        recovered_state,
                        "OTP 非 200 后恢复状态",
                    )
                    skymail_client._used_codes.add(code)
                    self._log(f"OTP 非 200 后恢复状态成功 {describe_flow_state(recovered_state)}")
                    return recovered_state
                return None

            try:
                otp_data = resp_otp.json()
            except Exception:
                self._log("email-otp/validate 响应不是 JSON")
                return None

            next_state = self._state_from_payload(
                otp_data,
                current_url=str(resp_otp.url) or (state.current_url or state.continue_url or request_url),
            )
            self._remember_successful_email_otp(code)
            mark_about_you_direct_authorize_reentry(
                next_state,
                "OTP 验证通过",
            )
            self._log(f"OTP 验证通过 {describe_flow_state(next_state)}")
            skymail_client._used_codes.add(code)
            return next_state

        if hasattr(skymail_client, "wait_for_verification_code"):
            self._log("使用 wait_for_verification_code 进行阻塞式获取新验证码...")
            if otp_sent_at is None:
                recent_success_code = self._get_recent_successful_email_otp()
                if recent_success_code:
                    self._log(
                        "本轮优先复用最近一次成功验证码，避免回看邮箱时命中更旧历史码: "
                        f"{recent_success_code}"
                    )
                    next_state = validate_otp(recent_success_code)
                    if next_state:
                        return next_state
            slow_mail_domains = ("@outlook.com", "@hotmail.com", "@live.com")
            while time.time() < otp_deadline:
                remaining = max(1, int(otp_deadline - time.time()))
                if str(email or "").lower().endswith(slow_mail_domains):
                    wait_time = min(60, max(30, remaining))
                elif existing_account_mode:
                    wait_time = min(45, max(25, remaining))
                else:
                    wait_time = min(20, max(12, remaining))
                try:
                    code = skymail_client.wait_for_verification_code(
                        email,
                        timeout=wait_time,
                        otp_sent_at=otp_sent_at,
                        exclude_codes=tried_codes,
                    )
                except Exception as e:
                    self._log(f"等待 OTP 异常: {e}")
                    code = None

                if not code:
                    if allow_resend:
                        self._log("暂未收到新的 OTP，尝试主动触发 passwordless/send-otp")
                        resend_state = self._submit_passwordless_send_otp(
                            email,
                            device_id,
                            user_agent=user_agent,
                            sec_ch_ua=sec_ch_ua,
                            impersonate=impersonate,
                            referer=state.current_url or state.continue_url or f"{self.oauth_issuer}/email-verification",
                        )
                        if resend_state:
                            return self._handle_otp_verification(
                                email,
                                device_id,
                                user_agent,
                                sec_ch_ua,
                                impersonate,
                                skymail_client,
                                resend_state,
                                allow_resend=False,
                            )
                        if (
                            str(email or "").lower().endswith(slow_mail_domains)
                            and bool(getattr(self, "prefer_email_otp_first", False))
                        ):
                            self._log(
                                "passwordless/send-otp 未建立下一步状态，"
                                "改走 authorize/continue 浏览器 fallback 重建 auth/OTP 状态"
                            )
                            browser_state = self._submit_authorize_continue_browser_fallback(
                                email,
                                user_agent=user_agent,
                            )
                            if browser_state:
                                if self._state_is_email_otp(browser_state):
                                    self.reuse_existing_email_code_once = True
                                    self._log(
                                        "authorize/continue 浏览器 fallback 已回到 email_otp_verification，"
                                        "允许 existing-account 恢复链复用一次最近邮箱验证码"
                                    )
                                self._log(
                                    "authorize/continue 浏览器 fallback 已重建状态 -> "
                                    f"{describe_flow_state(browser_state)}"
                                )
                                return browser_state
                        if str(getattr(self, "last_passwordless_send_otp_error_code", "") or "").strip() == "invalid_state":
                            self._log(
                                "passwordless/send-otp 返回 invalid_state，"
                                "改走 authorize/continue 浏览器 fallback 重建 auth 状态"
                            )
                            browser_state = self._submit_authorize_continue_browser_fallback(
                                email,
                                user_agent=user_agent,
                            )
                            if browser_state:
                                if self._state_is_email_otp(browser_state):
                                    self.reuse_existing_email_code_once = True
                                    self._log(
                                        "authorize/continue 浏览器 fallback 已回到 email_otp_verification，"
                                        "允许 existing-account 恢复链复用一次最近邮箱验证码"
                                    )
                                self._log(
                                    "authorize/continue 浏览器 fallback 已重建状态 -> "
                                    f"{describe_flow_state(browser_state)}"
                                )
                                return browser_state
                    if (
                        not allow_resend
                        and str(email or "").lower().endswith(slow_mail_domains)
                        and bool(getattr(self, "prefer_email_otp_first", False))
                    ):
                        self._log(
                            "Outlook existing-account OTP 在重发后一轮仍未收到，"
                            "提前返回上层走密码/浏览器回退"
                        )
                        return None
                    self._log("暂未收到新的 OTP，继续等待...")
                    continue

                if code in tried_codes:
                    self._log(f"跳过已尝试验证码: {code}")
                    continue

                next_state = validate_otp(code)
                if next_state:
                    return next_state
        else:
            while time.time() < otp_deadline:
                messages = skymail_client.fetch_emails(email) or []
                candidate_codes = []

                for msg in messages[:12]:
                    content = msg.get("content") or msg.get("text") or ""
                    code = skymail_client.extract_verification_code(content)
                    if code and code not in tried_codes:
                        candidate_codes.append(code)

                if not candidate_codes:
                    elapsed = int(45 - max(0, otp_deadline - time.time()))
                    self._log(f"等待新的 OTP... ({elapsed}s/45s)")
                    time.sleep(2)
                    continue

                for otp_code in candidate_codes:
                    next_state = validate_otp(otp_code)
                    if next_state:
                        return next_state

                time.sleep(2)

        self._log(f"OAuth 阶段 OTP 验证失败，已尝试 {len(tried_codes)} 个验证码")
        return None
