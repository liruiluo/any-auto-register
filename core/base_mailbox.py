"""邮箱池基类 - 抽象临时邮箱/收件服务"""
import atexit
import glob
import hashlib
import json
import os
import random
import re
import select
import shutil
import string
import subprocess
import sys
import tempfile
import threading
import time

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any
from urllib.parse import urlsplit, parse_qs, unquote, quote

import requests


@dataclass
class MailboxAccount:
    email: str
    account_id: str = ""
    extra: dict = None  # 平台额外信息


class BaseMailbox(ABC):
    def _log(self, message: str) -> None:
        log_fn = getattr(self, "_log_fn", None)
        if callable(log_fn):
            log_fn(message)

    @abstractmethod
    def get_email(self) -> MailboxAccount:
        """获取一个可用邮箱"""
        ...

    @abstractmethod
    def wait_for_code(self, account: MailboxAccount, keyword: str = "",
                      timeout: int = 120, before_ids: set = None,
                      code_pattern: str = None, **kwargs) -> str:
        """等待并返回验证码，code_pattern 为自定义正则（默认匹配6位数字）"""
        ...

    def _safe_extract(self, text: str, pattern: str = None) -> Optional[str]:
        """通用验证码提取逻辑：若有捕获组则返回 group(1)，否则返回 group(0)"""
        import re
        text = str(text or "")
        if not text:
            return None

        patterns = []
        if pattern:
            patterns.append(pattern)

        # 先匹配带明显语义的验证码，避免误提取 MIME boundary、时间戳等 6 位数字。
        patterns.extend([
            r'(?is)(?:verification\s+code|one[-\s]*time\s+(?:password|code)|security\s+code|login\s+code|验证码|校验码|动态码|認證碼|驗證碼)[^0-9]{0,30}(\d{6})',
            r'(?is)\bcode\b[^0-9]{0,12}(\d{6})',
            r'(?<!#)(?<!\d)(\d{6})(?!\d)',
        ])

        for regex in patterns:
            m = re.search(regex, text)
            if m:
                # 兼容逻辑：若 pattern 中有捕获组则取 group(1)，否则取 group(0)
                return m.group(1) if m.groups() else m.group(0)
        return None

    def _decode_raw_content(self, raw: str) -> str:
        """解析邮件原始文本 (借鉴自 Fugle)，处理 Quoted-Printable 和 HTML 实体"""
        import quopri, html, re
        text = str(raw or "")
        if not text: return ""
        # 简单切分 Header 和 Body
        if "\r\n\r\n" in text:
            text = text.split("\r\n\r\n", 1)[1]
        elif "\n\n" in text:
            text = text.split("\n\n", 1)[1]
        try:
            # 处理 Quoted-Printable
            decoded_bytes = quopri.decodestring(text)
            text = decoded_bytes.decode("utf-8", errors="ignore")
        except Exception:
            pass
        # 清除 HTML 标签并反转义
        text = html.unescape(text)
        text = re.sub(r'(?im)^content-(?:type|transfer-encoding):.*$', ' ', text)
        text = re.sub(r'(?im)^--+[_=\w.-]+$', ' ', text)
        text = re.sub(r'(?i)----=_part_[\w.]+', ' ', text)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    @abstractmethod
    def get_current_ids(self, account: MailboxAccount) -> set:
        """返回当前邮件 ID 集合（用于过滤旧邮件）"""
        ...


def normalize_domains(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, (list, tuple, set)):
        items = raw
    else:
        items = re.split(r"[\s,;]+", str(raw))
    seen = []
    for item in items:
        value = str(item or "").strip().lower()
        if not value or value in seen:
            continue
        seen.append(value)
    return seen


def base_domain(email_or_domain: str) -> str:
    value = str(email_or_domain or "").strip().lower()
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    parts = [part for part in value.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return value


OUTLOOK_API_OPENAI_KEYWORDS = [
    "chatgpt",
    "openai",
    "verification code",
    "your chatgpt code is",
    "chatgpt code is",
    "验证码",
]
outlook_api_claimed_addresses_lock = threading.Lock()
outlook_api_claimed_addresses: set[str] = set()


def parse_timestamp_info(value: Any) -> tuple[int, int]:
    if value in (None, ""):
        return 0, 0
    if isinstance(value, (int, float)):
        if value >= 1e12:
            return int(value), 1
        if value >= 1e9:
            return int(float(value) * 1000), 1000
        return int(value), 1

    text = str(value or "").strip()
    if not text:
        return 0, 0
    if re.fullmatch(r"\d{13}", text):
        return int(text), 1
    if re.fullmatch(r"\d{10}", text):
        return int(text) * 1000, 1000

    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000), 1000
    except Exception:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return int(parsed.timestamp() * 1000), 1000
        except Exception:
            continue
    return 0, 0


def normalize_outlook_api_accounts(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        if isinstance(payload.get("accounts"), list):
            return payload["accounts"]
        data = payload.get("data")
        if isinstance(data, dict) and isinstance(data.get("accounts"), list):
            return data["accounts"]
    if isinstance(payload, list):
        return payload
    return []


def normalize_outlook_api_messages(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("emails", "messages"):
            if isinstance(payload.get(key), list):
                return payload[key]
        data = payload.get("data")
        if isinstance(data, dict):
            for key in ("emails", "messages"):
                if isinstance(data.get(key), list):
                    return data[key]
    if isinstance(payload, list):
        return payload
    return []


def load_used_address_map(file_path: str) -> dict[str, dict[str, Any]]:
    raw_path = str(file_path or "").strip()
    if not raw_path:
        return {}
    path = Path(raw_path).expanduser()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    entries = []
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        entries = payload["items"]
    elif isinstance(payload, list):
        entries = payload

    result: dict[str, dict[str, Any]] = {}
    for item in entries:
        if not isinstance(item, dict):
            continue
        address = str(item.get("address") or "").strip()
        if not address:
            continue
        result[address.lower()] = {
            "address": address,
            "account_id": item.get("account_id") or item.get("accountId"),
            "disabled_at": item.get("disabled_at") or item.get("disabledAt") or "",
            "source": item.get("source") or "local",
        }
    return result


def save_used_address_map(file_path: str, used_map: dict[str, dict[str, Any]]) -> None:
    raw_path = str(file_path or "").strip()
    if not raw_path:
        return
    path = Path(raw_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    items = sorted(
        used_map.values(),
        key=lambda item: str(item.get("address") or "").lower(),
    )
    path.write_text(
        json.dumps({"items": items}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def create_mailbox(provider: str, extra: dict = None, proxy: str = None) -> 'BaseMailbox':
    """工厂方法：根据 provider 创建对应的 mailbox 实例"""
    extra = extra or {}

    def resolve_proxy_override(primary: Any, fallback: str = None) -> str | None:
        raw = str(primary or "").strip()
        if not raw:
            return fallback
        if raw.lower() in {"direct", "__direct__", "none", "off", "false", "0"}:
            return None
        return raw

    if provider == "tempmail_lol":
        return TempMailLolMailbox(
            proxy=proxy,
            preferred_base_domains=extra.get("tempmail_lol_preferred_base_domains"),
            reject_base_domains=extra.get("tempmail_lol_reject_base_domains"),
            domain_pick_attempts=int(extra.get("tempmail_lol_domain_pick_attempts", 1) or 1),
        )
    elif provider == "temp_mail_org_browser":
        return TempMailOrgBrowserMailbox(
            base_url=extra.get("temp_mail_org_base_url", "https://web2.temp-mail.org"),
            proxy=resolve_proxy_override(extra.get("temp_mail_org_proxy"), proxy),
            poll_interval=int(extra.get("temp_mail_org_poll_interval", 5) or 5),
            bootstrap_timeout=int(extra.get("temp_mail_org_bootstrap_timeout", 30) or 30),
            preferred_domains=extra.get("temp_mail_org_preferred_domains"),
            domain_pick_attempts=int(extra.get("temp_mail_org_domain_pick_attempts", 1) or 1),
            preferred_domain_strict=str(
                extra.get("temp_mail_org_preferred_domain_strict", "")
            ).strip().lower() in {"1", "true", "yes", "on"},
        )
    elif provider == "duckmail":
        return DuckMailMailbox(
            api_url=extra.get("duckmail_api_url", "https://www.duckmail.sbs"),
            provider_url=extra.get("duckmail_provider_url", "https://api.duckmail.sbs"),
            bearer=extra.get("duckmail_bearer", "kevin273945"),
            proxy=proxy,
        )
    elif provider == "freemail":
        return FreemailMailbox(
            api_url=extra.get("freemail_api_url", ""),
            admin_token=extra.get("freemail_admin_token", ""),
            username=extra.get("freemail_username", ""),
            password=extra.get("freemail_password", ""),
            proxy=proxy,
        )
    elif provider == "moemail":
        return MoeMailMailbox(
            api_url=extra.get("moemail_api_url", "https://sall.cc"),
            proxy=proxy,
        )
    elif provider == "cfworker":
        return CFWorkerMailbox(
            api_url=extra.get("cfworker_api_url", ""),
            admin_token=extra.get("cfworker_admin_token", ""),
            domain=extra.get("cfworker_domain", ""),
            fingerprint=extra.get("cfworker_fingerprint", ""),
            mode=extra.get("cfworker_mode", "auto"),
            proxy=resolve_proxy_override(extra.get("cfworker_proxy"), proxy),
        )
    elif provider == "luckmail":
        return LuckMailMailbox(
            base_url=extra.get("luckmail_base_url") or "https://mails.luckyous.com/",
            api_key=extra.get("luckmail_api_key", ""),
            project_code=extra.get("luckmail_project_code", ""),
            email_type=extra.get("luckmail_email_type", ""),
            domain=extra.get("luckmail_domain", ""),
        )
    elif provider == "imap_json_secret":
        provider_proxy = resolve_proxy_override(
            extra.get("imap_proxy") or extra.get("mail_provider_proxy"),
            proxy,
        )
        return IMAPSecretMailbox(
            secret_path=extra.get("imap_mailbox_secret_path", ""),
            target_email=extra.get("imap_target_email", ""),
            alias_mode=extra.get("imap_alias_mode", "plus"),
            alias_prefix=extra.get("imap_alias_prefix", "aar"),
            mailbox_name=extra.get("imap_mailbox", ""),
            from_filter=extra.get("imap_from_filter", ""),
            subject_filter=extra.get("imap_subject_filter", ""),
            lookback_seconds=extra.get("imap_lookback_seconds", 1800),
            interval=extra.get("imap_poll_interval", 5),
            max_fetch=extra.get("imap_max_fetch", 40),
            code_pattern=extra.get("imap_code_pattern", ""),
            proxy=provider_proxy,
        )
    elif provider == "outlook_webmail":
        provider_proxy = resolve_proxy_override(
            extra.get("outlook_webmail_proxy") or extra.get("mail_provider_proxy"),
            proxy,
        )
        return OutlookWebmailMailbox(
            pool_secret_path=extra.get("outlook_webmail_pool_secret", ""),
            login_slug=extra.get("outlook_webmail_login_slug", ""),
            base_email=extra.get("outlook_webmail_base_email", ""),
            base_url=extra.get("outlook_webmail_base_url", "https://ms.lqqq.cc"),
            alias_mode=extra.get("outlook_webmail_alias_mode", "plus"),
            alias_prefix=extra.get("outlook_webmail_alias_prefix", "aar"),
            target_email=extra.get("outlook_webmail_target_email", ""),
            poll_interval=extra.get("outlook_webmail_poll_interval", 5),
            timeout=extra.get("outlook_webmail_timeout", 60),
            proxy=provider_proxy,
        )
    elif provider == "outlook_official_web":
        provider_proxy = resolve_proxy_override(
            extra.get("outlook_official_proxy") or extra.get("mail_provider_proxy"),
            proxy,
        )
        return OutlookOfficialWebMailbox(
            pool_secret_path=extra.get("outlook_official_pool_secret", ""),
            login_slug=extra.get("outlook_official_login_slug", ""),
            base_email=extra.get("outlook_official_base_email", ""),
            alias_mode=extra.get("outlook_official_alias_mode", "official"),
            alias_prefix=extra.get("outlook_official_alias_prefix", "aar"),
            target_email=extra.get("outlook_official_target_email", ""),
            proof_pool_secret_path=extra.get("outlook_official_proof_pool_secret", ""),
            proof_imap_secret_path=extra.get("outlook_official_proof_imap_secret", ""),
            proof_target_email=extra.get("outlook_official_proof_target_email", ""),
            proof_alias_mode=extra.get("outlook_official_proof_alias_mode", "base"),
            poll_interval=extra.get("outlook_official_poll_interval", 5),
            timeout=extra.get("outlook_official_timeout", 60),
            disable_selenium=str(extra.get("outlook_official_disable_selenium", "")).strip().lower() in {"1", "true", "yes", "on"},
            proxy=provider_proxy,
        )
    elif provider in {"outlookapi", "outlook_api"}:
        provider_proxy = resolve_proxy_override(
            extra.get("outlook_email_proxy") or extra.get("mail_provider_proxy"),
            proxy,
        )
        return OutlookApiMailbox(
            base_url=extra.get("outlook_email_base_url", ""),
            auth_mode=extra.get("outlook_email_auth_mode", "auto"),
            api_key=extra.get("outlook_email_api_key", ""),
            login_password=extra.get("outlook_email_login_password", ""),
            group_id=extra.get("outlook_email_group_id"),
            address_mode=extra.get("outlook_email_address_mode", "aliases-first"),
            address_pool=extra.get("outlook_email_address_pool", ""),
            folder=extra.get("outlook_email_folder", "all"),
            fetch_top=extra.get("outlook_email_fetch_top", 10),
            disable_used_accounts=str(
                extra.get("outlook_email_disable_used_accounts", "true")
            ).strip().lower() not in {"0", "false", "no", "off"},
            disable_used_status=extra.get("outlook_email_disable_used_status", "inactive"),
            used_addresses_path=extra.get("outlook_email_used_addresses_path", ""),
            poll_interval=extra.get("outlook_email_poll_interval", 5),
            timeout=extra.get("outlook_email_timeout", 60),
            proxy=provider_proxy,
        )
    else:  # laoudo
        return LaoudoMailbox(
            auth_token=extra.get("laoudo_auth", ""),
            email=extra.get("laoudo_email", ""),
            account_id=extra.get("laoudo_account_id", ""),
        )


class LaoudoMailbox(BaseMailbox):
    """laoudo.com 邮箱服务"""
    def __init__(self, auth_token: str, email: str, account_id: str):
        self.auth = auth_token
        self._email = email
        self._account_id = account_id
        self.api = "https://laoudo.com/api/email"
        self._ua = "Mozilla/5.0"

    def get_email(self) -> MailboxAccount:
        if not self._email:
            raise RuntimeError(
                "Laoudo 邮箱未配置或已失效，请检查 laoudo_auth、laoudo_email、laoudo_account_id 配置，"
                "或切换到 tempmail_lol（无需配置）"
            )
        return MailboxAccount(email=self._email, account_id=self._account_id)

    def get_current_ids(self, account: MailboxAccount) -> set:
        from curl_cffi import requests as curl_requests
        try:
            r = curl_requests.get(
                f"{self.api}/list",
                params={"accountId": account.account_id, "allReceive": 0,
                        "emailId": 0, "timeSort": 1, "size": 50, "type": 0},
                headers={"authorization": self.auth, "user-agent": self._ua},
                timeout=15, impersonate="chrome131"
            )
            if r.status_code == 200:
                mails = r.json().get("data", {}).get("list", []) or []
                return {m.get("id") or m.get("emailId") for m in mails if m.get("id") or m.get("emailId")}
        except Exception:
            pass
        return set()

    def wait_for_code(self, account: MailboxAccount, keyword: str = "trae",
                      timeout: int = 120, before_ids: set = None, code_pattern: str = None, **kwargs) -> str:
        import re, time
        from curl_cffi import requests as curl_requests
        seen = set(before_ids) if before_ids else set()
        start = time.time()
        h = {"authorization": self.auth, "user-agent": self._ua}
        while time.time() - start < timeout:
            try:
                r = curl_requests.get(
                    f"{self.api}/list",
                    params={"accountId": account.account_id, "allReceive": 0,
                            "emailId": 0, "timeSort": 1, "size": 50, "type": 0},
                    headers=h, timeout=15, impersonate="chrome131"
                )
                if r.status_code == 200:
                    mails = r.json().get("data", {}).get("list", []) or []
                    for mail in mails:
                        mid = mail.get("id") or mail.get("emailId")
                        if not mid or mid in seen:
                            continue
                        seen.add(mid)
                        text = (str(mail.get("subject", "")) + " " +
                                str(mail.get("content") or mail.get("html") or ""))
                        if keyword and keyword.lower() not in text.lower():
                            continue
                        code = self._safe_extract(text, code_pattern)
                        if code:
                            return code
            except Exception:
                pass
            time.sleep(4)
        raise TimeoutError(f"等待验证码超时 ({timeout}s)")


class AitreMailbox(BaseMailbox):
    """mail.aitre.cc 临时邮箱"""
    def __init__(self, email: str):
        self._email = email
        self.api = "https://mail.aitre.cc/api/tempmail"

    def get_email(self) -> MailboxAccount:
        return MailboxAccount(email=self._email)

    def get_current_ids(self, account: MailboxAccount) -> set:
        import requests
        try:
            r = requests.get(f"{self.api}/emails", params={"email": account.email}, timeout=10)
            emails = r.json().get("emails", [])
            return {str(m["id"]) for m in emails if "id" in m}
        except Exception:
            return set()

    def wait_for_code(self, account: MailboxAccount, keyword: str = "trae",
                      timeout: int = 120, before_ids: set = None, code_pattern: str = None, **kwargs) -> str:
        import re, time, requests
        seen = set(before_ids) if before_ids else set()
        last_check = None
        start = time.time()
        while time.time() - start < timeout:
            params = {"email": account.email}
            if last_check:
                params["lastCheck"] = last_check
            try:
                r = requests.get(f"{self.api}/poll", params=params, timeout=10)
                data = r.json()
                last_check = data.get("lastChecked")
                if data.get("count", 0) > 0:
                    r2 = requests.get(f"{self.api}/emails", params={"email": account.email}, timeout=10)
                    for mail in r2.json().get("emails", []):
                        mid = str(mail.get("id", ""))
                        if mid in seen:
                            continue
                        seen.add(mid)
                        text = mail.get("preview", "") + mail.get("content", "")
                        if keyword and keyword.lower() not in text.lower():
                            continue
                        code = self._safe_extract(text, code_pattern)
                        if code:
                            return code
            except Exception:
                pass
            time.sleep(3)
        raise TimeoutError(f"等待验证码超时 ({timeout}s)")


class TempMailLolMailbox(BaseMailbox):
    """tempmail.lol 免费临时邮箱（无需注册，自动生成）"""

    def __init__(
        self,
        proxy: str = None,
        preferred_base_domains: Any = None,
        reject_base_domains: Any = None,
        domain_pick_attempts: int = 1,
    ):
        self.api = "https://api.tempmail.lol/v2"
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self._token = None
        self._email = None
        self.preferred_base_domains = normalize_domains(preferred_base_domains)
        self.reject_base_domains = normalize_domains(reject_base_domains)
        self.domain_pick_attempts = max(1, int(domain_pick_attempts or 1))

    def get_email(self) -> MailboxAccount:
        import requests
        seen_domains = []
        last_error = None
        for _ in range(self.domain_pick_attempts):
            r = requests.post(
                f"{self.api}/inbox/create",
                json={},
                proxies=self.proxy,
                timeout=15,
            )
            data = r.json()
            email = data.get("address") or data.get("email", "")
            if not email:
                last_error = RuntimeError(f"tempmail.lol API 返回空邮箱: {data}")
                continue
            current_base_domain = base_domain(email)
            seen_domains.append(current_base_domain)
            if self.preferred_base_domains and current_base_domain not in self.preferred_base_domains:
                last_error = RuntimeError(
                    f"tempmail.lol domain not preferred: {current_base_domain}; "
                    f"preferred={self.preferred_base_domains}"
                )
                continue
            if self.reject_base_domains and current_base_domain in self.reject_base_domains:
                last_error = RuntimeError(
                    f"tempmail.lol domain rejected: {current_base_domain}; "
                    f"reject={self.reject_base_domains}"
                )
                continue
            self._email = email
            self._token = data.get("token", "")
            print(f"[TempMailLol] 生成邮箱: {self._email}")
            return MailboxAccount(email=self._email, account_id=self._token)
        if last_error:
            raise RuntimeError(
                f"{last_error} | seen_domains={seen_domains}"
            )
        raise RuntimeError("tempmail.lol failed to produce a usable mailbox")

    def get_current_ids(self, account: MailboxAccount) -> set:
        import requests
        try:
            r = requests.get(f"{self.api}/inbox",
                params={"token": account.account_id},
                proxies=self.proxy, timeout=10)
            return {str(m["id"]) for m in r.json().get("emails", [])}
        except Exception:
            return set()

    def wait_for_code(self, account: MailboxAccount, keyword: str = "",
                      timeout: int = 120, before_ids: set = None, code_pattern: str = None, **kwargs) -> str:
        import re, time, requests
        seen = set(before_ids or [])
        otp_sent_at = kwargs.get("otp_sent_at")
        otp_cutoff = float(otp_sent_at) - 2 if otp_sent_at else None
        start = time.time()
        while time.time() - start < timeout:
            try:
                r = requests.get(f"{self.api}/inbox",
                    params={"token": account.account_id},
                    proxies=self.proxy, timeout=10)
                for mail in sorted(r.json().get("emails", []), key=lambda x: x.get("date", 0), reverse=True):
                    mid = str(mail.get("id", ""))
                    if mid in seen:
                        continue
                    if otp_sent_at and mail.get("date", 0) / 1000 < otp_sent_at:
                        continue
                    seen.add(mid)
                    text = mail.get("subject", "") + " " + mail.get("body", "") + " " + mail.get("html", "")
                    if keyword and keyword.lower() not in text.lower():
                        continue
                    code = self._safe_extract(text, code_pattern)
                    if code:
                        return code
            except Exception:
                pass
            time.sleep(3)
        raise TimeoutError(f"等待验证码超时 ({timeout}s)")


class TempMailOrgBrowserMailbox(BaseMailbox):
    """temp-mail.org browser-backed mailbox via same-origin fetch in fingerprint browser."""

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        base_url: str = "https://web2.temp-mail.org",
        proxy: str = None,
        poll_interval: int = 5,
        bootstrap_timeout: int = 30,
        preferred_domains: Any = None,
        domain_pick_attempts: int = 1,
        preferred_domain_strict: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.proxy = proxy
        self.poll_interval = max(2, int(poll_interval or 5))
        self.bootstrap_timeout = max(10, int(bootstrap_timeout or 30))
        self.preferred_domains = self._normalize_domains(preferred_domains)
        self.domain_pick_attempts = max(1, int(domain_pick_attempts or 1))
        self.preferred_domain_strict = bool(preferred_domain_strict)
        self.playwright = None
        self.context = None
        self.page = None
        self.profile_dir = ""
        self._account = None
        self._owner_thread_id = None
        atexit.register(self.close)

    @staticmethod
    def _normalize_domains(raw: Any) -> list[str]:
        if not raw:
            return []
        if isinstance(raw, (list, tuple, set)):
            items = raw
        else:
            items = re.split(r"[\s,;]+", str(raw))
        seen = []
        for item in items:
            domain = str(item or "").strip().lower()
            if not domain or "@" in domain:
                continue
            if domain not in seen:
                seen.append(domain)
        return seen

    def close(self) -> None:
        page = getattr(self, "page", None)
        context = getattr(self, "context", None)
        playwright = getattr(self, "playwright", None)
        self.page = None
        self.context = None
        self.playwright = None
        self._owner_thread_id = None
        try:
            if page is not None:
                page.close()
        except Exception:
            pass
        try:
            if context is not None:
                context.close()
        except Exception:
            pass
        try:
            if playwright is not None:
                playwright.stop()
        except Exception:
            pass
        profile_dir = getattr(self, "profile_dir", "")
        self.profile_dir = ""
        if profile_dir:
            shutil.rmtree(profile_dir, ignore_errors=True)

    def _proxy_settings(self) -> dict | None:
        if not self.proxy:
            return None
        return {"server": self.proxy}

    def _ensure_page(self):
        current_thread_id = threading.get_ident()
        if self.page is not None and self._owner_thread_id == current_thread_id:
            return self.page
        if self.page is not None and self._owner_thread_id != current_thread_id:
            self._log(
                "[TempMailOrgBrowser] 检测到线程切换，重建 browser mailbox "
                f"(from={self._owner_thread_id} to={current_thread_id})"
            )
            self.close()
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("temp-mail.org browser mailbox 需要 playwright") from exc
        from platforms.chatgpt.playwright_display import (
            ensure_headed_display,
            fingerprint_context_overrides,
            filtered_fingerprint_launch_args,
            load_fingerprint_profile,
        )

        ensure_headed_display(self._log)
        fp_profile = load_fingerprint_profile() or {}
        launch_args = ["--disable-blink-features=AutomationControlled"]
        for arg in filtered_fingerprint_launch_args(fp_profile):
            if arg not in launch_args:
                launch_args.append(arg)
        self.profile_dir = tempfile.mkdtemp(prefix="temp-mail-org-browser-")
        self.playwright = sync_playwright().start()
        launch_kwargs = {
            "headless": False,
            "args": launch_args,
            "viewport": {"width": 1280, "height": 900},
            "locale": "en-US",
            "timezone_id": "America/New_York",
            "user_agent": self.USER_AGENT,
        }
        browser_path = str(fp_profile.get("browser_path") or "").strip()
        if browser_path:
            launch_kwargs["executable_path"] = browser_path
        context_overrides = fingerprint_context_overrides()
        if context_overrides.get("viewport"):
            launch_kwargs["viewport"] = context_overrides["viewport"]
        if context_overrides.get("locale"):
            launch_kwargs["locale"] = context_overrides["locale"]
        if context_overrides.get("timezone_id"):
            launch_kwargs["timezone_id"] = context_overrides["timezone_id"]
        user_agent = str(fp_profile.get("user_agent") or "").strip()
        if user_agent:
            launch_kwargs["user_agent"] = user_agent
        proxy_settings = self._proxy_settings()
        if proxy_settings:
            launch_kwargs["proxy"] = proxy_settings
        self.context = self.playwright.chromium.launch_persistent_context(
            self.profile_dir,
            **launch_kwargs,
        )
        self.page = self.context.pages[0] if self.context.pages else self.context.new_page()
        self.page.set_default_timeout(max(self.bootstrap_timeout * 1000, 30000))
        self._owner_thread_id = current_thread_id
        return self.page

    def _ensure_site_ready(self) -> None:
        page = self._ensure_page()
        page.goto(self.base_url, wait_until="domcontentloaded", timeout=max(self.bootstrap_timeout * 1000, 60000))
        deadline = time.time() + self.bootstrap_timeout
        while time.time() < deadline:
            try:
                body = (page.inner_text("body", timeout=1000) or "").strip().lower()
            except Exception:
                body = ""
            if body and "just a moment" not in body and "cloudflare" not in body and "verify you are human" not in body:
                return
            page.wait_for_timeout(1500)
        self._log("[TempMailOrgBrowser] site readiness wait hit timeout; continue with same-origin fetch")

    def _fetch_json(self, endpoint: str, *, method: str = "GET", headers: dict | None = None, body: dict | None = None) -> dict:
        page = self._ensure_page()
        self._ensure_site_ready()
        payload = {
            "url": endpoint if endpoint.startswith("http") else f"{self.base_url}{endpoint}",
            "method": method,
            "headers": headers or {},
            "body": body,
        }
        result = page.evaluate(
            """
            async ({ url, method, headers, body }) => {
              const init = { method, headers: headers || {} };
              if (body !== null && body !== undefined) {
                init.body = JSON.stringify(body);
                if (!init.headers["Content-Type"]) {
                  init.headers["Content-Type"] = "application/json";
                }
              }
              const resp = await fetch(url, init);
              const text = await resp.text();
              let data = null;
              try { data = JSON.parse(text); } catch {}
              return { status: resp.status, text, data };
            }
            """,
            payload,
        )
        status = int(result.get("status") or 0)
        if status >= 400:
            raise RuntimeError(f"temp-mail.org fetch failed: HTTP {status} {str(result.get('text') or '')[:300]}")
        data = result.get("data")
        if not isinstance(data, dict):
            raise RuntimeError(f"temp-mail.org returned non-json body: {str(result.get('text') or '')[:300]}")
        return data

    def get_email(self) -> MailboxAccount:
        attempts = self.domain_pick_attempts if self.preferred_domains else 1
        last_account = None
        seen_domains = []
        for attempt in range(1, attempts + 1):
            data = self._fetch_json("/mailbox", method="POST")
            email = str(data.get("mailbox") or data.get("email") or "").strip()
            token = str(data.get("token") or "").strip()
            if not email or not token:
                raise RuntimeError(f"temp-mail.org create mailbox returned incomplete payload: {data}")
            domain = email.split("@", 1)[1].strip().lower() if "@" in email else ""
            last_account = MailboxAccount(
                email=email,
                account_id=token,
                extra={"provider": "temp_mail_org_browser", "mailbox_token": token},
            )
            if domain:
                seen_domains.append(domain)
            if not self.preferred_domains:
                self._account = last_account
                self._log(f"[TempMailOrgBrowser] 生成邮箱: {email}")
                return self._account
            if domain in self.preferred_domains:
                self._account = last_account
                self._log(
                    "[TempMailOrgBrowser] 命中偏好域名: "
                    f"{email} (attempt={attempt}/{attempts})"
                )
                return self._account
            self._log(
                "[TempMailOrgBrowser] 跳过非偏好域名: "
                f"{email} (attempt={attempt}/{attempts}, preferred={','.join(self.preferred_domains)})"
            )
        if self.preferred_domain_strict:
            raise RuntimeError(
                "temp-mail.org 未在限定次数内命中偏好域名: "
                f"preferred={self.preferred_domains} seen={seen_domains}"
            )
        if last_account is None:
            raise RuntimeError("temp-mail.org create mailbox failed without any candidate")
        self._account = last_account
        self._log(
            "[TempMailOrgBrowser] 未命中偏好域名，回退使用最后候选: "
            f"{last_account.email} (preferred={','.join(self.preferred_domains)})"
        )
        return self._account

    def _list_messages(self, account: MailboxAccount) -> list[dict]:
        data = self._fetch_json(
            "/messages",
            headers={"Authorization": f"Bearer {account.account_id}", "Cache-Control": "no-cache"},
        )
        messages = data.get("messages")
        return messages if isinstance(messages, list) else []

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            messages = self._list_messages(account)
        except Exception:
            return set()
        ids = set()
        for msg in messages:
            mid = msg.get("id") or msg.get("_id") or msg.get("message_id") or msg.get("created_at")
            if mid:
                ids.add(str(mid))
        return ids

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        seen = set(before_ids or [])
        otp_sent_at = kwargs.get("otp_sent_at")
        exclude_codes = {str(code) for code in (kwargs.get("exclude_codes") or []) if code}
        start = time.time()
        while time.time() - start < timeout:
            try:
                messages = self._list_messages(account)
                for msg in messages:
                    mid = msg.get("id") or msg.get("_id") or msg.get("message_id") or msg.get("created_at")
                    mid = str(mid or "")
                    if not mid or mid in seen:
                        continue
                    created_at = msg.get("createdAt") or msg.get("created_at") or msg.get("date")
                    if otp_sent_at and created_at:
                        try:
                            mail_ts = float(created_at)
                            if mail_ts > 1e12:
                                mail_ts /= 1000.0
                            if mail_ts < float(otp_sent_at) - 2:
                                continue
                        except Exception:
                            pass
                    seen.add(mid)
                    text = " ".join(
                        str(msg.get(key) or "")
                        for key in ("subject", "text", "body", "html", "from", "from_email")
                    )
                    if keyword and keyword.lower() not in text.lower():
                        continue
                    code = self._safe_extract(text, code_pattern)
                    if code and code not in exclude_codes:
                        return code
            except Exception as exc:
                self._log(f"[TempMailOrgBrowser] 拉取验证码异常: {exc}")
            time.sleep(self.poll_interval)
        raise TimeoutError(f"等待验证码超时 ({timeout}s)")


class DuckMailMailbox(BaseMailbox):
    """DuckMail 自动生成邮箱（随机创建账号）"""

    def __init__(self, api_url: str = "https://www.duckmail.sbs",
                 provider_url: str = "https://api.duckmail.sbs",
                 bearer: str = "kevin273945",
                 proxy: str = None):
        self.api = api_url.rstrip("/")
        self.provider_url = provider_url
        self.bearer = bearer
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self._token = None
        self._address = None

    def _common_headers(self) -> dict:
        return {
            "authorization": f"Bearer {self.bearer}",
            "content-type": "application/json",
            "x-api-provider-base-url": self.provider_url,
        }

    def get_email(self) -> MailboxAccount:
        import requests, random, string
        username = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        password = "Test" + "".join(random.choices(string.digits, k=8)) + "!"
        domain = self.provider_url.replace("https://api.", "").replace("https://", "")
        address = f"{username}@{domain}"
        # 创建账号
        r = requests.post(f"{self.api}/api/mail?endpoint=%2Faccounts",
            json={"address": address, "password": password},
            headers=self._common_headers(), proxies=self.proxy, timeout=15)
        data = r.json()
        self._address = data.get("address", address)
        # 登录获取 token
        r2 = requests.post(f"{self.api}/api/mail?endpoint=%2Ftoken",
            json={"address": self._address, "password": password},
            headers=self._common_headers(), proxies=self.proxy, timeout=15)
        self._token = r2.json().get("token", "")
        return MailboxAccount(email=self._address, account_id=self._token)

    def get_current_ids(self, account: MailboxAccount) -> set:
        import requests
        try:
            r = requests.get(f"{self.api}/api/mail?endpoint=%2Fmessages%3Fpage%3D1",
                headers={"authorization": f"Bearer {account.account_id}",
                         "x-api-provider-base-url": self.provider_url},
                proxies=self.proxy, timeout=10)
            return {str(m["id"]) for m in r.json().get("hydra:member", [])}
        except Exception:
            return set()

    def wait_for_code(self, account: MailboxAccount, keyword: str = "",
                      timeout: int = 120, before_ids: set = None, code_pattern: str = None, **kwargs) -> str:
        import re, time, requests
        seen = set(before_ids or [])
        start = time.time()
        while time.time() - start < timeout:
            try:
                r = requests.get(f"{self.api}/api/mail?endpoint=%2Fmessages%3Fpage%3D1",
                    headers={"authorization": f"Bearer {account.account_id}",
                             "x-api-provider-base-url": self.provider_url},
                    proxies=self.proxy, timeout=10)
                msgs = r.json().get("hydra:member", [])
                for msg in msgs:
                    mid = str(msg.get("id") or msg.get("msgid") or "")
                    if mid in seen: continue
                    seen.add(mid)
                    # 请求邮件详情获取完整 text
                    try:
                        r2 = requests.get(f"{self.api}/api/mail?endpoint=%2Fmessages%2F{mid}",
                            headers={"authorization": f"Bearer {account.account_id}",
                                     "x-api-provider-base-url": self.provider_url},
                            proxies=self.proxy, timeout=10)
                        detail = r2.json()
                        body = str(detail.get("text") or "") + " " + str(detail.get("subject") or "")
                    except Exception:
                        body = str(msg.get("subject") or "")
                    body = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '', body)
                    code = self._safe_extract(body, code_pattern)
                    if code: return code
            except Exception:
                pass
            time.sleep(3)
        raise TimeoutError(f"等待验证码超时 ({timeout}s)")


class CFWorkerMailbox(BaseMailbox):
    """Cloudflare Worker 自建临时邮箱服务"""

    MODE_AUTO = "auto"
    MODE_WORKER = "worker"
    MODE_WRDO = "wrdo"

    def __init__(self, api_url: str, admin_token: str = "", domain: str = "",
                 fingerprint: str = "", proxy: str = None, mode: str = "auto"):
        self.api = api_url.rstrip("/")
        self.admin_token = admin_token
        self.domain = domain
        self.fingerprint = fingerprint
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self._token = None
        self.mode = str(mode or "auto").strip().lower() or self.MODE_AUTO
        self.resolved_mode = self.mode

    def _headers(self) -> dict:
        h = {
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "x-admin-auth": self.admin_token,
        }
        if self.fingerprint:
            h["x-fingerprint"] = self.fingerprint
        return h

    def _generate_local_part(self) -> str:
        import random, string
        # 避免纯数字开头，提高邮箱格式“像真人”的程度
        prefix = "".join(random.choices(string.ascii_lowercase, k=6))
        suffix = "".join(random.choices(string.digits, k=4))
        return f"{prefix}{suffix}"

    def get_email(self) -> MailboxAccount:
        import requests
        name = self._generate_local_part()
        worker_payload = {"enablePrefix": True, "name": name}
        if self.domain:
            worker_payload["domain"] = self.domain
        wrdo_email = f"{name}@{self.domain}" if self.domain else ""

        def _try_wrdo():
            headers = {"wrdo-api-key": self.admin_token, "Content-Type": "application/json"}
            response = requests.post(
                f"{self.api}/api/v1/email",
                json={"emailAddress": wrdo_email},
                headers=headers,
                proxies=self.proxy,
                timeout=15,
            )
            print(f"[CFWorker/wrdo] create status={response.status_code} resp={response.text[:200]}")
            if response.status_code not in (200, 201):
                raise RuntimeError(f"wrdo create failed: http {response.status_code} {response.text[:200]}")
            data = response.json()
            email = data.get("emailAddress") or data.get("email") or data.get("address") or ""
            if not email:
                raise RuntimeError(f"wrdo create failed: missing emailAddress in {data}")
            self.resolved_mode = self.MODE_WRDO
            self._token = ""
            print(f"[CFWorker/wrdo] 生成邮箱: {email}")
            return MailboxAccount(email=email, account_id=email, extra={"provider": "cfworker_wrdo"})

        def _try_worker():
            response = requests.post(
                f"{self.api}/admin/new_address",
                json=worker_payload,
                headers=self._headers(),
                proxies=self.proxy,
                timeout=15,
            )
            print(f"[CFWorker/worker] new_address status={response.status_code} resp={response.text[:200]}")
            if response.status_code not in (200, 201):
                raise RuntimeError(f"worker new_address failed: http {response.status_code} {response.text[:200]}")
            data = response.json()
            email = data.get("email", data.get("address", ""))
            token = data.get("token", data.get("jwt", ""))
            if not email:
                raise RuntimeError(f"worker new_address failed: missing email in {data}")
            self._token = token
            self.resolved_mode = self.MODE_WORKER
            print(f"[CFWorker/worker] 生成邮箱: {email} token={token[:40] if token else 'NONE'}...")
            return MailboxAccount(email=email, account_id=token, extra={"provider": "cfworker_worker"})

        if self.mode == self.MODE_WRDO:
            return _try_wrdo()
        if self.mode == self.MODE_WORKER:
            return _try_worker()

        try:
            return _try_wrdo()
        except Exception as wrdo_exc:
            self._log(f"[CFWorker] wrdo create 失败，回退 worker: {wrdo_exc}")
        return _try_worker()

    def _get_mails_wrdo(self, email: str) -> list:
        import requests
        headers = {"wrdo-api-key": self.admin_token}
        response = requests.get(
            f"{self.api}/api/v1/email/inbox",
            params={"emailAddress": email, "page": 1, "size": 20},
            headers=headers,
            proxies=self.proxy,
            timeout=10,
        )
        data = response.json()
        if isinstance(data, dict):
            return data.get("list", [])
        return data if isinstance(data, list) else []

    def _get_mails_worker(self, email: str) -> list:
        import requests
        response = requests.get(
            f"{self.api}/admin/mails",
            params={"limit": 20, "offset": 0, "address": email},
            headers=self._headers(),
            proxies=self.proxy,
            timeout=10,
        )
        data = response.json()
        return data.get("results", data) if isinstance(data, dict) else data

    def _get_mails(self, email: str) -> list:
        if self.resolved_mode == self.MODE_WRDO:
            return self._get_mails_wrdo(email)
        return self._get_mails_worker(email)

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            mails = self._get_mails(account.email)
            return {str(m.get("id", "")) for m in mails}
        except Exception:
            return set()

    def wait_for_code(self, account: MailboxAccount, keyword: str = "",
                      timeout: int = 120, before_ids: set = None, code_pattern: str = None, **kwargs) -> str:
        import re
        import time
        from datetime import datetime, timezone

        seen = set(before_ids or [])
        exclude_codes = set(kwargs.get("exclude_codes") or [])
        otp_sent_at = kwargs.get("otp_sent_at")
        otp_cutoff = float(otp_sent_at) - 2 if otp_sent_at else None
        start = time.time()
        while time.time() - start < timeout:
            try:
                mails = self._get_mails(account.email)
                for mail in sorted(mails, key=lambda x: x.get("id", 0), reverse=True):
                    mid = str(mail.get("id", "") or mail.get("messageId", ""))
                    if not mid or mid in seen:
                        continue

                    created_at = str(mail.get("created_at", "") or "").strip()
                    if otp_cutoff and created_at:
                        try:
                            mail_ts = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
                            if mail_ts < otp_cutoff:
                                self._log(f"[CFWorker] \u8df3\u8fc7\u65e7\u90ae\u4ef6 id={mid} created_at={created_at}")
                                continue
                        except Exception:
                            pass

                    # 仅在通过时间边界筛选后再标记为已处理，避免边界邮件被过早加入 seen。
                    seen.add(mid)

                    if self.resolved_mode == self.MODE_WRDO:
                        sender = " ".join(
                            str(mail.get(key, "") or "")
                            for key in ("from", "fromName", "sender")
                        ).strip()
                        content = " ".join(
                            str(mail.get(key, "") or "")
                            for key in ("subject", "text", "html")
                        ).strip()
                        search_text = f"{sender} {content}".strip()
                    else:
                        raw = str(mail.get("raw", ""))
                        subject = str(mail.get("subject", ""))
                        search_text = f"{subject} {self._decode_raw_content(raw)}".strip()
                    search_text = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '', search_text)
                    search_text = re.sub(r'm=\+\d+\.\d+', '', search_text)
                    search_text = re.sub(r'\bt=\d+\b', '', search_text)
                    if keyword and keyword.lower() not in search_text.lower():
                        continue

                    code = self._safe_extract(search_text, code_pattern)
                    if code and code in exclude_codes:
                        self._log(f"[CFWorker] \u8df3\u8fc7\u5df2\u7528\u9a8c\u8bc1\u7801 id={mid} created_at={created_at} code={code}")
                        continue
                    if code:
                        self._log(f"[CFWorker] \u547d\u4e2d\u65b0\u9a8c\u8bc1\u7801 id={mid} created_at={created_at} code={code}")
                        return code
            except Exception:
                pass
            time.sleep(3)
        raise TimeoutError(f"\u7b49\u5f85\u9a8c\u8bc1\u7801\u8d85\u65f6 ({timeout}s)")


class MoeMailMailbox(BaseMailbox):
    """MoeMail (sall.cc) 邮箱服务 - 自动注册账号并生成临时邮箱"""

    def __init__(self, api_url: str = "https://sall.cc", proxy: str = None):
        self.api = api_url.rstrip("/")
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self._session_token = None
        self._email = None

    def _register_and_login(self) -> str:
        import requests, random, string
        s = requests.Session()
        s.proxies = self.proxy
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
        s.headers.update({"user-agent": ua, "origin": self.api, "referer": f"{self.api}/zh-CN/login"})
        # 注册
        username = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        password = "Test" + "".join(random.choices(string.digits, k=8)) + "!"
        print(f"[MoeMail] 注册账号: {username} / {password}")
        r_reg = s.post(f"{self.api}/api/auth/register",
            json={"username": username, "password": password, "turnstileToken": ""},
            timeout=15)
        print(f"[MoeMail] 注册结果: {r_reg.status_code} {r_reg.text[:80]}")
        # 获取 CSRF
        csrf_r = s.get(f"{self.api}/api/auth/csrf", timeout=10)
        csrf = csrf_r.json().get("csrfToken", "")
        # 登录
        s.post(f"{self.api}/api/auth/callback/credentials",
            headers={"content-type": "application/x-www-form-urlencoded"},
            data=f"username={username}&password={password}&csrfToken={csrf}&redirect=false&callbackUrl={self.api}",
            allow_redirects=True, timeout=15)
        self._session = s
        for cookie in s.cookies:
            if "session-token" in cookie.name:
                self._session_token = cookie.value
                print(f"[MoeMail] 登录成功")
                return cookie.value
        print(f"[MoeMail] 登录失败，cookies: {[c.name for c in s.cookies]}")
        return ""

    def get_email(self) -> MailboxAccount:
        # 每次调用都重新注册新账号，保证邮箱唯一
        self._session_token = None
        self._register_and_login()
        import random, string
        name = "".join(random.choices(string.ascii_letters + string.digits, k=8))
        # 获取可用域名列表，随机选一个
        domain = "sall.cc"
        try:
            cfg_r = self._session.get(f"{self.api}/api/config", timeout=10)
            domains = [d.strip() for d in cfg_r.json().get("emailDomains", "sall.cc").split(",") if d.strip()]
            if domains:
                domain = random.choice(domains)
        except Exception:
            pass
        r = self._session.post(f"{self.api}/api/emails/generate",
            json={"name": name, "domain": domain, "expiryTime": 86400000},
            timeout=15)
        data = r.json()
        self._email = data.get("email", data.get("address", ""))
        email_id = data.get("id", "")
        print(f"[MoeMail] 生成邮箱: {self._email} id={email_id} domain={domain} status={r.status_code}")
        if not email_id:
            print(f"[MoeMail] 生成失败: {data}")
        if email_id:
            self._email_count = getattr(self, '_email_count', 0) + 1
        return MailboxAccount(email=self._email, account_id=str(email_id))

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            r = self._session.get(f"{self.api}/api/emails/{account.account_id}", timeout=10)
            return {str(m.get("id", "")) for m in r.json().get("messages", [])}
        except Exception:
            return set()

    def wait_for_code(self, account: MailboxAccount, keyword: str = "",
                      timeout: int = 120, before_ids: set = None,
                      code_pattern: str = None, **kwargs) -> str:
        import re, time
        seen = set(before_ids or [])
        start = time.time()
        pattern = re.compile(code_pattern) if code_pattern else None
        while time.time() - start < timeout:
            try:
                r = self._session.get(f"{self.api}/api/emails/{account.account_id}",
                    timeout=10)
                msgs = r.json().get("messages", [])
                for msg in msgs:
                    mid = str(msg.get("id", ""))
                    if not mid or mid in seen: continue
                    seen.add(mid)
                    body = str(msg.get("content") or msg.get("text") or msg.get("body") or msg.get("html") or "") + " " + str(msg.get("subject") or "")
                    body = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '', body)
                    code = self._safe_extract(body, code_pattern)
                    if code: return code
            except Exception:
                pass
            time.sleep(3)
        raise TimeoutError(f"等待验证码超时 ({timeout}s)")


class LuckMailMailbox(BaseMailbox):
    """LuckMail 混合模式：ChatGPT 走购买邮箱，其他平台走订单接码"""

    def __init__(self, base_url: str, api_key: str,
                 project_code: str = "", email_type: str = "",
                 domain: str = ""):
        if not base_url or not api_key:
            raise RuntimeError(
                "LuckMail 未配置：请在全局设置中填写 luckmail_base_url 和 luckmail_api_key"
            )
        from .luckmail import LuckMailClient
        self._client = LuckMailClient(
            base_url=base_url,
            api_key=api_key,
        )
        self._project_code = project_code
        self._email_type = email_type or None
        self._domain = domain or None
        self._order_no = None
        self._token = None
        self._email = None

    def _use_purchase_mode(self, account: MailboxAccount = None) -> bool:
        if account and account.account_id and str(account.account_id).startswith("tok_"):
            return True
        if self._token:
            return True
        return self._project_code == "openai"

    def _resolve_token(self, account: MailboxAccount = None) -> str:
        token = (account.account_id if account else "") or self._token
        if token:
            self._token = token
            return token

        email = (account.email if account else "") or self._email
        if not email:
            return ""

        try:
            purchases = self._client.user.get_purchases(
                page=1,
                page_size=100,
                keyword=email,
            )
        except Exception:
            return ""

        email_lower = str(email).strip().lower()
        for item in purchases.list:
            if str(item.email_address).strip().lower() == email_lower and item.token:
                self._token = item.token
                self._email = item.email_address
                return item.token
        return ""

    def _extract_code_from_token_mails(self, token: str, code_pattern: str = None,
                                       before_ids: set = None) -> Optional[str]:
        try:
            mail_list = self._client.user.get_token_mails(token)
        except Exception:
            return None

        seen = {str(mid) for mid in (before_ids or set())}
        for mail in mail_list.mails:
            message_id = str(mail.message_id or "")
            if message_id and message_id in seen:
                continue
            body = " ".join([
                str(mail.subject or ""),
                str(mail.body or ""),
                str(mail.html_body or ""),
            ])
            code = self._safe_extract(body, code_pattern)
            if code:
                return code
        return None

    def get_email(self) -> MailboxAccount:
        if not self._project_code:
            raise RuntimeError("LuckMail 未设置 project_code，无法创建邮箱")

        if self._use_purchase_mode():
            self._log(
                f"[LuckMail] 分支: ChatGPT + LuckMail -> 购买邮箱接口 "
                f"(project_code={self._project_code}, email_type={self._email_type or '-'}, domain={self._domain or '-'})"
            )
            try:
                result = self._client.user.purchase_emails(
                    project_code=self._project_code,
                    quantity=1,
                    email_type=self._email_type,
                    domain=self._domain,
                )
            except Exception as e:
                raise RuntimeError(f"LuckMail 购买邮箱失败: {e}") from e

            purchases = (result or {}).get("purchases") or []
            if not purchases:
                raise RuntimeError(f"LuckMail 购买邮箱返回为空: {result}")

            item = purchases[0]
            email = str(item.get("email_address") or "").strip()
            token = str(item.get("token") or "").strip()
            if not email or not token:
                raise RuntimeError(f"LuckMail 返回缺少 email/token: {item}")

            self._email = email
            self._token = token
            self._log(f"[LuckMail] 已购邮箱: {email}")
            if item.get("warranty_until"):
                self._log(f"[LuckMail] 质保到期: {item.get('warranty_until')}")
            return MailboxAccount(
                email=email,
                account_id=token,
                extra={
                    "provider": "luckmail",
                    "token": token,
                    "project_code": self._project_code,
                },
            )

        self._log(
            f"[LuckMail] 分支: 其他平台 + LuckMail -> 创建订单/订单接码 "
            f"(project_code={self._project_code}, email_type={self._email_type or '-'})"
        )
        try:
            body = {"project_code": self._project_code}
            if self._email_type:
                body["email_type"] = self._email_type
            order = self._client.user._sync_create_order(body)
        except Exception as e:
            raise RuntimeError(f"LuckMail 创建订单失败: {e}") from e
        self._order_no = order.order_no
        email = order.email_address
        self._email = email
        self._log(f"[LuckMail] 订单 {order.order_no} 分配邮箱: {email}")
        self._log(f"[LuckMail] 超时时间: {order.expired_at}")
        return MailboxAccount(email=email, account_id=order.order_no)

    def get_current_ids(self, account: MailboxAccount) -> set:
        if not self._use_purchase_mode(account):
            return set()
        token = self._resolve_token(account)
        if not token:
            return set()
        try:
            mail_list = self._client.user.get_token_mails(token)
            return {str(m.message_id) for m in (mail_list.mails or []) if m.message_id}
        except Exception:
            return set()

    def wait_for_code(self, account: MailboxAccount, keyword: str = "",
                      timeout: int = 120, before_ids: set = None,
                      code_pattern: str = None, **kwargs) -> str:
        if not self._use_purchase_mode(account):
            self._log("[LuckMail] 等验证码分支: 订单接码")
            order_no = account.account_id or self._order_no
            if not order_no:
                raise RuntimeError("LuckMail 未创建订单，无法等待验证码")

            def on_poll_order(result):
                self._log(f"[LuckMail] 轮询中... 状态: {result.status}")

            try:
                code_result = self._client.user._sync_wait_for_code(
                    order_no=order_no,
                    timeout=timeout,
                    interval=3.0,
                    on_poll=on_poll_order,
                )
            except Exception as e:
                raise TimeoutError(f"LuckMail 等待验证码失败: {e}") from e

            if code_result.status == "success" and code_result.verification_code:
                code = code_result.verification_code
                self._log(f"[LuckMail] 收到验证码: {code}")
                return code

            raise TimeoutError(
                f"LuckMail 等待验证码超时 ({timeout}s)，最终状态: {code_result.status}"
            )

        token = self._resolve_token(account)
        if not token:
            raise RuntimeError("LuckMail 未找到已购邮箱 Token，无法等待验证码")
        self._log("[LuckMail] 等验证码分支: 已购邮箱 Token 收码")

        def on_poll(result):
            self._log(f"[LuckMail] 轮询中... 新邮件: {'是' if result.has_new_mail else '否'}")

        try:
            code_result = self._client.user.wait_for_token_code(
                token=token,
                timeout=timeout,
                interval=3.0,
                on_poll=on_poll,
            )
        except Exception as e:
            raise TimeoutError(f"LuckMail 等待验证码失败: {e}") from e

        code = code_result.verification_code
        if not code and code_result.mail:
            code = self._safe_extract(json.dumps(code_result.mail, ensure_ascii=False), code_pattern)
        if not code and (code_result.has_new_mail or before_ids is None):
            code = self._extract_code_from_token_mails(token, code_pattern, before_ids=before_ids)

        if code:
            self._log(f"[LuckMail] 收到验证码: {code}")
            return code

        raise TimeoutError(
            f"LuckMail 等待验证码超时 ({timeout}s)，最终状态: has_new_mail={code_result.has_new_mail}"
        )


class FreemailMailbox(BaseMailbox):
    """
    Freemail 自建邮箱服务（基于 Cloudflare Worker）
    项目: https://github.com/idinging/freemail
    支持管理员令牌或账号密码两种认证方式
    """

    def __init__(self, api_url: str, admin_token: str = "",
                 username: str = "", password: str = "",
                 proxy: str = None):
        self.api = api_url.rstrip("/")
        self.admin_token = admin_token
        self.username = username
        self.password = password
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self._session = None
        self._email = None

    def _get_session(self):
        import requests
        s = requests.Session()
        s.proxies = self.proxy
        if self.admin_token:
            s.headers.update({"Authorization": f"Bearer {self.admin_token}"})
        elif self.username and self.password:
            s.post(f"{self.api}/api/login",
                json={"username": self.username, "password": self.password},
                timeout=15)
        self._session = s
        return s

    def get_email(self) -> MailboxAccount:
        if not self._session:
            self._get_session()
        import requests
        r = self._session.get(f"{self.api}/api/generate", timeout=15)
        data = r.json()
        email = data.get("email", "")
        self._email = email
        print(f"[Freemail] 生成邮箱: {email}")
        return MailboxAccount(email=email, account_id=email)

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            r = self._session.get(f"{self.api}/api/emails",
                params={"mailbox": account.email, "limit": 50}, timeout=10)
            return {str(m["id"]) for m in r.json() if "id" in m}
        except Exception:
            return set()

    def wait_for_code(self, account: MailboxAccount, keyword: str = "",
                      timeout: int = 120, before_ids: set = None, code_pattern: str = None, **kwargs) -> str:
        import re, time
        seen = set(before_ids or [])
        start = time.time()
        while time.time() - start < timeout:
            try:
                r = self._session.get(f"{self.api}/api/emails",
                    params={"mailbox": account.email, "limit": 20}, timeout=10)
                for msg in r.json():
                    mid = str(msg.get("id", ""))
                    if not mid or mid in seen: continue
                    seen.add(mid)
                    # 直接用 verification_code 字段
                    code = str(msg.get("verification_code") or "")
                    if code and code != "None":
                        return code
                    # 兜底：从 preview 提取
                    text = str(msg.get("preview", "")) + " " + str(msg.get("subject", ""))
                    code = self._safe_extract(text, code_pattern)
                    if code: return code
            except Exception:
                pass
            time.sleep(3)
        raise TimeoutError(f"等待验证码超时 ({timeout}s)")


class IMAPSecretMailbox(BaseMailbox):
    """从本地 JSON secret 读取 IMAP 配置，支持固定地址或 Gmail plus alias。"""

    def __init__(
        self,
        secret_path: str,
        target_email: str = "",
        alias_mode: str = "plus",
        alias_prefix: str = "aar",
        mailbox_name: str = "",
        from_filter: str = "",
        subject_filter: str = "",
        lookback_seconds: Any = 1800,
        interval: Any = 5,
        max_fetch: Any = 40,
        code_pattern: str = "",
        proxy: str = None,
        secret_payload: dict | None = None,
    ):
        self.secret_path = str(secret_path or "").strip()
        self.target_email = str(target_email or "").strip()
        self.alias_mode = str(alias_mode or "plus").strip().lower()
        self.alias_prefix = str(alias_prefix or "aar").strip() or "aar"
        self.mailbox_name = str(mailbox_name or "").strip()
        self.from_filter = str(from_filter or "").strip()
        self.subject_filter = str(subject_filter or "").strip()
        self.lookback_seconds = self._to_int(lookback_seconds, 1800)
        self.interval = self._to_int(interval, 5)
        self.max_fetch = self._to_int(max_fetch, 40)
        self.code_pattern = str(code_pattern or "").strip()
        self.proxy = str(proxy or "").strip()
        self.secret_payload = secret_payload
        self._secret = None

    @staticmethod
    def _to_int(value: Any, default: int) -> int:
        try:
            return int(value)
        except Exception:
            return default

    def _normalize_secret_payload(self, raw_secret: dict) -> dict:
        if not isinstance(raw_secret, dict):
            raise RuntimeError("IMAP mailbox secret 格式不正确")

        imap_cfg = raw_secret.get("imap")
        if isinstance(imap_cfg, dict):
            normalized = dict(raw_secret)
            normalized["imap"] = dict(imap_cfg)
            base_email = str(normalized.get("base_email") or "").strip()
            username = str(imap_cfg.get("username") or "").strip()
            if not base_email and username and "@" in username:
                normalized["base_email"] = username
            return normalized

        shared_imap = raw_secret.get("shared_imap")
        if isinstance(shared_imap, dict):
            base_email = str(shared_imap.get("base_email") or "").strip()
            password = str(shared_imap.get("password") or "").strip()
            host = str(shared_imap.get("host") or "").strip()
            missing = [
                field for field, value in (
                    ("base_email", base_email),
                    ("password", password),
                    ("host", host),
                ) if not value
            ]
            if missing:
                raise RuntimeError(f"shared_imap 配置缺少字段: {missing}")
            try:
                port = int(shared_imap.get("port") or 993)
            except Exception as exc:
                raise RuntimeError("shared_imap.port 不是有效端口") from exc
            mailbox_name = str(shared_imap.get("mailbox") or "Inbox").strip() or "Inbox"
            return {
                "base_email": base_email,
                "email_mode": str(shared_imap.get("email_mode") or "").strip(),
                "imap": {
                    "host": host,
                    "port": port,
                    "username": str(shared_imap.get("username") or base_email).strip() or base_email,
                    "app_password": password,
                    "ssl": True,
                    "mailbox": mailbox_name,
                },
            }

        raise RuntimeError("IMAP 配置缺失: 既没有 imap，也没有 shared_imap")

    def _load_secret(self) -> dict:
        if self._secret is not None:
            return self._secret
        from pathlib import Path

        if self.secret_payload is not None:
            secret = self.secret_payload
        else:
            if not self.secret_path:
                raise RuntimeError("IMAP mailbox 未配置 secret_path（imap_mailbox_secret_path）")
            path = Path(self.secret_path).expanduser()
            if not path.exists():
                raise RuntimeError(f"IMAP mailbox secret 不存在: {path}")
            secret = json.loads(path.read_text(encoding="utf-8"))
        secret = self._normalize_secret_payload(secret)
        imap_cfg = secret.get("imap")
        missing = [key for key in ("host", "port", "username", "app_password") if not imap_cfg.get(key)]
        if missing:
            raise RuntimeError(f"IMAP 配置缺少字段: {missing}")
        self._secret = secret
        return secret

    def _resolve_mailbox_name(self) -> str:
        secret = self._load_secret()
        imap_cfg = secret.get("imap") or {}
        return self.mailbox_name or str(imap_cfg.get("mailbox") or "INBOX")

    def _resolve_base_email(self) -> str:
        secret = self._load_secret()
        base_email = str(secret.get("base_email") or "").strip()
        if base_email:
            return base_email
        imap_cfg = secret.get("imap") or {}
        username = str(imap_cfg.get("username") or "").strip()
        if username and "@" in username:
            return username
        raise RuntimeError("IMAP secret 缺少 base_email，且 username 不是邮箱地址")

    def _generate_target_email(self) -> str:
        if self.target_email:
            return self.target_email
        if self.alias_mode in ("fixed", "base"):
            return self._resolve_base_email()
        base_email = self._resolve_base_email()
        if "@" not in base_email:
            raise RuntimeError(f"base_email 不是有效邮箱地址: {base_email}")
        local_part, domain = base_email.split("@", 1)
        import secrets
        import time

        suffix = f"{self.alias_prefix}{int(time.time())}{secrets.token_hex(2)}"
        secret = self._load_secret()
        secret_email_mode = str(secret.get("email_mode") or "").strip().lower()
        if self.alias_mode in {"append", "append_alias"} or secret_email_mode == "append_alias":
            return f"{local_part}{suffix}@{domain}"
        if self.alias_mode in {"catch_all"} or secret_email_mode == "catch_all":
            return f"{suffix}@{domain}"
        return f"{local_part}+{suffix}@{domain}"

    def _build_proxy_socket(self, host: str, port: int, timeout: int = 20):
        import socket
        from urllib.parse import urlparse

        if not self.proxy:
            return socket.create_connection((host, port), timeout=timeout)

        try:
            import socks
        except ImportError as exc:
            raise RuntimeError("IMAP 代理需要 PySocks，请先安装 pysocks") from exc

        parsed = urlparse(self.proxy)
        if not parsed.scheme or not parsed.hostname or not parsed.port:
            raise RuntimeError(f"不支持的 IMAP 代理格式: {self.proxy}")

        scheme = parsed.scheme.lower()
        proxy_types = {
            "socks5": socks.SOCKS5,
            "socks5h": socks.SOCKS5,
            "socks4": socks.SOCKS4,
            "http": socks.HTTP,
            "https": socks.HTTP,
        }
        proxy_type = proxy_types.get(scheme)
        if proxy_type is None:
            raise RuntimeError(f"IMAP 暂不支持该代理协议: {scheme}")

        proxy_socket = socks.socksocket()
        use_remote_dns = scheme.endswith("h") or scheme in {"http", "https"}

        proxy_socket.set_proxy(
            proxy_type=proxy_type,
            addr=parsed.hostname,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            rdns=use_remote_dns,
        )
        proxy_socket.settimeout(timeout)
        proxy_socket.connect((host, port))
        return proxy_socket

    def _connect_imap(self):
        import imaplib
        import ssl

        secret = self._load_secret()
        imap_cfg = secret["imap"]
        host = str(imap_cfg["host"])
        port = int(imap_cfg["port"])
        username = str(imap_cfg["username"])
        password = str(imap_cfg["app_password"])
        use_ssl = str(imap_cfg.get("ssl", "true")).lower() not in {"0", "false", "no"}

        if self.proxy:
            mailbox = self

            class ProxyIMAP4_SSL(imaplib.IMAP4_SSL):
                def open(self, host: str = "", port: int = imaplib.IMAP4_SSL_PORT, timeout: int = None):
                    self.host = host
                    self.port = port
                    raw_sock = mailbox._build_proxy_socket(host, port, timeout or 20)
                    self.sock = self.ssl_context.wrap_socket(raw_sock, server_hostname=host)
                    self.file = self.sock.makefile("rb")

            class ProxyIMAP4(imaplib.IMAP4):
                def open(self, host: str = "", port: int = imaplib.IMAP4_PORT, timeout: int = None):
                    self.host = host
                    self.port = port
                    self.sock = mailbox._build_proxy_socket(host, port, timeout or 20)
                    self.file = self.sock.makefile("rb")

            if use_ssl:
                context = ssl.create_default_context()
                client = ProxyIMAP4_SSL(host=host, port=port, ssl_context=context, timeout=20)
            else:
                client = ProxyIMAP4(host=host, port=port, timeout=20)
        else:
            if use_ssl:
                client = imaplib.IMAP4_SSL(host, port, timeout=20)
            else:
                client = imaplib.IMAP4(host, port, timeout=20)

        client.login(username, password)
        status, _ = client.select(self._resolve_mailbox_name())
        if status != "OK":
            raise RuntimeError(f"无法打开 IMAP mailbox: {self._resolve_mailbox_name()}")
        return client

    @staticmethod
    def _is_retryable_imap_error(exc: Exception) -> bool:
        import imaplib
        import ssl

        if isinstance(exc, (TimeoutError, EOFError, ssl.SSLError, imaplib.IMAP4.abort, imaplib.IMAP4.error, OSError)):
            text = str(exc or "").lower()
            return any(
                marker in text
                for marker in (
                    "ssl",
                    "eof",
                    "unexpected eof",
                    "timed out",
                    "connection reset",
                    "broken pipe",
                    "socket",
                    "abort",
                )
            )
        return False

    @staticmethod
    def _safe_logout_imap(client) -> None:
        if client is None:
            return
        try:
            client.logout()
        except Exception:
            pass

    @staticmethod
    def _decode_header_text(value: Optional[str]) -> str:
        from email.header import decode_header, make_header
        if not value:
            return ""
        try:
            return str(make_header(decode_header(value)))
        except Exception:
            return str(value)

    def _fetch_recent_uids(self, client) -> list[bytes]:
        status, data = client.uid("search", None, "ALL")
        if status == "OK" and data and data[0]:
            all_uids = data[0].split()
            if all_uids:
                return all_uids[-self.max_fetch:]

        status, data = client.uid("fetch", "1:*", "(UID)")
        if status != "OK" or not data:
            return []
        uids: list[int] = []
        for item in data:
            if not item:
                continue
            raw = item[0] if isinstance(item, tuple) else item
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="ignore")
            match = re.search(r"UID\s+(\d+)", str(raw))
            if not match:
                continue
            try:
                uids.append(int(match.group(1)))
            except ValueError:
                continue
        return [str(uid).encode() for uid in sorted(set(uids))[-self.max_fetch:]]

    def _fetch_message(self, client, uid: bytes):
        import email

        status, data = client.uid("fetch", uid, "(RFC822)")
        if status != "OK" or not data:
            return None
        for item in data:
            if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
                return email.message_from_bytes(item[1])
        return None

    def _message_datetime(self, message):
        import email
        from datetime import timezone

        raw_date = message.get("Date")
        if not raw_date:
            return None
        parsed = email.utils.parsedate_to_datetime(raw_date)
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _message_text_parts(self, message) -> list[str]:
        import html
        import re

        def html_to_text(raw_html: str) -> str:
            text = re.sub(r"(?is)<(script|style).*?>.*?</\\1>", " ", raw_html)
            text = re.sub(r"(?is)<br\\s*/?>", "\n", text)
            text = re.sub(r"(?is)</p\\s*>", "\n", text)
            text = re.sub(r"(?is)<[^>]+>", " ", text)
            text = html.unescape(text)
            return re.sub(r"\\s+", " ", text).strip()

        parts = []
        if message.is_multipart():
            for part in message.walk():
                disposition = str(part.get("Content-Disposition") or "").lower()
                if "attachment" in disposition:
                    continue
                content_type = part.get_content_type()
                if content_type not in ("text/plain", "text/html"):
                    continue
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                try:
                    text = payload.decode(charset, errors="ignore")
                except LookupError:
                    text = payload.decode("utf-8", errors="ignore")
                if content_type == "text/html":
                    text = html_to_text(text)
                parts.append(text)
        else:
            payload = message.get_payload(decode=True)
            if payload is not None:
                charset = message.get_content_charset() or "utf-8"
                try:
                    text = payload.decode(charset, errors="ignore")
                except LookupError:
                    text = payload.decode("utf-8", errors="ignore")
                if message.get_content_type() == "text/html":
                    text = html_to_text(text)
                parts.append(text)
        return parts

    def _target_matches(self, message, target_email: str) -> bool:
        target = str(target_email or "").lower()
        for key in ("To", "Delivered-To", "X-Original-To", "Cc"):
            value = self._decode_header_text(message.get(key))
            if target and target in value.lower():
                return True
        if not target:
            return False
        secret = self._load_secret()
        secret_email_mode = str(secret.get("email_mode") or "").strip().lower()
        if secret_email_mode in {"catch_all", "plus_alias", "append_alias"}:
            subject_value = self._decode_header_text(message.get("Subject"))
            if target in subject_value.lower():
                return True
            for part in self._message_text_parts(message):
                if target in part.lower():
                    return True
        return False

    def _find_code_in_message(self, message, target_email: str, code_pattern: str = "") -> Optional[str]:
        if not self._target_matches(message, target_email):
            return None
        from_value = self._decode_header_text(message.get("From"))
        subject_value = self._decode_header_text(message.get("Subject"))
        if self.from_filter and self.from_filter.lower() not in from_value.lower():
            return None
        if self.subject_filter and self.subject_filter.lower() not in subject_value.lower():
            return None

        candidates = [subject_value]
        candidates.extend(self._message_text_parts(message))
        for blob in candidates:
            code = self._safe_extract(blob, code_pattern or self.code_pattern or None)
            if code:
                return code
        return None

    def get_email(self) -> MailboxAccount:
        email = self._generate_target_email()
        self._log(f"[IMAP] 使用邮箱: {email}")
        return MailboxAccount(
            email=email,
            account_id=email,
            extra={"mailbox": self._resolve_mailbox_name()},
        )

    def get_current_ids(self, account: MailboxAccount) -> set:
        last_error = None
        for _ in range(3):
            client = None
            try:
                client = self._connect_imap()
                return {uid.decode() for uid in self._fetch_recent_uids(client)}
            except Exception as exc:
                last_error = exc
                if not self._is_retryable_imap_error(exc):
                    raise
                time.sleep(1)
            finally:
                self._safe_logout_imap(client)
        if last_error is not None:
            raise last_error
        return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        from datetime import datetime, timedelta, timezone

        seen = {str(item) for item in (before_ids or set())}
        exclude_codes = {str(code) for code in (kwargs.get("exclude_codes") or set()) if code}
        otp_sent_at = kwargs.get("otp_sent_at")
        lookback_seconds = kwargs.get("lookback_seconds")
        if lookback_seconds is None:
            effective_lookback = self.lookback_seconds
        else:
            effective_lookback = self._to_int(lookback_seconds, self.lookback_seconds)
        earliest = datetime.now(timezone.utc) - timedelta(seconds=effective_lookback)
        otp_cutoff = None
        if otp_sent_at:
            try:
                otp_cutoff = datetime.fromtimestamp(float(otp_sent_at) - 2, timezone.utc)
            except Exception:
                otp_cutoff = None
        client = None
        deadline = time.time() + timeout
        def scan_mailbox(active_client):
            if active_client is None:
                active_client = self._connect_imap()
            try:
                active_client.noop()
            except Exception:
                pass
            for uid in reversed(self._fetch_recent_uids(active_client)):
                uid_str = uid.decode()
                if uid_str in seen:
                    continue
                seen.add(uid_str)
                message = self._fetch_message(active_client, uid)
                if message is None:
                    continue
                msg_dt = self._message_datetime(message)
                if msg_dt is not None and msg_dt < earliest:
                    continue
                if otp_cutoff is not None and msg_dt is not None and msg_dt < otp_cutoff:
                    continue
                code = self._find_code_in_message(message, account.email, code_pattern or "")
                if code and code not in exclude_codes:
                    return active_client, code
            return active_client, None
        try:
            while time.time() <= deadline:
                try:
                    client, code = scan_mailbox(client)
                    if code:
                        return code
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    time.sleep(min(self.interval, max(0.5, remaining)))
                except Exception as exc:
                    if not self._is_retryable_imap_error(exc):
                        raise
                    self._safe_logout_imap(client)
                    client = None
                    time.sleep(min(self.interval, 2))
            self._safe_logout_imap(client)
            client = None
            client, code = scan_mailbox(client)
            if code:
                return code
            raise TimeoutError(f"等待验证码超时 ({timeout}s)")
        finally:
            self._safe_logout_imap(client)


class OutlookWebmailMailbox(BaseMailbox):
    """Outlook plus-alias mailbox backed by the existing webmail relay secret."""

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        pool_secret_path: str = "",
        login_slug: str = "",
        base_email: str = "",
        base_url: str = "https://ms.lqqq.cc",
        alias_mode: str = "plus",
        alias_prefix: str = "aar",
        target_email: str = "",
        poll_interval: Any = 5,
        timeout: Any = 60,
        proxy: str = "",
    ):
        self.pool_secret_path = str(pool_secret_path or "").strip()
        self.login_slug = str(login_slug or "").strip()
        self.base_email = str(base_email or "").strip()
        self.base_url = str(base_url or "https://ms.lqqq.cc").strip().rstrip("/")
        self.alias_mode = str(alias_mode or "plus").strip().lower()
        self.alias_prefix = str(alias_prefix or "aar").strip()
        self.target_email = str(target_email or "").strip()
        self.poll_interval = max(float(poll_interval or 5), 0.5)
        self.timeout = max(int(timeout or 60), 5)
        self.proxy = str(proxy or "").strip()

        self._load_secret_if_needed()
        if not self.login_slug or not self.base_email:
            raise RuntimeError(
                "Outlook webmail 未配置：请提供 outlook_webmail_pool_secret，"
                "或显式提供 outlook_webmail_login_slug/outlook_webmail_base_email"
            )

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.USER_AGENT})
        if self.proxy:
            self.session.proxies.update({"http": self.proxy, "https": self.proxy})

    def _fetch_text(self, url: str) -> str:
        last_error = None
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.text
        except Exception as exc:
            last_error = exc

        try:
            from curl_cffi import requests as curl_requests
        except Exception:
            raise last_error

        curl_kwargs = {
            "headers": {"User-Agent": self.USER_AGENT},
            "timeout": self.timeout,
        }
        if self.proxy:
            curl_kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}

        for impersonate in (None, "chrome136"):
            try:
                kwargs = dict(curl_kwargs)
                if impersonate:
                    kwargs["impersonate"] = impersonate
                response = curl_requests.get(url, **kwargs)
                if int(getattr(response, "status_code", 0) or 0) >= 400:
                    raise RuntimeError(f"http {response.status_code}")
                return response.text
            except Exception as exc:
                last_error = exc

        raise last_error

    def _load_secret_if_needed(self) -> None:
        if not self.pool_secret_path:
            return
        secret_file = Path(self.pool_secret_path).expanduser()
        if not secret_file.exists():
            raise RuntimeError(f"Outlook webmail secret 不存在: {secret_file}")
        payload = json.loads(secret_file.read_text(encoding="utf-8"))
        mailbox = payload.get("webmail_mailbox") or {}
        self.login_slug = self.login_slug or str(mailbox.get("login_slug") or "").strip()
        self.base_email = self.base_email or str(mailbox.get("base_email") or "").strip()
        secret_base_url = str(mailbox.get("base_url") or "").strip()
        if secret_base_url:
            self.base_url = secret_base_url.rstrip("/")

    def _list_url(self) -> str:
        return f"{self.base_url}/web/{self.login_slug.lstrip('/')}"

    def _detail_url(self, msg_id: int | str) -> str:
        return f"{self.base_url}/show_email/{self.login_slug.lstrip('/')}/INBOX/{msg_id}"

    def _generate_plus_alias(self) -> str:
        local, domain = self.base_email.split("@", 1)
        suffix = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
        if self.alias_prefix:
            suffix = f"{self.alias_prefix}{suffix}"
        return f"{local}+{suffix}@{domain}"

    def _generate_target_email(self) -> str:
        if self.target_email:
            return self.target_email
        if self.alias_mode in {"base", "fixed", "none"}:
            return self.base_email
        return self._generate_plus_alias()

    def _target_visible(self, blob: str, target_email: str) -> bool:
        text = str(blob or "").lower()
        target = str(target_email or "").lower().strip()
        if target and target in text:
            return True
        otp_markers = [
            "your chatgpt code is",
            "chatgpt code is",
            "chatgpt",
            "openai",
            "verification code",
            "验证码",
        ]
        return any(marker in text for marker in otp_markers)

    def list_messages(self) -> list[dict[str, Any]]:
        html = self._fetch_text(self._list_url())
        subjects = re.findall(r'<div class="email-subject">(.*?)</div>', html, flags=re.S)
        ids = re.findall(r'/show_email/[^"\']+/INBOX/(\d+)', html)
        dates = re.findall(r'<div class="email-date">(.*?)</div>', html, flags=re.S)
        items = []
        for index, msg_id in enumerate(ids):
            subject = re.sub(r"<[^>]+>", "", subjects[index]).strip() if index < len(subjects) else ""
            date_text = re.sub(r"<[^>]+>", "", dates[index]).strip() if index < len(dates) else ""
            timestamp = None
            if date_text:
                try:
                    timestamp = datetime.strptime(date_text, "%Y-%m-%d %H:%M:%S").timestamp()
                except Exception:
                    timestamp = None
            items.append({
                "id": int(msg_id),
                "subject": subject,
                "date_text": date_text,
                "timestamp": timestamp,
            })
        items.sort(key=lambda row: int(row["id"]), reverse=True)
        return items

    def recent_messages(
        self,
        baseline_id: Any,
        limit: int = 20,
        otp_sent_at: Any = None,
        slack_seconds: int = 5,
    ) -> list[dict[str, Any]]:
        baseline_num = int(str(baseline_id or 0))
        otp_cutoff = None
        if otp_sent_at:
            try:
                otp_cutoff = float(otp_sent_at) - max(int(slack_seconds or 0), 0)
            except Exception:
                otp_cutoff = None
        rows = []
        for row in self.list_messages():
            row_id = int(row["id"])
            row_ts = row.get("timestamp")
            if otp_cutoff is not None and row_ts is not None:
                if row_ts >= otp_cutoff:
                    rows.append(row)
                continue
            if row_id > baseline_num:
                rows.append(row)
        return rows[:limit]

    def detail(self, msg_id: int | str) -> dict[str, str]:
        html = self._fetch_text(self._detail_url(msg_id))
        match = re.search(r'<h2 class="detail-subject">(.*?)</h2>', html, flags=re.S)
        subject = re.sub(r"<[^>]+>", "", match.group(1)).strip() if match else ""
        return {"subject": subject, "text": html, "html": html}

    def get_email(self) -> MailboxAccount:
        email = self._generate_target_email()
        baseline_id = 0
        if self.target_email:
            self._log("[OutlookWebmail] 固定 target_email 路线跳过 baseline 预拉取")
        else:
            try:
                items = self.list_messages()
                baseline_id = int(items[0]["id"]) if items else 0
            except Exception as exc:
                self._log(f"[OutlookWebmail] 拉取 baseline 失败，继续创建邮箱: {exc}")
        self._log(f"[OutlookWebmail] 使用邮箱: {email}")
        return MailboxAccount(
            email=email,
            account_id=email,
            extra={
                "provider": "outlook_webmail",
                "base_email": self.base_email,
                "login_slug": self.login_slug,
                "baseline_id": baseline_id,
            },
        )

    def get_current_ids(self, account: MailboxAccount) -> set:
        return {str(row["id"]) for row in self.list_messages()}

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        exclude_codes = {str(code) for code in (kwargs.get("exclude_codes") or set()) if code}
        baseline_id = 0
        otp_sent_at = kwargs.get("otp_sent_at")
        if isinstance(account.extra, dict):
            baseline_id = int(str(account.extra.get("baseline_id") or 0))
        seen_ids = {str(item) for item in (before_ids or set())}
        deadline = time.time() + timeout

        while time.time() <= deadline:
            try:
                rows = self.recent_messages(
                    baseline_id,
                    limit=20,
                    otp_sent_at=otp_sent_at,
                )
            except Exception as exc:
                self._log(f"[OutlookWebmail] 拉取邮件列表失败，稍后重试: {exc}")
                time.sleep(self.poll_interval)
                continue
            for row in rows:
                msg_id = str(row["id"])
                if msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)
                subject = str(row.get("subject") or "")
                if self._target_visible(subject, account.email):
                    subject_code = self._safe_extract(subject, code_pattern)
                    if subject_code and subject_code not in exclude_codes:
                        self._log(f"[OutlookWebmail] 从标题收到验证码: {subject_code}")
                        return subject_code
                try:
                    detail = self.detail(msg_id)
                except Exception as exc:
                    self._log(f"[OutlookWebmail] 拉取邮件详情失败，跳过 {msg_id}: {exc}")
                    continue
                blob = "\n".join(
                    part for part in [
                        str(detail.get("subject") or ""),
                        str(detail.get("text") or ""),
                        str(detail.get("html") or ""),
                    ]
                    if part
                )
                if not self._target_visible(blob, account.email):
                    continue
                code = self._safe_extract(blob, code_pattern)
                if code and code not in exclude_codes:
                    self._log(f"[OutlookWebmail] 收到验证码: {code}")
                    return code
            time.sleep(self.poll_interval)

        raise TimeoutError(f"等待验证码超时 ({timeout}s)")


class OutlookApiMailbox(BaseMailbox):
    """Outlook API mailbox provider borrowed from the peer Node workflow.

    支持两种接入面：
    1. external: 通过 X-API-Key 调 /api/external/*
    2. internal: 通过密码登录 /login 后调 /api/*

    目标不是替换现有 OAuth 主线，而是补一个更稳的 Outlook 邮箱池来源。
    """

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        base_url: str = "",
        auth_mode: str = "auto",
        api_key: str = "",
        login_password: str = "",
        group_id: Any = None,
        address_mode: str = "aliases-first",
        address_pool: Any = None,
        folder: str = "all",
        fetch_top: Any = 10,
        disable_used_accounts: bool = True,
        disable_used_status: str = "inactive",
        used_addresses_path: str = "",
        poll_interval: Any = 5,
        timeout: Any = 60,
        proxy: str = "",
    ):
        self.base_url = str(base_url or "").strip().rstrip("/")
        self.auth_mode = str(auth_mode or "auto").strip().lower() or "auto"
        self.api_key = str(api_key or "").strip()
        self.login_password = str(login_password or "").strip()
        self.group_id = None if group_id in (None, "") else str(group_id).strip()
        self.address_mode = str(address_mode or "aliases-first").strip().lower()
        self.address_pool = [
            item.strip()
            for item in re.split(r"[\r\n,]+", str(address_pool or ""))
            if str(item or "").strip()
        ]
        self.folder = str(folder or "all").strip().lower() or "all"
        self.fetch_top = max(1, min(50, int(fetch_top or 10)))
        self.disable_used_accounts = bool(disable_used_accounts)
        self.disable_used_status = str(disable_used_status or "inactive").strip() or "inactive"
        self.used_addresses_path = str(used_addresses_path or "").strip()
        self.poll_interval = max(float(poll_interval or 5), 1.0)
        self.timeout = max(int(timeout or 60), 5)
        self.proxy = str(proxy or "").strip()

        if self.auth_mode not in {"auto", "external", "internal"}:
            raise RuntimeError(f"Unsupported outlook_email_auth_mode: {self.auth_mode}")
        if self.address_mode not in {"aliases-first", "primary-first", "aliases-only", "primary-only"}:
            raise RuntimeError(f"Unsupported outlook_email_address_mode: {self.address_mode}")
        if not self.base_url:
            raise RuntimeError("Outlook API mailbox 未配置 outlook_email_base_url")

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.USER_AGENT})
        if self.proxy:
            self.session.proxies.update({"http": self.proxy, "https": self.proxy})
        self.internal_session_ready = False
        self.used_codes: set[str] = set()
        self.used_message_signatures: set[str] = set()
        self.used_address_map = load_used_address_map(self.used_addresses_path)
        self.current_reservation: Optional[dict[str, Any]] = None
        atexit.register(self.close)

    def close(self) -> None:
        self._disable_reserved_account_if_needed()
        try:
            self.session.close()
        except Exception:
            pass

    def _build_url(self, path: str, query: Optional[dict[str, Any]] = None) -> str:
        url = f"{self.base_url}/{str(path or '').lstrip('/')}"
        if not query:
            return url
        filtered = {
            key: value
            for key, value in query.items()
            if value not in (None, "")
        }
        if not filtered:
            return url
        from urllib.parse import urlencode

        return f"{url}?{urlencode(filtered)}"

    def _fetch_json(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        payload: Optional[dict[str, Any]] = None,
    ) -> Any:
        response = self.session.request(
            method,
            url,
            headers=headers or {},
            json=payload,
            timeout=self.timeout,
            allow_redirects=False,
        )
        text = response.text or ""
        parsed: Any = None
        if text.strip():
            try:
                parsed = response.json()
            except Exception:
                parsed = None

        if response.status_code >= 400:
            if isinstance(parsed, dict):
                message = parsed.get("error") or parsed.get("message")
            else:
                message = ""
            raise RuntimeError(
                message or f"Outlook API request failed: HTTP {response.status_code}"
            )

        if isinstance(parsed, dict) and parsed.get("success") is False:
            raise RuntimeError(
                str(parsed.get("error") or parsed.get("message") or "Outlook API request failed")
            )
        return parsed if parsed is not None else {}

    def _ensure_internal_session(self) -> None:
        if self.internal_session_ready:
            return
        if not self.login_password:
            raise RuntimeError("outlook_email_login_password 未配置，无法走 internal 模式")

        payload = self._fetch_json(
            "POST",
            self._build_url("/login"),
            payload={"password": self.login_password},
        )
        if isinstance(payload, dict) and payload.get("success") is False:
            raise RuntimeError(str(payload.get("error") or "Outlook API login failed"))
        if not self.session.cookies:
            raise RuntimeError("Outlook API login succeeded but returned no session cookie")
        self.internal_session_ready = True

    def _resolve_auth_order(self) -> list[str]:
        if self.auth_mode == "external":
            return ["external"]
        if self.auth_mode == "internal":
            return ["internal"]

        modes = []
        if self.api_key:
            modes.append("external")
        if self.login_password:
            modes.append("internal")
        if not modes:
            raise RuntimeError(
                "Outlook API mailbox 至少需要配置 outlook_email_api_key 或 outlook_email_login_password"
            )
        return modes

    def _request_external(self, path: str, query: Optional[dict[str, Any]] = None) -> Any:
        if not self.api_key:
            raise RuntimeError("outlook_email_api_key 未配置，无法走 external 模式")
        return self._fetch_json(
            "GET",
            self._build_url(path, query),
            headers={"X-API-Key": self.api_key},
        )

    def _request_internal(
        self,
        method: str,
        path: str,
        query: Optional[dict[str, Any]] = None,
        payload: Optional[dict[str, Any]] = None,
    ) -> Any:
        self._ensure_internal_session()
        return self._fetch_json(method, self._build_url(path, query), payload=payload)

    def _request_json(
        self,
        *,
        external_path: str,
        internal_path: str,
        query: Optional[dict[str, Any]] = None,
    ) -> Any:
        last_error = None
        for mode in self._resolve_auth_order():
            try:
                if mode == "external":
                    return self._request_external(external_path, query)
                return self._request_internal("GET", internal_path, query)
            except Exception as exc:
                last_error = exc
                self._log(f"[OutlookApi] {mode} 模式失败，尝试回退: {exc}")
        raise last_error or RuntimeError("Outlook API request failed")

    def _fetch_address_candidates(self) -> list[dict[str, Any]]:
        payload = self._request_json(
            external_path="/api/external/accounts",
            internal_path="/api/accounts",
            query={"group_id": self.group_id} if self.group_id else {},
        )
        accounts = normalize_outlook_api_accounts(payload)
        active_accounts = []
        for account in accounts:
            status = str(account.get("status") or "active").strip().lower()
            if status and status != "active":
                continue
            active_accounts.append(account)

        def account_sort_key(account: dict[str, Any]) -> int:
            for key in (
                "last_refresh_at",
                "lastRefreshAt",
                "updated_at",
                "updatedAt",
                "created_at",
                "createdAt",
            ):
                timestamp, _precision = parse_timestamp_info(account.get(key))
                if timestamp:
                    return timestamp
            return 0

        active_accounts.sort(key=account_sort_key)
        seen = set()
        alias_candidates: list[dict[str, Any]] = []
        primary_candidates: list[dict[str, Any]] = []

        def push_candidate(
            target: list[dict[str, Any]],
            *,
            address: str,
            resolved_email: str,
            kind: str,
            account_id: Any,
        ) -> None:
            normalized = str(address or "").strip()
            if not normalized:
                return
            lowered = normalized.lower()
            if lowered in seen:
                return
            seen.add(lowered)
            target.append(
                {
                    "address": normalized,
                    "resolved_email": str(resolved_email or normalized).strip() or normalized,
                    "kind": kind,
                    "account_id": account_id,
                }
            )

        for account in active_accounts:
            resolved_email = str(
                account.get("email")
                or account.get("address")
                or ""
            ).strip()
            account_id = account.get("id")
            aliases = account.get("aliases") or []
            if isinstance(aliases, list):
                for alias_item in aliases:
                    if isinstance(alias_item, dict):
                        alias = str(
                            alias_item.get("email")
                            or alias_item.get("address")
                            or alias_item.get("alias")
                            or ""
                        ).strip()
                    else:
                        alias = str(alias_item or "").strip()
                    push_candidate(
                        alias_candidates,
                        address=alias,
                        resolved_email=resolved_email or alias,
                        kind="alias",
                        account_id=account_id,
                    )
            push_candidate(
                primary_candidates,
                address=resolved_email,
                resolved_email=resolved_email,
                kind="primary",
                account_id=account_id,
            )

        if self.address_mode == "aliases-only":
            return alias_candidates
        if self.address_mode == "primary-only":
            return primary_candidates
        if self.address_mode == "primary-first":
            return primary_candidates + alias_candidates
        return alias_candidates + primary_candidates

    def _fetch_messages(self, email: str) -> list[dict[str, Any]]:
        payload = self._request_json(
            external_path="/api/external/emails",
            internal_path=f"/api/emails/{quote(str(email or '').strip())}",
            query={
                "email": str(email or "").strip(),
                "folder": self.folder,
                "top": self.fetch_top,
            },
        )
        return normalize_outlook_api_messages(payload)

    def _remember_used_address(self, candidate: dict[str, Any]) -> None:
        if not self.disable_used_accounts or not self.used_addresses_path:
            return
        address = str(candidate.get("address") or "").strip()
        if not address:
            return
        self.used_address_map[address.lower()] = {
            "address": address,
            "account_id": candidate.get("account_id"),
            "disabled_at": datetime.now(timezone.utc).isoformat(),
            "source": "reserved",
        }
        save_used_address_map(self.used_addresses_path, self.used_address_map)

    def _disable_reserved_account_if_needed(self) -> None:
        if not self.disable_used_accounts:
            return
        reservation = self.current_reservation
        self.current_reservation = None
        if not reservation:
            return
        account_id = reservation.get("account_id")
        if not account_id:
            return
        if not self.login_password:
            self._log(
                "[OutlookApi] 跳过远端 disable：未配置 outlook_email_login_password"
            )
            return
        try:
            self._request_internal(
                "PUT",
                f"/api/accounts/{account_id}",
                payload={"status": self.disable_used_status},
            )
            self._log(
                f"[OutlookApi] 已在远端邮箱池禁用 {reservation.get('address')} -> {self.disable_used_status}"
            )
        except Exception as exc:
            self._log(f"[OutlookApi] 远端禁用已用邮箱失败: {exc}")

    def _is_address_unavailable(self, address: str) -> bool:
        normalized = str(address or "").strip().lower()
        if not normalized:
            return True
        with outlook_api_claimed_addresses_lock:
            return (
                normalized in outlook_api_claimed_addresses
                or normalized in self.used_address_map
            )

    def _reserve_address(self, address: str) -> None:
        normalized = str(address or "").strip().lower()
        if not normalized:
            raise RuntimeError("Outlook API candidate address is empty")
        with outlook_api_claimed_addresses_lock:
            if normalized in outlook_api_claimed_addresses:
                raise RuntimeError(f"Outlook API address already reserved: {address}")
            outlook_api_claimed_addresses.add(normalized)

    def get_email(self) -> MailboxAccount:
        if self.address_pool:
            candidates = [
                {
                    "address": item,
                    "resolved_email": item,
                    "kind": "pool",
                    "account_id": None,
                }
                for item in self.address_pool
            ]
        else:
            candidates = self._fetch_address_candidates()

        selected = None
        for candidate in candidates:
            if self._is_address_unavailable(candidate.get("address", "")):
                continue
            selected = candidate
            break
        if selected is None:
            raise RuntimeError("Outlook API 没有可用邮箱地址（都已保留或已标记已用）")

        self._reserve_address(selected["address"])
        self.current_reservation = dict(selected)
        self._remember_used_address(selected)
        resolved_email = str(selected.get("resolved_email") or selected["address"]).strip()
        self._log(
            "[OutlookApi] 预留邮箱: "
            f"{selected['address']}"
            + (
                f" (resolved={resolved_email})"
                if resolved_email != selected["address"]
                else ""
            )
        )
        return MailboxAccount(
            email=str(selected["address"]).strip(),
            account_id=str(selected.get("account_id") or resolved_email or selected["address"]),
            extra={
                "provider": "outlookapi",
                "resolved_email": resolved_email,
                "mailbox_kind": selected.get("kind") or "primary",
                "outlook_api_account_id": selected.get("account_id"),
            },
        )

    def _message_signature(self, message: dict[str, Any]) -> str:
        return "|".join(
            [
                str(message.get("id") or ""),
                str(message.get("subject") or ""),
                str(message.get("from") or message.get("sender") or ""),
                str(
                    message.get("date")
                    or message.get("received_at")
                    or message.get("receivedAt")
                    or message.get("created_at")
                    or message.get("createdAt")
                    or ""
                ),
                str(
                    message.get("body_preview")
                    or message.get("bodyPreview")
                    or message.get("preview")
                    or message.get("snippet")
                    or ""
                ),
                str(message.get("folder") or ""),
            ]
        )

    def _message_search_text(self, message: dict[str, Any]) -> str:
        return "\n".join(
            [
                str(message.get("subject") or ""),
                str(message.get("from") or message.get("sender") or ""),
                str(
                    message.get("body_preview")
                    or message.get("bodyPreview")
                    or message.get("preview")
                    or message.get("snippet")
                    or message.get("body")
                    or message.get("text")
                    or ""
                ),
            ]
        ).strip()

    def _extract_code_from_message(
        self,
        message: dict[str, Any],
        code_pattern: Optional[str] = None,
    ) -> Optional[str]:
        return self._safe_extract(self._message_search_text(message), code_pattern)

    def _looks_like_openai_mail(self, message: dict[str, Any]) -> bool:
        from_text = str(message.get("from") or message.get("sender") or "").lower()
        if "openai" in from_text:
            return True
        search_text = self._message_search_text(message).lower()
        return any(keyword in search_text for keyword in OUTLOOK_API_OPENAI_KEYWORDS)

    def _is_message_fresh(self, message: dict[str, Any], otp_sent_at: Any) -> bool:
        if not otp_sent_at:
            return True
        raw_time = (
            message.get("date")
            or message.get("received_at")
            or message.get("receivedAt")
            or message.get("created_at")
            or message.get("createdAt")
            or message.get("timestamp")
        )
        timestamp_ms, precision_ms = parse_timestamp_info(raw_time)
        if not timestamp_ms:
            return True
        cutoff_ms = int(float(otp_sent_at) * 1000)
        slack_ms = max(int(precision_ms or 0), 2000)
        return timestamp_ms + slack_ms >= cutoff_ms

    def get_current_ids(self, account: MailboxAccount) -> set:
        try:
            messages = self._fetch_messages(account.email)
        except Exception:
            return set()
        result = set()
        for message in messages:
            message_id = str(message.get("id") or "").strip()
            if message_id:
                result.add(message_id)
                continue
            result.add(self._message_signature(message))
        return result

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        exclude_codes = {
            str(code) for code in (kwargs.get("exclude_codes") or set()) if code
        }
        otp_sent_at = kwargs.get("otp_sent_at")
        deadline = time.time() + timeout
        seen_markers = {str(item) for item in (before_ids or set()) if item}

        def pick_candidate(messages: list[dict[str, Any]]) -> Optional[tuple[str, str, str]]:
            preferred: list[tuple[str, str, str]] = []
            fallback: list[tuple[str, str, str]] = []
            for message in messages:
                message_id = str(message.get("id") or "").strip()
                signature = self._message_signature(message)
                if message_id and message_id in seen_markers:
                    continue
                if signature in seen_markers or signature in self.used_message_signatures:
                    continue
                if not self._is_message_fresh(message, otp_sent_at):
                    continue

                search_text = self._message_search_text(message)
                if keyword and keyword.lower() not in search_text.lower():
                    continue
                code = self._extract_code_from_message(message, code_pattern)
                if not code or code in exclude_codes or code in self.used_codes:
                    continue

                candidate = (message_id, signature, code)
                if self._looks_like_openai_mail(message):
                    preferred.append(candidate)
                else:
                    fallback.append(candidate)
            return preferred[0] if preferred else (fallback[0] if fallback else None)

        while time.time() <= deadline:
            messages = self._fetch_messages(account.email)
            candidate = pick_candidate(messages)
            if candidate:
                message_id, signature, code = candidate
                if message_id:
                    seen_markers.add(message_id)
                seen_markers.add(signature)
                self.used_codes.add(code)
                self.used_message_signatures.add(signature)
                self._log(f"[OutlookApi] 收到验证码: {code}")
                return code
            time.sleep(self.poll_interval)
        raise TimeoutError(f"等待验证码超时 ({timeout}s)")


class OutlookOfficialWebMailbox(BaseMailbox):
    """Official Outlook web mailbox with real alias creation and inbox polling."""

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        pool_secret_path: str = "",
        login_slug: str = "",
        base_email: str = "",
        alias_mode: str = "official",
        alias_prefix: str = "aar",
        target_email: str = "",
        proof_pool_secret_path: str = "",
        proof_imap_secret_path: str = "",
        proof_target_email: str = "",
        proof_alias_mode: str = "base",
        poll_interval: Any = 5,
        timeout: Any = 60,
        disable_selenium: bool = False,
        proxy: str = "",
    ):
        self.pool_secret_path = str(pool_secret_path or "").strip()
        self.login_slug = str(login_slug or "").strip()
        self.base_email = str(base_email or "").strip()
        self.alias_mode = str(alias_mode or "official").strip().lower()
        self.alias_prefix = str(alias_prefix or "aar").strip() or "aar"
        self.target_email = str(target_email or "").strip()
        self.proof_pool_secret_path = str(proof_pool_secret_path or "").strip()
        self.proof_imap_secret_path = str(proof_imap_secret_path or "").strip()
        self.proof_target_email = str(proof_target_email or "").strip()
        self.proof_alias_mode = str(proof_alias_mode or "base").strip().lower() or "base"
        self.poll_interval = max(float(poll_interval or 5), 0.5)
        self.timeout = max(int(timeout or 60), 5)
        self.disable_selenium = bool(disable_selenium)
        self.proxy = str(proxy or "").strip()

        self.login_email = ""
        self.login_password = ""
        self.playwright = None
        self.context = None
        self.page = None
        self._playwright_owner_thread_id = None
        self._playwright_executor: Optional[ThreadPoolExecutor] = None
        self._playwright_seeded_from_selenium = False
        self.driver = None
        self.display = ""
        self.xvfb_proc = None
        self.profile_dir = ""
        self.driver_profile_dir = ""
        self.cached_messages: dict[str, dict[str, str]] = {}
        self.last_refresh_ts = 0.0
        self.refresh_interval_seconds = max(self.poll_interval, 5.0)
        self.proof_mailbox = None

        self._load_secret_if_needed()
        self._resolve_login_credentials()
        if not self.base_email:
            self.base_email = self.login_email
        if not self.login_email or not self.login_password:
            raise RuntimeError(
                "Outlook official web 未配置可用登录凭据："
                "请提供 outlook_official_login_slug，"
                "或提供可推导出 base_email----password 的 outlook_official_pool_secret"
            )
        atexit.register(self.close)

    def close(self) -> None:
        proof_mailbox = self.proof_mailbox
        self.proof_mailbox = None
        if proof_mailbox is not None:
            close_fn = getattr(proof_mailbox, "close", None)
            if callable(close_fn):
                try:
                    close_fn()
                except Exception:
                    pass
        self._shutdown_playwright_executor()
        driver = self.driver
        self.driver = None
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
        if self.xvfb_proc is not None:
            try:
                if self.xvfb_proc.poll() is None:
                    self.xvfb_proc.terminate()
                    self.xvfb_proc.wait(timeout=3)
            except Exception:
                try:
                    self.xvfb_proc.kill()
                except Exception:
                    pass
            self.xvfb_proc = None
        if self.profile_dir:
            shutil.rmtree(self.profile_dir, ignore_errors=True)
            self.profile_dir = ""
        if self.driver_profile_dir:
            shutil.rmtree(self.driver_profile_dir, ignore_errors=True)
            self.driver_profile_dir = ""

    def _load_secret_if_needed(self) -> None:
        if not self.pool_secret_path:
            return
        secret_file = Path(self.pool_secret_path).expanduser()
        if not secret_file.exists():
            raise RuntimeError(f"Outlook official web secret 不存在: {secret_file}")
        payload = json.loads(secret_file.read_text(encoding="utf-8"))
        webmail = payload.get("webmail_mailbox") if isinstance(payload, dict) else {}
        if not isinstance(webmail, dict):
            webmail = {}
        mother = payload.get("mother") if isinstance(payload, dict) else {}
        if not isinstance(mother, dict):
            mother = {}

        self.base_email = self.base_email or str(webmail.get("base_email") or "").strip() or str(
            mother.get("email") or ""
        ).strip()
        if not self.login_slug:
            official_slug = str(webmail.get("official_login_slug") or "").strip()
            if official_slug:
                self.login_slug = official_slug
        if not self.login_slug:
            webmail_login_slug = str(webmail.get("login_slug") or "").strip()
            if webmail_login_slug:
                self.login_slug = webmail_login_slug
        if not self.login_slug:
            self.login_slug = self._derive_login_slug_from_pool_secret(payload)

    def _derive_login_slug_from_pool_secret(self, payload: Any) -> str:
        if not isinstance(payload, dict):
            return ""
        base_email = str(self.base_email or "").strip().lower()
        mother = payload.get("mother") or {}
        if isinstance(mother, dict):
            mother_email = str(mother.get("email") or "").strip()
            mother_password = str(mother.get("password") or "").strip()
            if mother_email and mother_password:
                if not base_email or mother_email.lower() == base_email:
                    return f"{mother_email}----{mother_password}"

        for child in payload.get("children") or []:
            if not isinstance(child, dict):
                continue
            child_slug = str(child.get("mailbox_login_slug") or "").strip()
            if "----" not in child_slug:
                continue
            slug_email = child_slug.split("----", 1)[0].strip().lower()
            child_base = str(child.get("mailbox_base_email") or "").strip().lower()
            if not base_email or slug_email == base_email or child_base == base_email:
                return child_slug
        return ""

    def _resolve_login_credentials(self) -> None:
        if "----" not in self.login_slug:
            return
        email, password = (self.login_slug.split("----", 1) + [""])[:2]
        self.login_email = str(email or "").strip()
        self.login_password = str(password or "").strip()

    def _playwright_proxy_settings(self) -> Optional[dict[str, str]]:
        if not self.proxy:
            return None
        parsed = urlsplit(self.proxy)
        if not parsed.scheme or not parsed.hostname or not parsed.port:
            raise RuntimeError(f"不支持的 Outlook official proxy 格式: {self.proxy}")
        result = {"server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"}
        if parsed.username:
            result["username"] = parsed.username
        if parsed.password:
            result["password"] = parsed.password
        return result

    def _selenium_imports(self):
        try:
            from selenium import webdriver  # type: ignore
            from selenium.webdriver.chrome.options import Options  # type: ignore
            from selenium.webdriver.chrome.service import Service  # type: ignore
            from selenium.webdriver.common.by import By  # type: ignore
            from selenium.webdriver.support import expected_conditions as EC  # type: ignore
            from selenium.webdriver.support.ui import WebDriverWait  # type: ignore
            from selenium.common.exceptions import TimeoutException  # type: ignore
            return webdriver, Options, Service, By, EC, WebDriverWait, TimeoutException
        except ImportError:
            candidate_roots = [
                str(Path.home() / "miniconda3" / "lib" / "python*" / "site-packages"),
                "/home/leadtek/Downloads/codex-account/chatgpt_register/.venv/lib/python*/site-packages",
                "/home/leadtek/Downloads/codex-account/chatgpt_register/.venv/lib64/python*/site-packages",
            ]
            for pattern in candidate_roots:
                for site in glob.glob(pattern):
                    if site not in sys.path:
                        sys.path.insert(0, site)
            from selenium import webdriver  # type: ignore
            from selenium.webdriver.chrome.options import Options  # type: ignore
            from selenium.webdriver.chrome.service import Service  # type: ignore
            from selenium.webdriver.common.by import By  # type: ignore
            from selenium.webdriver.support import expected_conditions as EC  # type: ignore
            from selenium.webdriver.support.ui import WebDriverWait  # type: ignore
            from selenium.common.exceptions import TimeoutException  # type: ignore
            return webdriver, Options, Service, By, EC, WebDriverWait, TimeoutException

    def _start_xvfb(self) -> None:
        if self.xvfb_proc is not None:
            return
        try:
            proc = subprocess.Popen(
                ["Xvfb", "-displayfd", "1", "-screen", "0", "1366x900x24", "-nolisten", "tcp", "-ac"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            display_num_text = ""
            deadline = time.time() + 10
            while time.time() <= deadline:
                if proc.stdout is not None:
                    ready, _, _ = select.select([proc.stdout], [], [], 0.2)
                    if ready:
                        display_num_text = (proc.stdout.readline() or "").strip()
                        if display_num_text:
                            break
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            if display_num_text.isdigit():
                socket_path = Path(f"/tmp/.X11-unix/X{display_num_text}")
                ready = False
                for _ in range(40):
                    if socket_path.exists():
                        ready = True
                        break
                    time.sleep(0.25)
                if ready:
                    display = f":{display_num_text}"
                    self.display = display
                    self.xvfb_proc = proc
                    os.environ["DISPLAY"] = display
                    return
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        except Exception:
            pass
        for display_num in range(90, 2048):
            socket_path = Path(f"/tmp/.X11-unix/X{display_num}")
            lock_path = Path(f"/tmp/.X{display_num}-lock")
            if socket_path.exists() or lock_path.exists():
                continue
            display = f":{display_num}"
            proc = subprocess.Popen(
                ["Xvfb", display, "-screen", "0", "1366x900x24", "-nolisten", "tcp", "-ac"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            ready = False
            for _ in range(40):
                if socket_path.exists():
                    ready = True
                    break
                time.sleep(0.25)
            if ready:
                self.display = display
                self.xvfb_proc = proc
                os.environ["DISPLAY"] = display
                return
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        raise RuntimeError("official_outlook_web_xvfb_start_failed")

    def _use_selenium_inbox_mode(self) -> bool:
        if self.disable_selenium:
            return False
        return bool(self.target_email) or self.alias_mode in {"base", "fixed", "none", "plus"}

    def _running_inside_asyncio_loop(self) -> bool:
        try:
            import asyncio
            asyncio.get_running_loop()
            return True
        except RuntimeError:
            return False
        except Exception:
            return False

    def _close_playwright_stack(self) -> None:
        page = self.page
        context = self.context
        playwright = self.playwright
        self.page = None
        self.context = None
        self.playwright = None
        self._playwright_owner_thread_id = None
        self._playwright_seeded_from_selenium = False
        if page is not None:
            try:
                page.close()
            except Exception:
                pass
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        if playwright is not None:
            try:
                playwright.stop()
            except Exception:
                pass

    def _ensure_playwright_executor(self) -> ThreadPoolExecutor:
        executor = self._playwright_executor
        if executor is None:
            executor = ThreadPoolExecutor(
                max_workers=1,
                thread_name_prefix="outlook-official-playwright",
            )
            self._playwright_executor = executor
        return executor

    def _shutdown_playwright_executor(self) -> None:
        executor = self._playwright_executor
        owner_thread_id = self._playwright_owner_thread_id
        current_thread_id = threading.get_ident()
        if self.page is not None or self.context is not None or self.playwright is not None:
            if executor is not None and owner_thread_id and current_thread_id != owner_thread_id:
                try:
                    executor.submit(self._close_playwright_stack).result(timeout=20)
                except Exception:
                    self._close_playwright_stack()
            else:
                self._close_playwright_stack()
        self._playwright_executor = None
        if executor is not None:
            try:
                executor.shutdown(wait=True, cancel_futures=False)
            except Exception:
                pass

    def _run_playwright_fallback(self, func, *args, timeout: Optional[int] = None, **kwargs):
        worker_timeout = int(timeout or max(self.timeout + 30, 90))
        future = self._ensure_playwright_executor().submit(func, *args, **kwargs)
        return future.result(timeout=worker_timeout)

    def _ensure_driver(self):
        if self.driver is not None:
            return self.driver

        webdriver, Options, Service, _, _, _, _ = self._selenium_imports()
        self._start_xvfb()
        self.driver_profile_dir = tempfile.mkdtemp(prefix="outlook-official-selenium-")
        os.environ["DISPLAY"] = self.display

        options = Options()
        options.binary_location = "/usr/bin/google-chrome"
        chrome_args = [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--window-size=1366,900",
            "--disable-blink-features=AutomationControlled",
            f"--user-data-dir={self.driver_profile_dir}",
        ]
        if self.proxy:
            chrome_args.append(f"--proxy-server={self.proxy}")
        for arg in chrome_args:
            options.add_argument(arg)
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)
        self.driver = webdriver.Chrome(
            service=Service(log_output=subprocess.DEVNULL),
            options=options,
        )
        return self.driver

    def _bounded_get(self, url: str, timeout: int) -> bool:
        _, _, _, _, _, _, TimeoutException = self._selenium_imports()
        driver = self._ensure_driver()
        driver.set_page_load_timeout(timeout)
        try:
            driver.get(url)
            return True
        except TimeoutException:
            try:
                driver.execute_script("window.stop();")
            except Exception:
                pass
            return False

    def _selenium_wait_for_mail_rows(self, timeout: int = 60) -> None:
        _, _, _, By, _, WebDriverWait, _ = self._selenium_imports()
        driver = self._ensure_driver()
        wait = WebDriverWait(driver, timeout)
        wait.until(lambda d: "outlook.live.com/mail" in d.current_url.lower() or " - Outlook" in d.title or d.title == "Outlook")
        wait.until(
            lambda d: len(d.find_elements(By.CSS_SELECTOR, '[role="option"][aria-label], [role="option"][data-convid]')) > 0
        )

    def _selenium_login_if_needed(self) -> None:
        _, _, _, By, EC, WebDriverWait, _ = self._selenium_imports()
        driver = self._ensure_driver()
        try:
            self._bounded_get("https://outlook.live.com/mail/0/", timeout=8)
            self._selenium_wait_for_mail_rows(timeout=8)
            return
        except Exception:
            pass

        self._bounded_get("https://login.live.com/", timeout=15)
        wait = WebDriverWait(driver, 30)
        email_box = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, 'input[type="email"], input[name="loginfmt"]')))
        email_box.clear()
        email_box.send_keys(self.login_email)
        driver.find_element(By.CSS_SELECTOR, 'input[type="submit"], button[type="submit"], #idSIButton9').click()

        pwd_box = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, 'input[type="password"], input[name="passwd"]')))
        pwd_box.clear()
        pwd_box.send_keys(self.login_password)
        driver.find_element(By.CSS_SELECTOR, 'input[type="submit"], button[type="submit"], #idSIButton9').click()

        try:
            stay = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, '#idSIButton9, #declineButton'))
            )
            stay.click()
        except Exception:
            pass

        self._bounded_get("https://outlook.live.com/mail/0/", timeout=15)
        self._selenium_wait_for_mail_rows(timeout=max(60, self.timeout))

    def _selenium_normalize_message_rows(self, raw_rows: list[dict[str, str]]) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for raw in raw_rows:
            aria = (raw.get("aria") or "").strip()
            text = (raw.get("text") or "").strip()
            subject = ""
            for source in (text, aria):
                match = re.search(r"(Your (?:OpenAI|ChatGPT|Microsoft) code is \d{4,8})", source, flags=re.I)
                if match:
                    subject = match.group(1).strip()
                    break
            if not subject:
                lines = [line.strip() for line in text.splitlines() if line.strip()]
                subject = lines[1] if len(lines) > 1 else (lines[0] if lines else text[:120].strip())
            raw_id = (raw.get("id") or "").strip() or (raw.get("convid") or "").strip()
            if not raw_id:
                digest_source = "\n".join(part for part in (aria, text, subject) if part)
                raw_id = "digest:" + hashlib.sha1(digest_source.encode("utf-8", errors="ignore")).hexdigest()
            rows.append(
                {
                    "id": raw_id,
                    "subject": subject,
                    "text": text or aria or subject,
                    "html": aria or text or subject,
                }
            )
        return rows

    def _selenium_list_messages(self) -> list[dict[str, str]]:
        driver = self._ensure_driver()
        self._selenium_login_if_needed()
        if time.monotonic() - self.last_refresh_ts >= self.refresh_interval_seconds:
            self._bounded_get("https://outlook.live.com/mail/0/", timeout=15)
            self.last_refresh_ts = time.monotonic()
        self._selenium_wait_for_mail_rows(timeout=max(20, self.timeout))
        raw_rows = driver.execute_script(
            """
            const rows = Array.from(document.querySelectorAll('[role="option"][aria-label], [role="option"][data-convid]'));
            return rows.slice(0, 20).map((el) => ({
              id: el.id || '',
              convid: el.getAttribute('data-convid') || '',
              aria: el.getAttribute('aria-label') || '',
              text: el.innerText || ''
            })).filter((row) => row.aria || row.text);
            """
        )
        if not isinstance(raw_rows, list):
            return []
        messages = self._selenium_normalize_message_rows(raw_rows)
        self.cached_messages = {row["id"]: row for row in messages}
        return messages

    def _ensure_page(self):
        current_thread_id = threading.get_ident()
        if self.page is not None and self._playwright_owner_thread_id == current_thread_id:
            return self.page
        if self.page is not None and self._playwright_owner_thread_id != current_thread_id:
            self._log(
                "[OutlookOfficialWeb] 检测到线程切换，重建 Playwright inbox "
                f"(from={self._playwright_owner_thread_id} to={current_thread_id})"
            )
            self._close_playwright_stack()
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("Outlook official web 需要 playwright，请先安装依赖") from exc

        self._start_xvfb()
        self.profile_dir = tempfile.mkdtemp(prefix="outlook-official-webmail-")
        os.environ["DISPLAY"] = self.display

        launch_kwargs = {
            "headless": False,
            "executable_path": "/usr/bin/google-chrome",
            "args": [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--window-size=1366,900",
                "--disable-blink-features=AutomationControlled",
            ],
            "user_agent": self.USER_AGENT,
            "viewport": {"width": 1366, "height": 900},
        }
        proxy_settings = self._playwright_proxy_settings()
        if proxy_settings:
            launch_kwargs["proxy"] = proxy_settings

        self.playwright = sync_playwright().start()
        self.context = self.playwright.chromium.launch_persistent_context(self.profile_dir, **launch_kwargs)
        self.page = self.context.pages[0] if self.context.pages else self.context.new_page()
        self.page.set_default_timeout(max(self.timeout * 1000, 30000))
        self._playwright_owner_thread_id = current_thread_id
        self._playwright_seeded_from_selenium = False
        return self.page

    def _hydrate_playwright_from_selenium(self) -> bool:
        if self.driver is None or self.context is None:
            return False
        try:
            raw_cookies = self.driver.get_cookies()
        except Exception as exc:
            self._log(f"[OutlookOfficialWeb] Selenium cookies 注入 Playwright 失败: {exc}")
            return False
        cookies: list[dict[str, Any]] = []
        for item in raw_cookies or []:
            name = str(item.get("name") or "").strip()
            value = str(item.get("value") or "")
            domain = str(item.get("domain") or "").strip()
            if not name or not value or not domain:
                continue
            cookie: dict[str, Any] = {
                "name": name,
                "value": value,
                "domain": domain,
                "path": str(item.get("path") or "/"),
                "secure": bool(item.get("secure", False)),
                "httpOnly": bool(item.get("httpOnly", False)),
            }
            same_site = str(item.get("sameSite") or "").strip().lower()
            same_site_map = {
                "lax": "Lax",
                "strict": "Strict",
                "none": "None",
            }
            if same_site in same_site_map:
                cookie["sameSite"] = same_site_map[same_site]
            expiry = item.get("expiry")
            if isinstance(expiry, (int, float)) and expiry > 0:
                cookie["expires"] = float(expiry)
            cookies.append(cookie)
        if not cookies:
            return False
        try:
            self.context.add_cookies(cookies)
        except Exception as exc:
            self._log(f"[OutlookOfficialWeb] Playwright add_cookies 失败: {exc}")
            return False
        self._playwright_seeded_from_selenium = True
        try:
            current_url = str(self.driver.current_url or "").strip()
        except Exception:
            current_url = ""
        if current_url.startswith("http"):
            self._goto(current_url, timeout_ms=15000)
        self._log(
            f"[OutlookOfficialWeb] 已将 Selenium 会话注入 Playwright cookies ({len(cookies)})"
        )
        return True

    def _playwright_list_messages(self, max_wait_seconds: Optional[float] = None) -> list[dict[str, str]]:
        page = self._ensure_page()
        operation_budget = max(float(max_wait_seconds or min(self.timeout, 20)), 5.0)
        if not self._playwright_seeded_from_selenium:
            self._hydrate_playwright_from_selenium()
        self._login_if_needed(max_wait_seconds=operation_budget)
        refresh_timeout_ms = min(max(int(operation_budget * 1000), 8000), 15000)
        if (
            time.monotonic() - self.last_refresh_ts >= self.refresh_interval_seconds
            or (not self._mail_rows_available() and not self._mail_host_ready())
        ):
            self._goto_mail_home(timeout_ms=refresh_timeout_ms)
            self.last_refresh_ts = time.monotonic()
        deadline = time.time() + operation_budget
        while time.time() <= deadline:
            try:
                raw_rows = page.evaluate(
                    """
                    () => Array.from(document.querySelectorAll('[role="option"][aria-label], [role="option"][data-convid]'))
                      .slice(0, 20)
                      .map((el) => ({
                        id: el.id || '',
                        convid: el.getAttribute('data-convid') || '',
                        aria: el.getAttribute('aria-label') || '',
                        text: el.innerText || ''
                      }))
                      .filter((row) => row.aria || row.text)
                    """
                )
            except Exception:
                raw_rows = []
            if isinstance(raw_rows, list) and raw_rows:
                messages = self._normalize_message_rows(raw_rows)
                self.cached_messages = {row["id"]: row for row in messages}
                return messages
            time.sleep(1)
        raise RuntimeError("official_outlook_web_no_mail_rows_within_budget")

    def _goto(self, url: str, timeout_ms: Optional[int] = None) -> None:
        page = self._ensure_page()
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms or max(self.timeout * 1000, 30000))
        except Exception as exc:
            self._log(f"[OutlookOfficialWeb] 页面跳转超时/失败，继续尝试当前页: {exc}")

    def _goto_mail_home(self, timeout_ms: Optional[int] = None) -> None:
        self._goto("https://outlook.live.com/mail/0/", timeout_ms=timeout_ms)
        page = self._ensure_page()
        page.wait_for_timeout(1500)
        if self._is_marketing_landing_page():
            self._resume_outlook_sign_in()

    def _is_marketing_landing_page(self) -> bool:
        page = self._ensure_page()
        url = str(page.url or "").lower()
        body = self._body_text().lower()
        return (
            "microsoft-365/outlook" in url
            and "microsoft.com/" in url
            and ("sign in" in body or "continue to sign in" in body or "create free account" in body)
        )

    def _is_account_home_page(self) -> bool:
        page = self._ensure_page()
        url = str(page.url or "").lower()
        body = self._body_text().lower()
        title = ""
        try:
            title = str(page.title() or "").lower()
        except Exception:
            title = ""
        return (
            "account.microsoft.com/" in url
            and ("microsoft account" in title or "open outlook.com" in body or "your life organizer" in body)
        )

    def _visible_locator(self, selectors: list[str], timeout_ms: int = 1500):
        page = self._ensure_page()
        for selector in selectors:
            locator = page.locator(selector).first
            try:
                if locator.is_visible(timeout=timeout_ms):
                    return locator
            except Exception:
                continue
        return None

    def _control_text(self, locator) -> str:
        for getter in (
            lambda: locator.inner_text(timeout=1000),
            lambda: locator.input_value(timeout=1000),
            lambda: locator.get_attribute("aria-label", timeout=1000),
            lambda: locator.get_attribute("value", timeout=1000),
        ):
            try:
                text = getter()
            except Exception:
                continue
            if text:
                return str(text).strip()
        return ""

    def _click_control_with_text(self, patterns: list[str]) -> bool:
        page = self._ensure_page()
        locator = page.locator('button, input[type="submit"], a, div[role="button"], span[role="button"]')
        try:
            count = min(locator.count(), 60)
        except Exception:
            count = 0
        patterns_lower = [item.lower() for item in patterns if item]
        for index in range(count):
            candidate = locator.nth(index)
            try:
                if not candidate.is_visible(timeout=1000):
                    continue
            except Exception:
                continue
            text = self._control_text(candidate).lower()
            if not text:
                continue
            if any(pattern in text for pattern in patterns_lower):
                self._click_without_navigation_wait(candidate)
                return True
        return False

    def _click_without_navigation_wait(self, locator) -> None:
        try:
            locator.click(no_wait_after=True)
            return
        except TypeError:
            pass
        except Exception:
            pass
        try:
            locator.click(force=True)
            return
        except Exception:
            pass
        try:
            locator.evaluate("(node) => node.click()")
            return
        except Exception:
            pass
        locator.click()

    def _fill_text_input(self, locator, value: str) -> None:
        text = str(value or "")
        try:
            locator.focus()
        except Exception:
            pass
        locator.fill("")
        try:
            locator.type(text, delay=35)
        except Exception:
            locator.fill(text)
        for event_name in ("input", "change"):
            try:
                locator.dispatch_event(event_name)
            except Exception:
                pass
        try:
            locator.press("Tab")
        except Exception:
            pass

    def _wait_locator_enabled(self, locator, timeout_ms: int = 8000) -> bool:
        deadline = time.time() + max(timeout_ms, 1000) / 1000.0
        while time.time() <= deadline:
            try:
                if locator.is_enabled(timeout=500):
                    return True
            except Exception:
                pass
            self._ensure_page().wait_for_timeout(250)
        return False

    def _body_text(self) -> str:
        page = self._ensure_page()
        try:
            return page.locator("body").inner_text(timeout=2000)
        except Exception:
            return ""

    def _is_browser_error_page(self) -> bool:
        page = self._ensure_page()
        url = page.url.lower()
        body = self._body_text().lower()
        return url.startswith("chrome-error://") or any(
            marker in body
            for marker in (
                "err_connection_closed",
                "this site can’t be reached",
                "this site can't be reached",
                "unexpectedly closed the connection",
                "proxy and the firewall",
            )
        )

    def _is_security_info_gate(self) -> bool:
        body = self._body_text().lower()
        page = self._ensure_page()
        return (
            "/proofs/" in page.url.lower()
            or "let's protect your account" in body
            or "add another way to verify it's you" in body
        )

    def _is_passkey_interrupt(self) -> bool:
        page = self._ensure_page()
        url = page.url.lower()
        body = self._body_text().lower()
        return "/interrupt/passkey/" in url or "/consumers/fido/create" in url or (
            "passkey" in body and (
                "couldn't create a passkey" in body
                or "create a passkey" in body
                or "something went wrong trying to create a passkey" in body
                or "setting up your passkey" in body
                or "finish setting up your passkey" in body
            )
        )

    def _extract_passkey_return_url(self) -> str:
        page = self._ensure_page()
        candidates: list[str] = [str(page.url or "").strip()]
        try:
            form_action = page.locator("form").first.get_attribute("action", timeout=1000)
        except Exception:
            form_action = ""
        if form_action:
            candidates.append(str(form_action).strip())

        for candidate in candidates:
            if not candidate:
                continue
            try:
                parsed = urlsplit(candidate)
                ru_values = parse_qs(parsed.query).get("ru") or []
            except Exception:
                ru_values = []
            for raw_value in ru_values:
                target = unquote(str(raw_value or "").strip())
                if target.startswith("http"):
                    return target

        try:
            html = page.content()
        except Exception:
            html = ""
        if html:
            match = re.search(r"ru=(https?%3a%2f%2f[^&\"']+)", html, re.IGNORECASE)
            if match:
                target = unquote(match.group(1).strip())
                if target.startswith("http"):
                    return target
        return ""

    def _dismiss_passkey_interrupt(self) -> bool:
        if not self._is_passkey_interrupt():
            return False
        page = self._ensure_page()
        self._log(f"[OutlookOfficialWeb] 检测到 passkey interrupt: {page.url}")
        cancel = self._visible_locator(["#idBtn_Back", 'input#idBtn_Back', 'input[type="button"]'], timeout_ms=1500)
        if cancel is not None:
            try:
                self._click_without_navigation_wait(cancel)
                page.wait_for_timeout(2000)
                if not self._is_passkey_interrupt():
                    self._log("[OutlookOfficialWeb] 已通过 Back 退出 passkey interrupt")
                    return True
            except Exception as exc:
                self._log(f"[OutlookOfficialWeb] passkey Back 点击失败，尝试其他退出路径: {exc}")
        clicked = self._click_control_with_text(["cancel", "not now", "skip", "later", "back"])
        if clicked:
            page.wait_for_timeout(2000)
            if not self._is_passkey_interrupt():
                self._log("[OutlookOfficialWeb] 已通过文案按钮退出 passkey interrupt")
                return True
        return_url = self._extract_passkey_return_url()
        if return_url:
            self._log(f"[OutlookOfficialWeb] passkey interrupt 回跳到 return URL: {return_url}")
            self._goto(return_url, timeout_ms=30000)
            page.wait_for_timeout(2000)
            if not self._is_passkey_interrupt():
                return True
        try:
            page.go_back(wait_until="load", timeout=15000)
            page.wait_for_timeout(1500)
            if not self._is_passkey_interrupt():
                self._log("[OutlookOfficialWeb] 已通过 go_back 退出 passkey interrupt")
                return True
        except Exception as exc:
            self._log(f"[OutlookOfficialWeb] passkey interrupt go_back 失败: {exc}")
        return not self._is_passkey_interrupt()

    def _stay_signed_in_prompt_active(self) -> bool:
        body = self._body_text().lower()
        return "stay signed in" in body

    def _dismiss_stay_signed_in_prompt(self) -> bool:
        if not self._stay_signed_in_prompt_active():
            return False
        decline = self._visible_locator(["#declineButton"], timeout_ms=1200)
        if decline is not None:
            try:
                decline.click()
                self._ensure_page().wait_for_timeout(1200)
                return True
            except Exception:
                pass
        return self._click_control_with_text(["no", "yes"])

    def _alias_manage_ready(self) -> bool:
        page = self._ensure_page()
        url = page.url.lower()
        body = self._body_text().lower()
        if "account.live.com/names/manage" in url:
            return True
        return any(
            marker in body
            for marker in (
                "account aliases",
                "add email",
                "add alias",
                "create a new email address",
            )
        )

    def _is_manage_identity_gate(self) -> bool:
        page = self._ensure_page()
        url = page.url.lower()
        body = self._body_text().lower()
        return "login.live.com/login.srf" in url and (
            "almost there" in body
            or "verify your identity" in body
            or "verify it’s you" in body
            or "verify it's you" in body
            or "send a code to" in body and "already have a code" in body
            or "email a" in body and "i have a code" in body
        )

    def _resume_outlook_sign_in(self) -> None:
        page = self._ensure_page()
        for candidate in (
            "https://login.live.com/",
            "https://login.live.com/login.srf",
            "https://go.microsoft.com/fwlink/p/?LinkID=2125442&deeplink=mail%2F0%2F",
            "https://outlook.live.com/mail/0/",
            "https://outlook.live.com/owa/",
        ):
            self._goto(candidate, timeout_ms=30000)
            page.wait_for_timeout(1500)
            if not self._is_marketing_landing_page():
                return

    def _is_login_email_verify_prompt(self) -> bool:
        body = self._body_text().lower()
        return (
            "verify your email" in body
            and self._visible_locator(
                ['#proof-confirmation-email-input', '#proof-confirmation'],
                timeout_ms=500,
            )
            is not None
        )

    def _is_login_email_code_prompt(self) -> bool:
        code_input = self._visible_locator(
            ['#codeEntry-0', '#otc-confirmation-input', 'input[name="otc"]'],
            timeout_ms=500,
        )
        if code_input is None:
            return False
        body = self._body_text().lower()
        return "enter" in body and "code" in body

    def _login_email_send_failed(self) -> bool:
        body = self._body_text().lower()
        return (
            "verify your email" in body
            and any(
                marker in body
                for marker in (
                    "we couldn't send the code",
                    "we could not send the code",
                    "couldn't send the code",
                    "could not send the code",
                    "please try again",
                )
            )
        )

    def _submit_login_email_verification_target(self, proof_email: str) -> bool:
        page = self._ensure_page()
        input_box = self._visible_locator(
            ['#proof-confirmation-email-input', '#proof-confirmation', 'input[type="text"]'],
            timeout_ms=1500,
        )
        if input_box is None:
            if self._is_login_email_code_prompt():
                if not self._back_to_login_email_verify_prompt():
                    raise RuntimeError("outlook_official_login_proof_email_input_missing")
                input_box = self._visible_locator(
                    ['#proof-confirmation-email-input', '#proof-confirmation', 'input[type="text"]'],
                    timeout_ms=1500,
                )
        if input_box is None:
            raise RuntimeError("outlook_official_login_proof_email_input_missing")
        self._fill_text_input(input_box, proof_email)
        submit = self._visible_locator(['button[type="submit"]'], timeout_ms=1500)
        if submit is None:
            raise RuntimeError("outlook_official_login_proof_email_submit_missing")
        if not self._wait_locator_enabled(submit, timeout_ms=6000):
            raise RuntimeError("outlook_official_login_proof_email_submit_disabled")
        self._click_without_navigation_wait(submit)
        deadline = time.time() + 20
        while time.time() <= deadline:
            if self._is_login_email_code_prompt():
                return True
            if self._login_email_send_failed():
                self._log("[OutlookOfficialWeb] 微软未发出登录验证码，转密码登录")
                return False
            page.wait_for_timeout(1000)
        raise RuntimeError("outlook_official_login_proof_code_prompt_missing")

    def _submit_login_email_verification_code(self, code: str) -> None:
        page = self._ensure_page()
        digits = list(str(code).strip())
        if len(digits) < 6:
            raise RuntimeError(f"微软登录邮箱验证码位数异常: {code}")
        otp_input = self._visible_locator(
            ['#otc-confirmation-input', 'input[name="otc"]'],
            timeout_ms=800,
        )
        if otp_input is not None:
            self._fill_text_input(otp_input, "".join(digits[:6]))
            submit = self._visible_locator(
                ['#oneTimeCodePrimaryButton', 'button[type="submit"]', 'input[type="submit"]'],
                timeout_ms=1200,
            )
            if submit is not None:
                self._click_without_navigation_wait(submit)
            page.wait_for_timeout(2500)
            return
        for index, digit in enumerate(digits[:6]):
            locator = page.locator(f"#codeEntry-{index}")
            locator.fill(digit)
            page.wait_for_timeout(120)
        page.wait_for_timeout(2500)

    def _login_email_code_rejected(self) -> bool:
        body = self._body_text().lower()
        return any(
            marker in body
            for marker in (
                "didn't work",
                "did not work",
                "isn't valid",
                "is not valid",
                "incorrect code",
                "wrong code",
                "that code didn't work",
            )
        )

    def _back_to_login_email_verify_prompt(self) -> bool:
        page = self._ensure_page()
        back_button = self._visible_locator(["#back-button"], timeout_ms=1200)
        if back_button is not None:
            try:
                self._click_without_navigation_wait(back_button)
                page.wait_for_timeout(1500)
            except Exception:
                pass
        return self._is_login_email_verify_prompt()

    def _resend_login_email_verification(self, proof_email: str) -> bool:
        page = self._ensure_page()
        self._back_to_login_email_verify_prompt()
        if self._is_login_email_verify_prompt():
            self._log("[OutlookOfficialWeb] 重新触发微软登录验证码发送")
            return self._submit_login_email_verification_target(proof_email)
        return False

    def _switch_login_email_prompt_to_password(self) -> bool:
        if not (
            self._is_login_email_code_prompt()
            or self._is_login_email_verify_prompt()
            or self._is_manage_identity_gate()
        ):
            return False
        password_box = self._visible_locator(
            ['input[type="password"]', 'input[name="passwd"]'],
            timeout_ms=800,
        )
        if password_box is not None:
            self._log("[OutlookOfficialWeb] 登录验证码页已切到密码输入")
            return True
        if not self._click_control_with_text(["use your password", "use password", "password"]):
            return False
        deadline = time.time() + 10
        while time.time() <= deadline:
            password_box = self._visible_locator(
                ['input[type="password"]', 'input[name="passwd"]'],
                timeout_ms=800,
            )
            if password_box is not None:
                self._log("[OutlookOfficialWeb] 登录验证码页切换到密码登录")
                return True
            self._ensure_page().wait_for_timeout(500)
        return False

    def _complete_login_email_verification(self) -> str:
        proof_account = self._ensure_security_proof_target()
        proof_mailbox = self._build_security_proof_mailbox()
        baseline_ids = proof_mailbox.get_current_ids(proof_account)
        self._log(f"[OutlookOfficialWeb] 登录验证邮箱: {proof_account.email}")
        code_prompt_ready = self._submit_login_email_verification_target(proof_account.email)
        if not code_prompt_ready:
            if self._switch_login_email_prompt_to_password():
                return "password"
            raise RuntimeError("outlook_official_login_proof_send_failed")
        deadline = time.time() + max(self.timeout + 60, 120)
        exclude_codes: set[str] = set()

        while time.time() <= deadline:
            remaining = max(int(deadline - time.time()), 1)
            try:
                code = proof_mailbox.wait_for_code(
                    proof_account,
                    keyword="microsoft",
                    timeout=min(45, remaining),
                    before_ids=baseline_ids,
                    code_pattern=r"(?<!\d)(\d{6})(?!\d)",
                    exclude_codes=exclude_codes,
                )
            except TimeoutError:
                if self._switch_login_email_prompt_to_password():
                    return "password"
                resend_ready = self._resend_login_email_verification(proof_account.email)
                if resend_ready:
                    baseline_ids = proof_mailbox.get_current_ids(proof_account)
                    continue
                if self._switch_login_email_prompt_to_password():
                    return "password"
                raise
            exclude_codes.add(str(code))
            self._log(f"[OutlookOfficialWeb] 收到微软登录验证码: {code}")
            self._submit_login_email_verification_code(code)
            post_deadline = time.time() + 20
            mail_home_resume_attempted = False
            while time.time() <= post_deadline:
                if self._mail_rows_available():
                    return
                if self._stay_signed_in_prompt_active():
                    self._dismiss_stay_signed_in_prompt()
                    return "verified"
                if self._login_email_code_rejected():
                    self._log("[OutlookOfficialWeb] 微软登录验证码未通过，继续尝试下一封")
                    if self._switch_login_email_prompt_to_password():
                        return "password"
                    resend_ready = self._resend_login_email_verification(proof_account.email)
                    if resend_ready:
                        baseline_ids = proof_mailbox.get_current_ids(proof_account)
                    elif self._switch_login_email_prompt_to_password():
                        return "password"
                    break
                if self._is_login_email_verify_prompt():
                    break
                if self._is_login_email_code_prompt():
                    self._ensure_page().wait_for_timeout(1000)
                    continue
                if not mail_home_resume_attempted:
                    mail_home_resume_attempted = True
                    self._log("[OutlookOfficialWeb] 登录验证码提交后主动打开 mail home 确认状态")
                    try:
                        self._goto_mail_home(timeout_ms=15000)
                    except Exception as exc:
                        self._log(f"[OutlookOfficialWeb] 登录验证码后打开 mail home 失败，继续当前页轮询: {exc}")
                    self._ensure_page().wait_for_timeout(1200)
                    continue
                self._ensure_page().wait_for_timeout(1000)
            if not (self._is_login_email_verify_prompt() or self._is_login_email_code_prompt()):
                return "verified"

        raise RuntimeError("outlook_official_login_email_verification_timeout")

    def _trigger_manage_identity_code_prompt(self, proof_email: str) -> str:
        if self._is_login_email_code_prompt():
            return "code"
        if self._is_login_email_verify_prompt():
            code_prompt_ready = self._submit_login_email_verification_target(proof_email)
            if code_prompt_ready:
                return "code"
            if self._switch_login_email_prompt_to_password():
                return "password"
            raise RuntimeError("outlook_official_manage_identity_proof_send_failed")
        for patterns in (
            ["send a code to"],
            ["email a"],
            ["already have a code"],
            ["i have a code"],
        ):
            if not self._click_control_with_text(patterns):
                continue
            deadline = time.time() + 20
            while time.time() <= deadline:
                if self._is_login_email_code_prompt():
                    return "code"
                if self._is_login_email_verify_prompt():
                    code_prompt_ready = self._submit_login_email_verification_target(proof_email)
                    if code_prompt_ready:
                        return "code"
                    if self._switch_login_email_prompt_to_password():
                        return "password"
                    raise RuntimeError("outlook_official_manage_identity_proof_send_failed")
                if not self._is_manage_identity_gate():
                    return "resolved"
                self._ensure_page().wait_for_timeout(1000)
        raise RuntimeError("outlook_official_manage_identity_code_prompt_missing")

    def _complete_manage_identity_gate(self) -> str | None:
        proof_account = self._ensure_security_proof_target()
        proof_mailbox = self._build_security_proof_mailbox()
        baseline_ids = proof_mailbox.get_current_ids(proof_account)
        self._log(f"[OutlookOfficialWeb] 管理页身份验证邮箱: {proof_account.email}")
        if self._switch_login_email_prompt_to_password():
            return "password"
        trigger_result = self._trigger_manage_identity_code_prompt(proof_account.email)
        if trigger_result == "password":
            return "password"
        if trigger_result == "resolved" and not self._is_manage_identity_gate():
            return None
        deadline = time.time() + max(self.timeout + 60, 120)
        exclude_codes: set[str] = set()

        while time.time() <= deadline:
            remaining = max(int(deadline - time.time()), 1)
            try:
                code = proof_mailbox.wait_for_code(
                    proof_account,
                    keyword="microsoft",
                    timeout=min(45, remaining),
                    before_ids=baseline_ids,
                    code_pattern=r"(?<!\d)(\d{6})(?!\d)",
                    exclude_codes=exclude_codes,
                )
            except TimeoutError:
                if self._switch_login_email_prompt_to_password():
                    return "password"
                if self._click_control_with_text(["send a code to", "email a"]):
                    baseline_ids = proof_mailbox.get_current_ids(proof_account)
                    self._ensure_page().wait_for_timeout(1000)
                    continue
                raise

            exclude_codes.add(str(code))
            self._log(f"[OutlookOfficialWeb] 收到管理页身份验证码: {code}")
            self._submit_login_email_verification_code(code)
            self._log("[OutlookOfficialWeb] 管理页身份验证码已提交，主动直跳 names/manage 确认状态")
            try:
                self._goto("https://account.live.com/names/manage", timeout_ms=12000)
                self._ensure_page().wait_for_timeout(2000)
                if self._alias_manage_ready():
                    self._log("[OutlookOfficialWeb] 管理页验证码提交后已进入 alias manage")
                    return None
            except Exception as exc:
                self._log(f"[OutlookOfficialWeb] 管理页验证码提交后直跳 names/manage 失败，继续当前页轮询: {exc}")
            post_deadline = time.time() + 20
            while time.time() <= post_deadline:
                if self._alias_manage_ready():
                    return None
                if self._stay_signed_in_prompt_active():
                    self._dismiss_stay_signed_in_prompt()
                    if self._alias_manage_ready():
                        return None
                if self._login_email_code_rejected():
                    self._log("[OutlookOfficialWeb] 管理页身份验证码未通过，重试")
                    if self._switch_login_email_prompt_to_password():
                        return "password"
                    if self._click_control_with_text(["send a code to", "email a", "already have a code", "i have a code"]):
                        baseline_ids = proof_mailbox.get_current_ids(proof_account)
                    break
                if self._is_login_email_code_prompt() or self._is_manage_identity_gate():
                    self._ensure_page().wait_for_timeout(1000)
                    continue
                self._ensure_page().wait_for_timeout(1000)
            if not (self._is_login_email_code_prompt() or self._is_manage_identity_gate()):
                return None

        raise RuntimeError("outlook_official_manage_identity_timeout")

    def _open_alias_manage_page(self) -> None:
        self._login_if_needed()
        for attempt in range(4):
            entry_url = self._resolve_manage_entry_url()
            self._goto(entry_url)
            page = self._ensure_page()
            page.wait_for_timeout(2000)
            if self._alias_manage_ready():
                return
            if not self._is_security_info_gate():
                if self._is_browser_error_page():
                    self._log(
                        f"[OutlookOfficialWeb] alias manage 落到浏览器错误页，重试入口: {page.url}"
                    )
                    continue
                current_url = str(page.url or "").lower()
                if "login.live.com/login.srf" in current_url:
                    if self._is_manage_identity_gate():
                        manage_result = self._complete_manage_identity_gate()
                        if manage_result == "password":
                            self._complete_login_prompts_on_current_page()
                        continue
                    self._complete_login_prompts_on_current_page()
                    continue
                if self._stay_signed_in_prompt_active():
                    self._dismiss_stay_signed_in_prompt()
                    continue
                if self._is_passkey_interrupt():
                    self._dismiss_passkey_interrupt()
                    continue
                if self._is_manage_identity_gate():
                    manage_result = self._complete_manage_identity_gate()
                    if manage_result == "password":
                        self._login_if_needed()
                    continue
                if "microsoft.com/en-us/microsoft-365/outlook" in page.url.lower():
                    self._resume_outlook_sign_in()
                    self._login_if_needed()
                    continue
                page.wait_for_timeout(5000)
                if self._alias_manage_ready():
                    return
                if self._is_manage_identity_gate():
                    manage_result = self._complete_manage_identity_gate()
                    if manage_result == "password":
                        self._login_if_needed()
                    continue
                raise RuntimeError(f"outlook_official_alias_manage_unexpected_page: {page.url}")
            if attempt < 3:
                self._complete_security_info_gate()
                continue
            raise RuntimeError(
                "outlook_official_web_security_info_gate: 当前微软账号先要求补安全验证邮箱/手机号，"
                "尚未进入 alias 管理页"
            )

    def _resolve_manage_entry_url(self) -> str:
        proxies = {}
        if self.proxy:
            proxies = {"http": self.proxy, "https": self.proxy}
        try:
            response = requests.get(
                "https://account.live.com/names/manage",
                headers={"User-Agent": self.USER_AGENT},
                proxies=proxies or None,
                timeout=20,
                allow_redirects=True,
                verify=False,
            )
            if response.status_code < 500 and response.url:
                return str(response.url)
        except Exception as exc:
            self._log(f"[OutlookOfficialWeb] alias manage 入口预解析失败，回退直连入口: {exc}")
        return "https://account.live.com/names/manage"

    def _complete_login_prompts_on_current_page(self) -> None:
        page = self._ensure_page()
        deadline = time.time() + max(self.timeout, 30)
        while time.time() <= deadline:
            if self._alias_manage_ready():
                return
            if self._is_passkey_interrupt():
                self._dismiss_passkey_interrupt()
                page.wait_for_timeout(1000)
                continue
            if self._is_manage_identity_gate():
                return
            if self._stay_signed_in_prompt_active():
                self._dismiss_stay_signed_in_prompt()
                page.wait_for_timeout(1000)
                continue
            if self._is_login_email_verify_prompt() or self._is_login_email_code_prompt():
                self._complete_login_email_verification()
                page.wait_for_timeout(1000)
                continue
            email_box = self._visible_locator(['input[type="email"]', 'input[name="loginfmt"]'], timeout_ms=800)
            if email_box is not None:
                self._fill_text_input(email_box, self.login_email)
                next_button = self._visible_locator(
                    ['#idSIButton9', 'input[type="submit"]', 'button[type="submit"]'],
                    timeout_ms=3000,
                )
                if next_button is None:
                    raise RuntimeError("official_outlook_web_manage_login_email_submit_missing")
                if not self._wait_locator_enabled(next_button, timeout_ms=6000):
                    raise RuntimeError("official_outlook_web_manage_login_email_submit_disabled")
                self._click_without_navigation_wait(next_button)
                page.wait_for_timeout(1200)
                continue
            password_box = self._visible_locator(['input[type="password"]', 'input[name="passwd"]'], timeout_ms=800)
            if password_box is not None:
                self._fill_text_input(password_box, self.login_password)
                submit_button = self._visible_locator(
                    ['#idSIButton9', 'input[type="submit"]', 'button[type="submit"]'],
                    timeout_ms=3000,
                )
                if submit_button is None:
                    raise RuntimeError("official_outlook_web_manage_login_password_submit_missing")
                if not self._wait_locator_enabled(submit_button, timeout_ms=6000):
                    raise RuntimeError("official_outlook_web_manage_login_password_submit_disabled")
                self._click_without_navigation_wait(submit_button)
                page.wait_for_timeout(1500)
                continue
            current_url = str(page.url or "").lower()
            if "login.live.com/login.srf" not in current_url and not self._is_browser_error_page():
                return
            time.sleep(1)
        raise RuntimeError("official_outlook_web_manage_login_timeout")

    def _login_if_needed(self, max_wait_seconds: Optional[float] = None) -> None:
        page = self._ensure_page()
        login_email_verification_completed = False
        operation_budget = max(float(max_wait_seconds or max(self.timeout, 30)), 10.0)
        mail_timeout_ms = min(max(int(operation_budget * 1000), 8000), 30000)
        if self._playwright_seeded_from_selenium:
            self._goto_mail_home(timeout_ms=mail_timeout_ms)
        else:
            self._goto("https://login.live.com/", timeout_ms=mail_timeout_ms)
        deadline = time.time() + operation_budget
        while time.time() <= deadline:
            if self._mail_rows_available() or self._mail_host_ready():
                return
            current_url = str(page.url or "").lower()
            if (
                ("outlook.live.com/mail/0" in current_url or "outlook.office.com/mail" in current_url)
                and not self._body_text().strip()
            ):
                self._goto("https://login.live.com/", timeout_ms=mail_timeout_ms)
                deadline = time.time() + operation_budget
                continue
            if self._is_account_home_page():
                self._goto_mail_home(timeout_ms=mail_timeout_ms)
                deadline = time.time() + operation_budget
                continue
            if self._is_browser_error_page():
                self._goto_mail_home(timeout_ms=mail_timeout_ms)
                continue
            if self._is_passkey_interrupt():
                self._dismiss_passkey_interrupt()
                if self._is_passkey_interrupt():
                    self._goto("https://outlook.live.com/mail/0/", timeout_ms=mail_timeout_ms)
                deadline = time.time() + operation_budget
                continue
            if self._is_marketing_landing_page():
                self._resume_outlook_sign_in()
                deadline = time.time() + operation_budget
                continue
            if self._is_login_email_verify_prompt() or self._is_login_email_code_prompt():
                verification_result = self._complete_login_email_verification()
                if verification_result == "verified":
                    login_email_verification_completed = True
                    self._goto_mail_home(timeout_ms=mail_timeout_ms)
                deadline = time.time() + operation_budget
                continue
            if self._is_security_info_gate():
                self._complete_security_info_gate()
                self._goto_mail_home(timeout_ms=mail_timeout_ms)
                deadline = time.time() + operation_budget
                continue
            email_box = self._visible_locator(['input[type="email"]', 'input[name="loginfmt"]'], timeout_ms=800)
            if email_box is not None:
                self._fill_text_input(email_box, self.login_email)
                next_button = self._visible_locator(
                    ['#idSIButton9', 'input[type="submit"]', 'button[type="submit"]'],
                    timeout_ms=3000,
                )
                if next_button is None:
                    raise RuntimeError("official_outlook_web_login_email_submit_missing")
                if not self._wait_locator_enabled(next_button, timeout_ms=6000):
                    raise RuntimeError("official_outlook_web_login_email_submit_disabled")
                self._click_without_navigation_wait(next_button)
                page.wait_for_timeout(1200)
                continue
            password_box = self._visible_locator(['input[type="password"]', 'input[name="passwd"]'], timeout_ms=800)
            if password_box is not None:
                self._fill_text_input(password_box, self.login_password)
                submit_button = self._visible_locator(
                    ['#idSIButton9', 'input[type="submit"]', 'button[type="submit"]'],
                    timeout_ms=3000,
                )
                if submit_button is None:
                    raise RuntimeError("official_outlook_web_login_password_submit_missing")
                if not self._wait_locator_enabled(submit_button, timeout_ms=6000):
                    raise RuntimeError("official_outlook_web_login_password_submit_disabled")
                self._click_without_navigation_wait(submit_button)
                page.wait_for_timeout(1500)
                continue
            if self._stay_signed_in_prompt_active():
                self._dismiss_stay_signed_in_prompt()
                continue
            if login_email_verification_completed and (self._mail_rows_available() or self._mail_host_ready()):
                return
            time.sleep(1)
        if login_email_verification_completed and (self._mail_rows_available() or self._mail_host_ready()):
            return
        raise RuntimeError("official_outlook_web_login_timeout")

    def _mail_rows_available(self) -> bool:
        page = self._ensure_page()
        try:
            rows = page.evaluate(
                """
                () => Array.from(
                  document.querySelectorAll('[role="option"][aria-label], [role="option"][data-convid]')
                ).length
                """
            )
            return int(rows or 0) > 0
        except Exception:
            return False

    def _mail_host_ready(self) -> bool:
        page = self._ensure_page()
        url = str(page.url or "").lower()
        if "outlook.live.com/mail/0" not in url and "outlook.office.com/mail" not in url:
            return False
        if self._is_marketing_landing_page():
            return False
        if self._is_browser_error_page():
            return False
        if self._is_passkey_interrupt():
            return False
        if self._is_login_email_verify_prompt() or self._is_login_email_code_prompt():
            return False
        if self._is_security_info_gate():
            return False
        if self._stay_signed_in_prompt_active():
            return False
        body = self._body_text().strip()
        if not body:
            return False
        email_box = self._visible_locator(['input[type="email"]', 'input[name="loginfmt"]'], timeout_ms=300)
        if email_box is not None:
            return False
        password_box = self._visible_locator(['input[type="password"]', 'input[name="passwd"]'], timeout_ms=300)
        if password_box is not None:
            return False
        return True

    def _build_security_proof_mailbox(self):
        if self.proof_mailbox is not None:
            return self.proof_mailbox
        if self.proof_imap_secret_path:
            self.proof_mailbox = IMAPSecretMailbox(
                secret_path=self.proof_imap_secret_path,
                target_email=self.proof_target_email,
                alias_mode=self.proof_alias_mode,
                from_filter="microsoft",
                interval=self.poll_interval,
                max_fetch=80,
                proxy=self.proxy,
            )
            return self.proof_mailbox
        if self.proof_pool_secret_path:
            secret_file = Path(self.proof_pool_secret_path).expanduser()
            if not secret_file.exists():
                raise RuntimeError(f"Outlook official proof secret 不存在: {secret_file}")
            payload = json.loads(secret_file.read_text(encoding="utf-8"))
            if not isinstance(payload.get("shared_imap"), dict):
                raise RuntimeError("Outlook official proof secret 缺少 shared_imap 配置")
            self.proof_mailbox = IMAPSecretMailbox(
                secret_path="",
                secret_payload=payload,
                target_email=self.proof_target_email,
                alias_mode=self.proof_alias_mode,
                from_filter="microsoft",
                interval=self.poll_interval,
                max_fetch=80,
                proxy=self.proxy,
            )
            return self.proof_mailbox
        return None

    def _ensure_security_proof_target(self) -> MailboxAccount:
        proof_mailbox = self._build_security_proof_mailbox()
        if proof_mailbox is None:
            raise RuntimeError(
                "outlook_official_web_security_info_gate: 当前微软账号先要求补安全验证邮箱/手机号，"
                "请配置 outlook_official_proof_pool_secret 或 outlook_official_proof_imap_secret"
            )
        account = proof_mailbox.get_email()
        if "@" not in account.email:
            raise RuntimeError(f"微软安全验证邮箱无效: {account.email}")
        return account

    def _security_verify_input_visible(self) -> bool:
        locator = self._visible_locator(
            ['#iOttText', 'input[name="otc"]', 'input[type="tel"]'],
            timeout_ms=1200,
        )
        return locator is not None

    def _resend_security_code(self) -> bool:
        if self._click_control_with_text(["i don't have a code", "send code", "resend code", "resend"]):
            self._ensure_page().wait_for_timeout(1500)
            return True
        return False

    def _security_code_rate_limited(self) -> bool:
        body = self._body_text().lower()
        return any(
            marker in body
            for marker in (
                "you've requested too many codes this week",
                "you have requested too many codes this week",
                "please try again in a week",
                "too many codes this week",
            )
        )

    def _submit_security_proof_email(self, proof_email: str) -> None:
        page = self._ensure_page()
        if self._security_verify_input_visible():
            self._resend_security_code()
            return

        email_input = self._visible_locator(
            ['#EmailAddress', 'input[type="email"]', 'input[name="ProofConfirmation"]'],
            timeout_ms=2500,
        )
        if email_input is None:
            if self._is_security_info_gate():
                raise RuntimeError("outlook_official_web_security_email_input_missing")
            return

        self._fill_text_input(email_input, proof_email)
        next_button = self._visible_locator(
            ['#iNext', '#idSubmit_ProofUp_Redirect', 'button[type="submit"]', 'input[type="submit"]'],
            timeout_ms=3000,
        )
        if next_button is None:
            raise RuntimeError("outlook_official_web_security_email_submit_missing")
        if not self._wait_locator_enabled(next_button, timeout_ms=6000):
            raise RuntimeError("outlook_official_web_security_email_submit_disabled")
        self._click_without_navigation_wait(next_button)
        deadline = time.time() + 20
        while time.time() <= deadline:
            if self._security_verify_input_visible():
                return
            if self._security_code_rate_limited():
                raise RuntimeError("outlook_official_web_security_code_rate_limited")
            if not self._is_security_info_gate():
                return
            page.wait_for_timeout(1000)
        raise RuntimeError("outlook_official_web_security_verify_page_missing")

    def _submit_security_proof_code(self, code: str) -> None:
        code_input = self._visible_locator(
            ['#iOttText', 'input[name="otc"]', 'input[type="tel"]'],
            timeout_ms=2500,
        )
        if code_input is None:
            raise RuntimeError("outlook_official_web_security_code_input_missing")
        code_input.fill(str(code))
        next_button = self._visible_locator(
            ['#iNext', 'button[type="submit"]', 'input[type="submit"]'],
            timeout_ms=2500,
        )
        if next_button is None:
            raise RuntimeError("outlook_official_web_security_code_submit_missing")
        self._click_without_navigation_wait(next_button)
        self._ensure_page().wait_for_timeout(2500)

    def _security_code_rejected(self) -> bool:
        body = self._body_text().lower()
        return any(
            marker in body
            for marker in (
                "didn't work",
                "did not work",
                "isn't valid",
                "is not valid",
                "incorrect code",
                "wrong code",
                "enter the code we sent",
            )
        )

    def _complete_security_info_gate(self) -> None:
        proof_account = self._ensure_security_proof_target()
        proof_mailbox = self._build_security_proof_mailbox()
        baseline_ids = proof_mailbox.get_current_ids(proof_account)
        self._log(f"[OutlookOfficialWeb] 使用安全验证邮箱: {proof_account.email}")
        self._submit_security_proof_email(proof_account.email)
        exclude_codes: set[str] = set()
        deadline = time.time() + max(self.timeout + 60, 120)

        while time.time() <= deadline:
            remaining = max(int(deadline - time.time()), 1)
            try:
                code = proof_mailbox.wait_for_code(
                    proof_account,
                    keyword="microsoft",
                    timeout=min(45, remaining),
                    before_ids=baseline_ids,
                    code_pattern=r"(?<!\d)(\d{6})(?!\d)",
                    exclude_codes=exclude_codes,
                )
            except TimeoutError:
                if self._security_code_rate_limited():
                    raise RuntimeError("outlook_official_web_security_code_rate_limited")
                if self._resend_security_code():
                    continue
                raise RuntimeError("outlook_official_web_security_code_timeout")

            exclude_codes.add(str(code))
            self._log(f"[OutlookOfficialWeb] 收到微软安全验证码: {code}")
            self._submit_security_proof_code(code)
            if not self._is_security_info_gate():
                return
            if self._security_code_rate_limited():
                raise RuntimeError("outlook_official_web_security_code_rate_limited")
            if self._security_verify_input_visible() and self._security_code_rejected():
                self._log("[OutlookOfficialWeb] 微软安全验证码未通过，继续等待下一封")
                continue
            self._goto("https://account.live.com/names/manage")
            self._ensure_page().wait_for_timeout(2000)
            if not self._is_security_info_gate():
                return

        raise RuntimeError("outlook_official_web_security_code_timeout")

    def _normalize_message_rows(self, raw_rows: list[dict[str, str]]) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for raw in raw_rows:
            aria = (raw.get("aria") or "").strip()
            text = (raw.get("text") or "").strip()
            subject = ""
            for source in (text, aria):
                match = re.search(r"(Your (?:OpenAI|ChatGPT|Microsoft) code is \d{4,8})", source, flags=re.I)
                if match:
                    subject = match.group(1).strip()
                    break
            if not subject:
                lines = [line.strip() for line in text.splitlines() if line.strip()]
                subject = lines[1] if len(lines) > 1 else (lines[0] if lines else text[:120].strip())
            raw_id = (raw.get("id") or "").strip() or (raw.get("convid") or "").strip()
            if not raw_id:
                digest_source = "\n".join(part for part in (aria, text, subject) if part)
                raw_id = f"digest:{hash(digest_source)}"
            rows.append(
                {
                    "id": raw_id,
                    "subject": subject,
                    "text": text or aria or subject,
                    "html": aria or text or subject,
                }
            )
        return rows

    def list_messages(self) -> list[dict[str, str]]:
        if self._use_selenium_inbox_mode():
            try:
                return self._selenium_list_messages()
            except Exception as exc:
                self._log(f"[OutlookOfficialWeb] Selenium inbox fallback 失败，回退 Playwright: {exc}")
        playwright_budget = min(max(self.poll_interval * 3, 12), 25)
        try:
            return self._run_playwright_fallback(
                self._playwright_list_messages,
                max_wait_seconds=playwright_budget,
                timeout=int(playwright_budget + 10),
            )
        except Exception as exc:
            if not self.disable_selenium:
                self._log(f"[OutlookOfficialWeb] Playwright inbox 失败，回退 Selenium: {exc}")
                return self._selenium_list_messages()
            raise

    def latest_id(self) -> str:
        items = self.list_messages()
        return items[0]["id"] if items else ""

    def recent_messages(
        self,
        baseline_id: Any,
        limit: int = 20,
        otp_sent_at: Any = None,
        slack_seconds: int = 5,
    ) -> list[dict[str, str]]:
        baseline = str(baseline_id or "").strip()
        items = self.list_messages()
        results: list[dict[str, str]] = []
        for item in items:
            if baseline and item["id"] == baseline:
                if not results:
                    results.append({"id": item["id"], "subject": item["subject"]})
                break
            results.append({"id": item["id"], "subject": item["subject"]})
            if len(results) >= limit:
                break
        return results

    def detail(self, msg_id: Any) -> dict[str, str]:
        key = str(msg_id or "").strip()
        if key not in self.cached_messages:
            self.list_messages()
        item = self.cached_messages.get(key)
        if not item:
            return {"subject": "", "text": "", "html": ""}
        return {
            "subject": item.get("subject", ""),
            "text": item.get("text", ""),
            "html": item.get("html", ""),
        }

    def _generate_official_target_email(self) -> str:
        if self.target_email:
            if "@" not in self.target_email:
                raise RuntimeError(f"outlook_official_target_email 不是有效邮箱地址: {self.target_email}")
            target_local, target_domain = self.target_email.split("@", 1)
            base_domain = self.base_email.split("@", 1)[1]
            if target_domain.lower() != base_domain.lower():
                raise RuntimeError(
                    "outlook_official_target_email 必须与 base_email 使用同一微软邮箱域"
                )
            return f"{target_local}@{target_domain}"
        if self.alias_mode in {"base", "fixed", "none"}:
            return self.base_email
        if self.alias_mode == "plus":
            local, domain = self.base_email.split("@", 1)
            suffix = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
            if self.alias_prefix:
                suffix = f"{self.alias_prefix}{suffix}"
            return f"{local}+{suffix}@{domain}"
        base_domain = self.base_email.split("@", 1)[1]
        prefix = re.sub(r"[^a-z0-9]", "", self.alias_prefix.lower()) or "aar"
        if not prefix[0].isalpha():
            prefix = f"a{prefix}"
        suffix = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
        return f"{prefix}{suffix}@{base_domain}"

    def _existing_alias_visible(self, target_email: str) -> bool:
        body = self._body_text().lower()
        return target_email.lower() in body

    def _click_add_alias(self) -> bool:
        patterns = [
            "add email",
            "add alias",
            "create a new email address",
        ]
        return self._click_control_with_text(patterns)

    def _fill_alias_form(self, target_email: str) -> None:
        page = self._ensure_page()
        local_part, target_domain = target_email.split("@", 1)
        page.wait_for_timeout(1200)

        new_address_toggle = self._click_control_with_text(
            [
                "create a new email address",
                "new email address",
                "add it as an alias",
            ]
        )
        if new_address_toggle:
            page.wait_for_timeout(1000)

        live_option = self._visible_locator(['#idLiveOption'], timeout_ms=800)
        if live_option is not None:
            try:
                live_option.check(force=True)
            except Exception:
                try:
                    live_option.click(force=True)
                except Exception:
                    pass

        input_locator = self._visible_locator(
            [
                '#AssociatedIdLive',
                'input[name*="MemberName"]',
                'input[id*="MemberName"]',
                'input[id*="AssociatedId"]',
                'input[type="text"]',
            ],
            timeout_ms=2000,
        )
        if input_locator is None and "/addassocid" in page.url.lower():
            page.wait_for_timeout(2500)
            input_locator = self._visible_locator(
                [
                    '#AssociatedIdLive',
                    'input[name*="MemberName"]',
                    'input[id*="MemberName"]',
                    'input[id*="AssociatedId"]',
                    'input[type="text"]',
                ],
                timeout_ms=2000,
            )
        if input_locator is None:
            raise RuntimeError("outlook_official_alias_input_missing")
        self._fill_text_input(input_locator, local_part)

        select_locator = self._visible_locator(["select"], timeout_ms=1000)
        if select_locator is not None:
            try:
                options = [
                    (item.get("value") or "").strip()
                    for item in select_locator.evaluate(
                        """el => Array.from(el.options).map((opt) => ({value: opt.value || '', text: opt.textContent || ''}))"""
                    )
                ]
            except Exception:
                options = []
            chosen = next((value for value in options if target_domain.lower() in value.lower()), None)
            if chosen:
                try:
                    select_locator.select_option(value=chosen)
                except Exception:
                    pass

    def _submit_alias_form(self) -> None:
        submit_locator = self._visible_locator(
            ['#SubmitYes', 'button[type="submit"]', 'input[type="submit"]'],
            timeout_ms=1200,
        )
        if submit_locator is not None:
            try:
                self._click_without_navigation_wait(submit_locator)
                return
            except Exception:
                pass
        if self._click_control_with_text(["add alias", "add email", "add username", "save"]):
            return
        raise RuntimeError("outlook_official_alias_submit_missing")

    def _create_official_alias(self) -> str:
        attempts = 1 if self.target_email else 6
        last_error = ""
        for _ in range(attempts):
            target_email = self._generate_official_target_email()
            try:
                self._open_alias_manage_page()
                if self._existing_alias_visible(target_email):
                    return target_email
                if not self._click_add_alias():
                    raise RuntimeError("outlook_official_add_alias_link_missing")
                self._ensure_page().wait_for_timeout(2000)
                self._fill_alias_form(target_email)
                self._submit_alias_form()
                page = self._ensure_page()
                page.wait_for_timeout(3000)
                body = self._body_text().lower()
                if self._is_security_info_gate():
                    raise RuntimeError(
                        "outlook_official_web_security_info_gate: 当前微软账号先要求补安全验证邮箱/手机号，"
                        "尚未进入 alias 管理页"
                    )
                if target_email.lower() in body or self._existing_alias_visible(target_email):
                    return target_email
                if any(
                    marker in body
                    for marker in (
                        "already taken",
                        "already in use",
                        "not available",
                        "try another",
                    )
                ):
                    last_error = f"alias_taken:{target_email}"
                    if self.target_email:
                        break
                    continue
                try:
                    page.wait_for_timeout(2000)
                    self._open_alias_manage_page()
                    page = self._ensure_page()
                    page.wait_for_timeout(2000)
                    refreshed_body = self._body_text().lower()
                    if target_email.lower() in refreshed_body or self._existing_alias_visible(target_email):
                        return target_email
                except Exception:
                    pass
                last_error = f"alias_create_unknown_result:{target_email}"
            except Exception as exc:
                last_error = str(exc)
                if self.target_email:
                    break
        raise RuntimeError(last_error or "outlook_official_alias_create_failed")

    def _target_visible(self, blob: str, target_email: str) -> bool:
        text = str(blob or "").lower()
        target = str(target_email or "").lower().strip()
        if target and target in text:
            return True
        otp_markers = [
            "your chatgpt code is",
            "chatgpt code is",
            "openai",
            "chatgpt",
            "microsoft account security code",
            "verification code",
            "验证码",
        ]
        return any(marker in text for marker in otp_markers)

    def get_email(self) -> MailboxAccount:
        if self.target_email or self.alias_mode in {"base", "fixed", "none", "plus"}:
            email = self._generate_official_target_email()
        else:
            email = self._create_official_alias()
        baseline_id = ""
        baseline_ids: list[str] = []
        try:
            rows = self.list_messages()
            baseline_id = rows[0]["id"] if rows else ""
            baseline_ids = [str(row.get("id") or "").strip() for row in rows[:10] if str(row.get("id") or "").strip()]
        except Exception as exc:
            self._log(f"[OutlookOfficialWeb] 拉取 baseline 失败，继续创建邮箱: {exc}")
        finally:
            if self.disable_selenium:
                self._shutdown_playwright_executor()
        self._log(f"[OutlookOfficialWeb] 使用邮箱: {email}")
        return MailboxAccount(
            email=email,
            account_id=email,
            extra={
                "provider": "outlook_official_web",
                "base_email": self.base_email,
                "login_slug": self.login_slug,
                "baseline_id": baseline_id,
                "baseline_ids": baseline_ids,
            },
        )

    def get_current_ids(self, account: MailboxAccount) -> set:
        return {str(row["id"]) for row in self.list_messages()}

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        exclude_codes = {str(code) for code in (kwargs.get("exclude_codes") or set()) if code}
        baseline_id = ""
        baseline_ids: set[str] = set()
        otp_sent_at = kwargs.get("otp_sent_at")
        if isinstance(account.extra, dict):
            baseline_id = str(account.extra.get("baseline_id") or "")
            baseline_ids = {
                str(item).strip()
                for item in (account.extra.get("baseline_ids") or [])
                if str(item).strip()
            }
        seen_ids = {str(item) for item in (before_ids or set())}
        seen_ids.update(baseline_ids)
        deadline = time.time() + timeout

        while time.time() <= deadline:
            try:
                rows = self.recent_messages(
                    baseline_id,
                    limit=20,
                    otp_sent_at=otp_sent_at,
                )
            except Exception as exc:
                self._log(f"[OutlookOfficialWeb] 拉取邮件列表失败，稍后重试: {exc}")
                time.sleep(self.poll_interval)
                continue
            for row in rows:
                msg_id = str(row["id"])
                if msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)
                try:
                    detail = self.detail(msg_id)
                except Exception as exc:
                    self._log(f"[OutlookOfficialWeb] 拉取邮件详情失败，跳过 {msg_id}: {exc}")
                    continue
                blob = "\n".join(
                    part
                    for part in [
                        str(detail.get("subject") or ""),
                        str(detail.get("text") or ""),
                        str(detail.get("html") or ""),
                    ]
                    if part
                )
                if keyword and keyword.lower() not in blob.lower() and not self._target_visible(blob, account.email):
                    continue
                if not keyword and not self._target_visible(blob, account.email):
                    continue
                code = self._safe_extract(blob, code_pattern)
                if code and code not in exclude_codes:
                    self._log(f"[OutlookOfficialWeb] 收到验证码: {code}")
                    return code
            time.sleep(self.poll_interval)

        raise TimeoutError(f"等待验证码超时 ({timeout}s)")
