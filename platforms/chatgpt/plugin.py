"""ChatGPT / Codex CLI 平台插件"""
import random, string
from core.base_platform import BasePlatform, Account, AccountStatus, RegisterConfig
from core.base_mailbox import BaseMailbox
from core.registry import register


@register
class ChatGPTPlatform(BasePlatform):
    name = "chatgpt"
    display_name = "ChatGPT"
    version = "1.0.0"

    def __init__(self, config: RegisterConfig = None, mailbox: BaseMailbox = None):
        super().__init__(config)
        self.mailbox = mailbox

    def check_valid(self, account: Account) -> bool:
        try:
            from platforms.chatgpt.payment import check_subscription_status
            class _A: pass
            a = _A()
            extra = account.extra or {}
            a.access_token = extra.get("access_token") or account.token
            a.cookies = extra.get("cookies", "")
            status = check_subscription_status(a, proxy=self.config.proxy if self.config else None)
            return status not in ("expired", "invalid", "banned", None)
        except Exception:
            return False

    def register(self, email: str = None, password: str = None) -> Account:
        if not password:
            password = "".join(random.choices(
                string.ascii_letters + string.digits + "!@#$", k=16))

        proxy = self.config.proxy if self.config else None
        browser_mode = (self.config.executor_type if self.config else None) or "protocol"
        log_fn = getattr(self, '_log_fn', print)
        from platforms.chatgpt.register_v2 import RegistrationEngineV2 as RegistrationEngine
        log_fn = getattr(self, '_log_fn', print)
        max_retries = 3
        skip_chatgpt_web_upgrade = False
        fixed_first_name = ""
        fixed_last_name = ""
        fixed_birthdate = ""
        if self.config and getattr(self.config, "extra", None):
            try:
                max_retries = int((self.config.extra or {}).get("register_max_retries", 3) or 3)
            except Exception:
                max_retries = 3
            try:
                raw_skip = (self.config.extra or {}).get("skip_chatgpt_web_upgrade", False)
                skip_chatgpt_web_upgrade = str(raw_skip).strip().lower() in {"1", "true", "yes", "on"}
            except Exception:
                skip_chatgpt_web_upgrade = False
            try:
                fixed_first_name = str((self.config.extra or {}).get("chatgpt_fixed_first_name", "") or "").strip()
                fixed_last_name = str((self.config.extra or {}).get("chatgpt_fixed_last_name", "") or "").strip()
                fixed_birthdate = str((self.config.extra or {}).get("chatgpt_fixed_birthdate", "") or "").strip()
            except Exception:
                fixed_first_name = ""
                fixed_last_name = ""
                fixed_birthdate = ""

        if self.mailbox:
            # 通用 EmailService 适配器，支持所有 BaseMailbox 实现 (cfworker, duckmail, laoudo 等)
            _mailbox = self.mailbox
            _fixed_email = email
            email_service = None

            class GenericEmailService:
                service_type = type('ST', (), {'value': 'custom_provider'})()
                def __init__(self):
                    self._acct = None
                    self._email = _fixed_email
                    self.mailbox_class = type(_mailbox).__name__
                def create_email(self, config=None):
                    if self._email and self._acct and _fixed_email:
                        return {'email': self._email, 'service_id': self._acct.account_id, 'token': ''}
                    self._acct = _mailbox.get_email()
                    if not self._email:
                        self._email = self._acct.email
                    elif not _fixed_email:
                        self._email = self._acct.email
                    return {'email': self._email, 'service_id': self._acct.account_id, 'token': ''}
                def get_verification_code(self, email=None, email_id=None, timeout=120, pattern=None, otp_sent_at=None, exclude_codes=None):
                    if not self._acct:
                        raise RuntimeError("邮箱账户尚未创建，无法获取验证码")
                    return _mailbox.wait_for_code(
                        self._acct,
                        keyword="",
                        timeout=timeout,
                        otp_sent_at=otp_sent_at,
                        exclude_codes=exclude_codes,
                    )
                def update_status(self, success, error=None): pass
                @property
                def status(self): return None

            email_service = GenericEmailService()
            engine = RegistrationEngine(
                email_service=email_service,
                proxy_url=proxy,
                browser_mode=browser_mode,
                callback_logger=log_fn,
                max_retries=max_retries,
                skip_chatgpt_web_upgrade=skip_chatgpt_web_upgrade,
            )
            engine.email = email
            engine.password = password
        else:
            # 兼容逻辑：若未传入 mailbox 则默认使用 tempmail_lol
            from core.base_mailbox import TempMailLolMailbox
            _tmail = TempMailLolMailbox(proxy=proxy)

            class TempMailEmailService:
                service_type = type('ST', (), {'value': 'tempmail_lol'})()
                def create_email(self, config=None):
                    acct = _tmail.get_email()
                    self._acct = acct
                    return {'email': acct.email, 'service_id': acct.account_id, 'token': acct.account_id}
                def get_verification_code(self, email=None, email_id=None, timeout=120, pattern=None, otp_sent_at=None, exclude_codes=None):
                    return _tmail.wait_for_code(
                        self._acct,
                        keyword="",
                        timeout=timeout,
                        otp_sent_at=otp_sent_at,
                        exclude_codes=exclude_codes,
                    )
                def update_status(self, success, error=None): pass
                @property
                def status(self): return None

            engine = RegistrationEngine(
                email_service=TempMailEmailService(),
                proxy_url=proxy,
                browser_mode=browser_mode,
                callback_logger=log_fn,
                max_retries=max_retries,
                skip_chatgpt_web_upgrade=skip_chatgpt_web_upgrade,
            )
            if email:
                engine.email = email
                engine.password = password

        if fixed_first_name and fixed_last_name and fixed_birthdate:
            engine.fixed_first_name = fixed_first_name
            engine.fixed_last_name = fixed_last_name
            engine.fixed_birthdate = fixed_birthdate

        result = engine.run()
        if not result or not result.success:
            raise RuntimeError(result.error_message if result else '注册失败')

        extra = {
            'access_token':  result.access_token,
            'refresh_token': result.refresh_token,
            'id_token':      result.id_token,
            'session_token': result.session_token,
            'workspace_id':  result.workspace_id,
        }
        mailbox_account = None
        if self.mailbox and getattr(engine.email_service, "_acct", None) is not None:
            mailbox_account = engine.email_service._acct
        if mailbox_account is not None:
            if getattr(mailbox_account, "account_id", ""):
                extra["mailbox_account_id"] = mailbox_account.account_id
                extra.setdefault("mailbox_token", mailbox_account.account_id)
            if getattr(mailbox_account, "email", ""):
                extra["mailbox_email"] = mailbox_account.email
            mailbox_extra = getattr(mailbox_account, "extra", None) or {}
            if isinstance(mailbox_extra, dict):
                for key, value in mailbox_extra.items():
                    if value not in (None, "", [], {}):
                        extra[key] = value
        metadata = result.metadata or {}
        for key in (
            'auth_provider',
            'expires',
            'user_id',
            'user',
            'account',
            'recovered_existing_account',
            'cookies',
            'cookie_bundle',
            'cf_clearance',
            'oai_did',
            'oai_sc',
            'skip_chatgpt_web_upgrade',
            'access_token_client_id',
            'access_token_audience',
            'access_token_scopes',
            'id_token_audience',
            'has_refresh_token',
            'has_session_token',
            'initial_auth_provider',
            'initial_access_token_client_id',
            'initial_access_token_audience',
            'initial_access_token_scopes',
            'initial_id_token_audience',
            'initial_has_refresh_token',
            'initial_has_session_token',
            'oauth_existing_failure',
            'oauth_existing_state',
            'codex_existing_failure',
            'codex_existing_state',
            'web_upgrade_failure',
            'web_upgrade_state',
            'codex_upgrade_failure',
            'codex_upgrade_state',
        ):
            value = metadata.get(key)
            if value not in (None, '', [], {}):
                extra[key] = value

        return Account(
            platform='chatgpt',
            email=result.email,
            password=result.password or password,
            user_id=result.account_id,
            token=result.access_token,
            status=AccountStatus.REGISTERED,
            extra=extra,
        )

    def get_platform_actions(self) -> list:
        return [
            {"id": "refresh_token", "label": "刷新 Token", "params": []},
            {"id": "payment_link", "label": "生成支付链接",
             "params": [
                 {"key": "country", "label": "地区", "type": "select",
                  "options": ["US","SG","TR","HK","JP","GB","AU","CA"]},
                 {"key": "plan", "label": "套餐", "type": "select",
                  "options": ["plus", "team"]},
             ]},
            {"id": "upload_cpa", "label": "上传 CPA",
             "params": [
                 {"key": "api_url", "label": "CPA API URL", "type": "text"},
                 {"key": "api_key", "label": "CPA API Key", "type": "text"},
             ]},
            {"id": "upload_tm", "label": "上传 Team Manager",
             "params": [
                 {"key": "api_url", "label": "TM API URL", "type": "text"},
                 {"key": "api_key", "label": "TM API Key", "type": "text"},
             ]},
        ]

    def execute_action(self, action_id: str, account: Account, params: dict) -> dict:
        proxy = self.config.proxy if self.config else None
        extra = account.extra or {}

        class _A: pass
        a = _A()
        a.email = account.email
        a.access_token = extra.get("access_token") or account.token
        a.refresh_token = extra.get("refresh_token", "")
        a.id_token = extra.get("id_token", "")
        a.session_token = extra.get("session_token", "")
        a.client_id = (
            extra.get("client_id")
            or extra.get("access_token_client_id")
            or "app_EMoamEEZ73f0CkXaXp7hrann"
        )
        a.cookies = extra.get("cookies", "")

        if action_id == "refresh_token":
            from platforms.chatgpt.token_refresh import TokenRefreshManager
            manager = TokenRefreshManager(proxy_url=proxy)
            result = manager.refresh_account(a)
            if result.success:
                return {"ok": True, "data": {"access_token": result.access_token,
                        "refresh_token": result.refresh_token}}
            return {"ok": False, "error": result.error_message}

        elif action_id == "payment_link":
            from platforms.chatgpt.payment import generate_plus_link, generate_team_link
            plan = params.get("plan", "plus")
            country = params.get("country", "US")
            if plan == "plus":
                url = generate_plus_link(a, proxy=proxy, country=country)
            else:
                url = generate_team_link(a, proxy=proxy, country=country)
            return {"ok": bool(url), "data": {"url": url}}

        elif action_id == "upload_cpa":
            from platforms.chatgpt.cpa_upload import upload_to_cpa, generate_token_json
            token_data = generate_token_json(a)
            ok, msg = upload_to_cpa(token_data, api_url=params.get("api_url"),
                                    api_key=params.get("api_key"))
            return {"ok": ok, "data": msg}

        elif action_id == "upload_tm":
            from platforms.chatgpt.cpa_upload import upload_to_team_manager
            ok, msg = upload_to_team_manager(a, api_url=params.get("api_url"),
                                             api_key=params.get("api_key"))
            return {"ok": ok, "data": msg}

        raise NotImplementedError(f"未知操作: {action_id}")
