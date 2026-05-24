"""
注册流程引擎 V2
基于 curl_cffi 的注册状态机，注册成功后直接复用同一会话提取 ChatGPT Session。
"""

import time
import logging
from datetime import datetime
from typing import Optional, Callable

from core.base_platform import AccountStatus
from platforms.chatgpt.register import RegistrationResult

from .chatgpt_client import ChatGPTClient
from .oauth_client import OAuthClient
from .utils import generate_random_name, generate_random_birthday, decode_jwt_payload

logger = logging.getLogger(__name__)

class EmailServiceAdapter:
    """\u5c06 V1 \u7684 email_service \u9002\u914d\u6210 V2 \u6240\u9700\u7684\u63a5\u7801\u63a5\u53e3\u3002"""
    def __init__(self, email_service, email, log_fn):
        self.es = email_service
        self.email = email
        self.log_fn = log_fn
        self._used_codes = set()

    def wait_for_verification_code(self, email, timeout=60, otp_sent_at=None, exclude_codes=None):
        msg = f"\u6b63\u5728\u7b49\u5f85\u90ae\u7bb1 {email} \u7684\u9a8c\u8bc1\u7801 ({timeout}s)..."
        self.log_fn(msg)
        effective_exclude_codes = self._used_codes if exclude_codes is None else exclude_codes
        code = self.es.get_verification_code(
            timeout=timeout,
            otp_sent_at=otp_sent_at,
            exclude_codes=effective_exclude_codes,
        )
        if code:
            self._used_codes.add(code)
            self.log_fn(f"\u6210\u529f\u83b7\u53d6\u9a8c\u8bc1\u7801: {code}")
        return code

class RegistrationEngineV2:
    def __init__(
        self,
        email_service,
        proxy_url: Optional[str] = None,
        browser_mode: str = "protocol",
        callback_logger: Optional[Callable[[str], None]] = None,
        task_uuid: Optional[str] = None,
        max_retries: int = 3,
        skip_chatgpt_web_upgrade: bool = False,
    ):
        self.email_service = email_service
        self.proxy_url = proxy_url
        self.browser_mode = browser_mode or "protocol"
        self.callback_logger = callback_logger
        self.task_uuid = task_uuid
        self.max_retries = max(1, int(max_retries or 1))
        self.skip_chatgpt_web_upgrade = bool(skip_chatgpt_web_upgrade)
        
        self.email = None
        self.password = None
        self.logs = []
        self.fixed_first_name = ""
        self.fixed_last_name = ""
        self.fixed_birthdate = ""

    def _build_token_lineage_metadata(
        self,
        *,
        access_token: str = "",
        id_token: str = "",
        refresh_token: str = "",
        session_token: str = "",
        auth_provider: str = "",
        prefix: str = "",
    ) -> dict:
        access_payload = decode_jwt_payload(str(access_token or "").strip())
        id_payload = decode_jwt_payload(str(id_token or "").strip())
        data = {
            f"{prefix}auth_provider": str(auth_provider or "").strip(),
            f"{prefix}access_token_client_id": str(access_payload.get("client_id") or "").strip(),
            f"{prefix}access_token_audience": access_payload.get("aud") or [],
            f"{prefix}access_token_scopes": access_payload.get("scp") or [],
            f"{prefix}id_token_audience": id_payload.get("aud") or [],
            f"{prefix}has_refresh_token": bool(refresh_token),
            f"{prefix}has_session_token": bool(session_token),
        }
        return {
            key: value
            for key, value in data.items()
            if value not in ("", None, [], {})
        }
        
    def _log(self, message: str, level: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        self.logs.append(log_message)
        if self.callback_logger:
            self.callback_logger(log_message)
        if level == "error":
            logger.error(log_message)
        else:
            logger.info(log_message)

    def _should_retry(self, message: str) -> bool:
        text = str(message or "").lower()
        retriable_markers = [
            "tls",
            "ssl",
            "curl: (35)",
            "预授权被拦截",
            "authorize",
            "registration_disallowed",
            "http 400",
            "创建账号失败",
            "未获取到 authorization code",
            "consent",
            "workspace",
            "organization",
            "otp",
            "验证码",
            "session",
            "accessToken",
            "next-auth",
        ]
        return any(marker.lower() in text for marker in retriable_markers)

    def run(self) -> RegistrationResult:
        result = RegistrationResult(success=False, logs=self.logs)
        try:
            last_error = ""
            for attempt in range(self.max_retries):
                try:
                    if attempt == 0:
                        self._log("=" * 60)
                        self._log("开始注册流程 V2 (Session 复用直取 AccessToken)")
                        self._log(f"请求模式: {self.browser_mode}")
                        self._log("=" * 60)
                    else:
                        self._log(f"整流程重试 {attempt + 1}/{self.max_retries} ...")
                        time.sleep(1)

                    # 1. 创建邮箱
                    email_data = self.email_service.create_email()
                    email_addr = self.email or (email_data.get('email') if email_data else None)
                    if not email_addr:
                        result.error_message = "创建邮箱失败"
                        return result

                    result.email = email_addr

                    pwd = self.password or "AAb1234567890!"
                    result.password = pwd

                    # 姓名、生日：若上层明确指定则优先使用，否则随机生成
                    if self.fixed_first_name and self.fixed_last_name and self.fixed_birthdate:
                        first_name = self.fixed_first_name
                        last_name = self.fixed_last_name
                        birthdate = self.fixed_birthdate
                    else:
                        first_name, last_name = generate_random_name()
                        birthdate = generate_random_birthday()

                    self._log(f"邮箱: {email_addr}, 密码: {pwd}")
                    self._log(f"注册信息: {first_name} {last_name}, 生日: {birthdate}")

                    # 使用包装器为底层客户端提供接码服务
                    skymail_adapter = EmailServiceAdapter(self.email_service, email_addr, self._log)

                    # 2. 初始化 V2 客户端
                    chatgpt_client = ChatGPTClient(
                        proxy=self.proxy_url,
                        verbose=False,
                        browser_mode=self.browser_mode,
                    )
                    chatgpt_client._log = self._log

                    self._log("步骤 1/2: 执行注册状态机...")

                    success, msg = chatgpt_client.register_complete_flow(
                        email_addr, pwd, first_name, last_name, birthdate, skymail_adapter
                    )

                    existing_account_recovery = False
                    force_oauth_existing_account_recovery = False
                    oauth_existing_failure = ""
                    oauth_existing_state = ""
                    codex_existing_failure = ""
                    codex_existing_state = ""
                    if not success:
                        last_error = f"注册流失败: {msg}"
                        if attempt < self.max_retries - 1 and self._should_retry(msg):
                            self._log(f"注册流失败，准备整流程重试: {msg}")
                            continue
                        result.error_message = last_error
                        return result

                    if str(msg or "").strip() == "existing_account_login":
                        force_oauth_existing_account_recovery = True
                        self._log("检测到 existing-account 登录桥，跳过 next-auth / web bridge，直接走 OAuth token 恢复")

                    self._log("步骤 2/2: 复用注册会话，直接获取 ChatGPT Session / AccessToken...")
                    session_ok = False
                    session_result = "existing_account_login"
                    initial_session_result = {}
                    if not force_oauth_existing_account_recovery:
                        session_ok, session_result = chatgpt_client.reuse_session_and_get_tokens()
                        if isinstance(session_result, dict):
                            initial_session_result = dict(session_result)
                            initial_client_id = self._build_token_lineage_metadata(
                                access_token=session_result.get("access_token", ""),
                                id_token=session_result.get("id_token", ""),
                                refresh_token=session_result.get("refresh_token", ""),
                                session_token=session_result.get("session_token", ""),
                                auth_provider=session_result.get("auth_provider", ""),
                            ).get("access_token_client_id", "")
                            self._log(
                                "初始会话 lineage: "
                                f"provider={session_result.get('auth_provider', '') or 'unknown'} "
                                f"client_id={initial_client_id or 'unknown'} "
                                f"refresh={'yes' if session_result.get('refresh_token') else 'no'}"
                            )
                    if (not force_oauth_existing_account_recovery) and (not session_ok) and ('缺少 __Secure-next-auth.session-token' in str(session_result)):
                        self._log('未拿到 next-auth session，先走 ChatGPT Web next-auth bridge 恢复 session ...')
                        session_ok, session_result = chatgpt_client.bridge_existing_auth_to_web_session(
                            email_addr,
                            skymail_client=skymail_adapter,
                            profile={
                                'first_name': first_name,
                                'last_name': last_name,
                                'birthdate': birthdate,
                            },
                        )
                        if session_ok:
                            existing_account_recovery = True
                        else:
                            self._log(f'ChatGPT Web bridge 恢复失败: {session_result}')
                            self._log('改走 existing-account OAuth 登录恢复 token（次级兜底）...')
                    if force_oauth_existing_account_recovery or (not session_ok):
                        if not force_oauth_existing_account_recovery:
                            self._log('改走 existing-account OAuth 登录恢复 token（次级兜底）...')
                        oauth_client = OAuthClient(
                            {
                                'oauth_client_id': 'app_X8zY6vW2pQ9tR3dE7nK1jL5gH',
                                'oauth_redirect_uri': 'https://chatgpt.com/api/auth/callback/openai',
                                'oauth_scope': 'openid email profile offline_access model.request model.read organization.read organization.write',
                                'oauth_audience': 'https://api.openai.com/v1',
                                'oauth_extra_authorize_params': {},
                            },
                            proxy=self.proxy_url,
                            verbose=False,
                            browser_mode=self.browser_mode,
                            session=chatgpt_client.session,
                        )
                        oauth_client._log = self._log
                        if isinstance(session_result, dict):
                            oauth_client.chatgpt_session_seed = dict(session_result)
                        if force_oauth_existing_account_recovery:
                            oauth_client.prefer_email_otp_first = True
                            oauth_client.reuse_existing_email_code_once = False
                        tokens = oauth_client.login_and_get_tokens(
                            email_addr,
                            pwd,
                            chatgpt_client.device_id,
                            user_agent=chatgpt_client.ua,
                            sec_ch_ua=chatgpt_client.sec_ch_ua,
                            impersonate=chatgpt_client.impersonate,
                            skymail_client=skymail_adapter,
                            profile={
                                'first_name': first_name,
                                'last_name': last_name,
                                'birthdate': birthdate,
                            },
                        )
                        if tokens:
                            session_ok = True
                            session_result = {
                                'access_token': tokens.get('access_token', ''),
                                'session_token': '',
                                'account_id': tokens.get('workspace_id', ''),
                                'user_id': '',
                                'workspace_id': tokens.get('workspace_id', ''),
                                'auth_provider': 'oauth_existing_account',
                                'expires': tokens.get('expires_in', ''),
                                'user': {},
                                'account': {},
                                'refresh_token': tokens.get('refresh_token', ''),
                                'id_token': tokens.get('id_token', ''),
                            }
                            existing_account_recovery = True
                        else:
                            self._log('existing-account OAuth 恢复失败')
                            oauth_existing_failure = str(
                                getattr(oauth_client, 'last_login_failure_reason', '') or ''
                            ).strip()
                            oauth_existing_state = str(
                                getattr(oauth_client, 'last_flow_state_description', '') or ''
                            ).strip()
                            if oauth_existing_failure:
                                self._log(f'existing-account OAuth 失败原因: {oauth_existing_failure}')
                            if oauth_existing_state:
                                self._log(f'existing-account OAuth 最后状态: {oauth_existing_state}')
                            self._log('改试 direct Codex localhost OAuth 恢复 token...')
                            codex_recovery_tokens = None
                            try:
                                codex_recovery_client = OAuthClient(
                                    {
                                        'oauth_client_id': 'app_EMoamEEZ73f0CkXaXp7hrann',
                                        'oauth_redirect_uri': 'http://localhost:1455/auth/callback',
                                        'oauth_scope': 'openid profile email offline_access',
                                        'oauth_audience': None,
                                        'oauth_prompt': '',
                                        'oauth_extra_authorize_params': {
                                            'id_token_add_organizations': 'true',
                                            'codex_cli_simplified_flow': 'true',
                                        },
                                    },
                                    proxy=self.proxy_url,
                                    verbose=False,
                                    browser_mode=self.browser_mode,
                                    session=chatgpt_client.session,
                                )
                                codex_recovery_client._log = self._log
                                if isinstance(session_result, dict):
                                    codex_recovery_client.chatgpt_session_seed = dict(session_result)
                                if force_oauth_existing_account_recovery:
                                    codex_recovery_client.prefer_email_otp_first = True
                                    codex_recovery_client.reuse_existing_email_code_once = False
                                codex_recovery_tokens = codex_recovery_client.login_and_get_tokens(
                                    email_addr,
                                    pwd,
                                    chatgpt_client.device_id,
                                    user_agent=chatgpt_client.ua,
                                    sec_ch_ua=chatgpt_client.sec_ch_ua,
                                    impersonate=chatgpt_client.impersonate,
                                    skymail_client=skymail_adapter,
                                    profile={
                                        'first_name': first_name,
                                        'last_name': last_name,
                                        'birthdate': birthdate,
                                    },
                                )
                            except Exception as codex_recovery_error:
                                self._log(f"direct Codex localhost OAuth 恢复异常: {codex_recovery_error}")

                            if (
                                codex_recovery_tokens
                                and codex_recovery_tokens.get('access_token')
                                and codex_recovery_tokens.get('refresh_token')
                            ):
                                session_ok = True
                                session_result = {
                                    'access_token': codex_recovery_tokens.get('access_token', ''),
                                    'session_token': '',
                                    'account_id': codex_recovery_tokens.get('workspace_id', ''),
                                    'user_id': '',
                                    'workspace_id': codex_recovery_tokens.get('workspace_id', ''),
                                    'auth_provider': 'oauth_codex_localhost',
                                    'expires': codex_recovery_tokens.get('expires_in', ''),
                                    'user': {},
                                    'account': {},
                                    'refresh_token': codex_recovery_tokens.get('refresh_token', ''),
                                    'id_token': codex_recovery_tokens.get('id_token', ''),
                                }
                                existing_account_recovery = True
                                self._log('direct Codex localhost OAuth 恢复成功')
                            else:
                                self._log('direct Codex localhost OAuth 恢复失败')
                                codex_existing_failure = str(
                                    getattr(codex_recovery_client, 'last_login_failure_reason', '') or ''
                                ).strip()
                                codex_existing_state = str(
                                    getattr(codex_recovery_client, 'last_flow_state_description', '') or ''
                                ).strip()
                                if codex_existing_failure:
                                    self._log(f'direct Codex localhost OAuth 失败原因: {codex_existing_failure}')
                                if codex_existing_state:
                                    self._log(f'direct Codex localhost OAuth 最后状态: {codex_existing_state}')

                    if session_ok:
                        web_upgrade_failure = ""
                        web_upgrade_state = ""
                        codex_upgrade_failure = ""
                        codex_upgrade_state = ""
                        if (
                            isinstance(session_result, dict)
                            and session_result.get('auth_provider') == 'oauth_codex_localhost'
                            and session_result.get('access_token')
                            and session_result.get('refresh_token')
                        ):
                            self._log("步骤 2.5/2: 已直接拿到 Codex localhost OAuth token，跳过后续升级")
                        else:
                            if self.skip_chatgpt_web_upgrade:
                                self._log("步骤 2.5/2: 按配置跳过 ChatGPT Web OAuth token 升级")
                            else:
                                self._log("步骤 2.5/2: 尝试升级为 ChatGPT Web OAuth token...")
                                web_oauth_tokens = None
                                try:
                                    if hasattr(chatgpt_client, "clear_next_auth_transient_cookies"):
                                        chatgpt_client.clear_next_auth_transient_cookies()
                                    web_oauth_client = OAuthClient(
                                        {
                                            'oauth_client_id': 'app_X8zY6vW2pQ9tR3dE7nK1jL5gH',
                                            'oauth_redirect_uri': 'https://chatgpt.com/api/auth/callback/openai',
                                            'oauth_scope': 'openid email profile offline_access model.request model.read organization.read organization.write',
                                            'oauth_audience': 'https://api.openai.com/v1',
                                            'oauth_extra_authorize_params': {},
                                        },
                                        proxy=self.proxy_url,
                                        verbose=False,
                                        browser_mode=self.browser_mode,
                                        session=chatgpt_client.session,
                                    )
                                    web_oauth_client._log = self._log
                                    if isinstance(session_result, dict):
                                        web_oauth_client.chatgpt_session_seed = dict(session_result)
                                    web_oauth_tokens = web_oauth_client.login_and_get_tokens(
                                        email_addr,
                                        pwd,
                                        chatgpt_client.device_id,
                                        user_agent=chatgpt_client.ua,
                                        sec_ch_ua=chatgpt_client.sec_ch_ua,
                                        impersonate=chatgpt_client.impersonate,
                                        skymail_client=skymail_adapter,
                                        profile={
                                            'first_name': first_name,
                                            'last_name': last_name,
                                            'birthdate': birthdate,
                                        },
                                    )
                                except Exception as web_upgrade_error:
                                    self._log(f"ChatGPT Web OAuth 升级异常: {web_upgrade_error}")
                                    web_upgrade_failure = str(web_upgrade_error or "").strip() or "web_upgrade_exception"

                                if web_oauth_tokens and web_oauth_tokens.get('access_token') and web_oauth_tokens.get('refresh_token'):
                                    session_result = {
                                        **session_result,
                                        'access_token': web_oauth_tokens.get('access_token', ''),
                                        'refresh_token': web_oauth_tokens.get('refresh_token', ''),
                                        'id_token': web_oauth_tokens.get('id_token', ''),
                                        'expires': web_oauth_tokens.get('expires_in', ''),
                                        'auth_provider': 'oauth_chatgpt_web',
                                    }
                                    self._log("ChatGPT Web OAuth token 升级成功")
                                else:
                                    web_upgrade_failure = web_upgrade_failure or str(
                                        getattr(web_oauth_client, 'last_login_failure_reason', '') or ''
                                    ).strip()
                                    web_upgrade_state = str(
                                        getattr(web_oauth_client, 'last_flow_state_description', '') or ''
                                    ).strip()
                                    self._log("ChatGPT Web OAuth token 升级失败，回退 Codex localhost OAuth token...")
                                    if web_upgrade_failure:
                                        self._log(
                                            f"ChatGPT Web OAuth 升级失败原因: {web_upgrade_failure}"
                                        )
                                    if web_upgrade_state:
                                        self._log(
                                            f"ChatGPT Web OAuth 最后状态: {web_upgrade_state}"
                                        )

                            self._log("步骤 2.6/2: 尝试升级为 Codex localhost OAuth token...")
                            codex_tokens = None
                            try:
                                codex_oauth_client = OAuthClient(
                                    {
                                        'oauth_client_id': 'app_EMoamEEZ73f0CkXaXp7hrann',
                                        'oauth_redirect_uri': 'http://localhost:1455/auth/callback',
                                        'oauth_scope': 'openid profile email offline_access',
                                        'oauth_audience': None,
                                        'oauth_prompt': '',
                                        'oauth_extra_authorize_params': {
                                            'id_token_add_organizations': 'true',
                                            'codex_cli_simplified_flow': 'true',
                                        },
                                    },
                                    proxy=self.proxy_url,
                                    verbose=False,
                                    browser_mode=self.browser_mode,
                                    session=chatgpt_client.session,
                                )
                                codex_oauth_client._log = self._log
                                if isinstance(session_result, dict):
                                    codex_oauth_client.chatgpt_session_seed = dict(session_result)
                                codex_oauth_client.direct_authorize_before_about_you_once = True
                                codex_tokens = codex_oauth_client.login_and_get_tokens(
                                    email_addr,
                                    pwd,
                                    chatgpt_client.device_id,
                                    user_agent=chatgpt_client.ua,
                                    sec_ch_ua=chatgpt_client.sec_ch_ua,
                                    impersonate=chatgpt_client.impersonate,
                                    skymail_client=skymail_adapter,
                                    profile={
                                        'first_name': first_name,
                                        'last_name': last_name,
                                        'birthdate': birthdate,
                                    },
                                )
                            except Exception as codex_upgrade_error:
                                self._log(f"Codex localhost OAuth 升级异常: {codex_upgrade_error}")

                            if (
                                codex_tokens
                                and codex_tokens.get('access_token')
                                and codex_tokens.get('refresh_token')
                            ):
                                session_result = {
                                    **session_result,
                                    'access_token': codex_tokens.get('access_token', ''),
                                    'refresh_token': codex_tokens.get('refresh_token', ''),
                                    'id_token': codex_tokens.get('id_token', ''),
                                    'expires': codex_tokens.get('expires_in', ''),
                                    'auth_provider': 'oauth_codex_localhost',
                                }
                                self._log("Codex localhost OAuth token 升级成功")
                            else:
                                self._log("Codex localhost OAuth token 升级失败，保留当前 ChatGPT Web token")
                                codex_upgrade_failure = str(
                                    getattr(codex_oauth_client, 'last_login_failure_reason', '') or ''
                                ).strip()
                                codex_upgrade_state = str(
                                    getattr(codex_oauth_client, 'last_flow_state_description', '') or ''
                                ).strip()
                                if codex_upgrade_failure:
                                    self._log(
                                        f"Codex localhost OAuth 升级失败原因: {codex_upgrade_failure}"
                                    )
                                if codex_upgrade_state:
                                    self._log(
                                        f"Codex localhost OAuth 最后状态: {codex_upgrade_state}"
                                    )

                        self._log("Token 提取完成！")
                        result.success = True
                        result.access_token = session_result.get("access_token", "")
                        result.session_token = session_result.get("session_token", "")
                        result.refresh_token = session_result.get("refresh_token", "")
                        result.id_token = session_result.get("id_token", "")
                        result.account_id = (
                            session_result.get("account_id")
                            or session_result.get("user_id")
                            or session_result.get("workspace_id")
                            or ("v2_acct_" + chatgpt_client.device_id[:8])
                        )
                        result.workspace_id = session_result.get("workspace_id", "")
                        result.metadata = {
                            "auth_provider": session_result.get("auth_provider", ""),
                            "expires": session_result.get("expires", ""),
                            "user_id": session_result.get("user_id", ""),
                            "user": session_result.get("user") or {},
                            "account": session_result.get("account") or {},
                            "recovered_existing_account": existing_account_recovery,
                            "cookies": session_result.get("cookies", ""),
                            "cookie_bundle": session_result.get("cookie_bundle") or {},
                            "cf_clearance": session_result.get("cf_clearance", ""),
                            "oai_did": session_result.get("oai_did", ""),
                            "oai_sc": session_result.get("oai_sc", ""),
                            "skip_chatgpt_web_upgrade": self.skip_chatgpt_web_upgrade,
                        }
                        result.metadata.update(
                            self._build_token_lineage_metadata(
                                access_token=result.access_token,
                                id_token=result.id_token,
                                refresh_token=result.refresh_token,
                                session_token=result.session_token,
                                auth_provider=session_result.get("auth_provider", ""),
                            )
                        )
                        if initial_session_result:
                            result.metadata.update(
                                self._build_token_lineage_metadata(
                                    access_token=initial_session_result.get("access_token", ""),
                                    id_token=initial_session_result.get("id_token", ""),
                                    refresh_token=initial_session_result.get("refresh_token", ""),
                                    session_token=initial_session_result.get("session_token", ""),
                                    auth_provider=initial_session_result.get("auth_provider", ""),
                                    prefix="initial_",
                                )
                            )
                        for key, value in (
                            ("oauth_existing_failure", oauth_existing_failure),
                            ("oauth_existing_state", oauth_existing_state),
                            ("codex_existing_failure", codex_existing_failure),
                            ("codex_existing_state", codex_existing_state),
                            ("web_upgrade_failure", web_upgrade_failure),
                            ("web_upgrade_state", web_upgrade_state),
                            ("codex_upgrade_failure", codex_upgrade_failure),
                            ("codex_upgrade_state", codex_upgrade_state),
                        ):
                            if value:
                                result.metadata[key] = value

                        if result.workspace_id:
                            self._log(f"Session Workspace ID: {result.workspace_id}")
                        final_client_id = result.metadata.get("access_token_client_id", "")
                        if final_client_id:
                            self._log(
                                "最终 token lineage: "
                                f"provider={result.metadata.get('auth_provider', '') or 'unknown'} "
                                f"client_id={final_client_id} "
                                f"refresh={'yes' if result.refresh_token else 'no'}"
                            )

                        self._log("=" * 60)
                        self._log("注册流程成功结束!")
                        self._log("=" * 60)
                        return result

                    detail_reasons = []
                    if oauth_existing_failure:
                        detail_reasons.append(f"oauth_existing={oauth_existing_failure}")
                    if oauth_existing_state:
                        detail_reasons.append(f"oauth_existing_state={oauth_existing_state}")
                    if codex_existing_failure:
                        detail_reasons.append(f"oauth_codex_localhost={codex_existing_failure}")
                    if codex_existing_state:
                        detail_reasons.append(f"oauth_codex_localhost_state={codex_existing_state}")
                    detail_suffix = f" ({'; '.join(detail_reasons)})" if detail_reasons else ""
                    last_error = f"注册成功，但复用会话获取 AccessToken 失败: {session_result}{detail_suffix}"
                    if attempt < self.max_retries - 1:
                        self._log(f"{last_error}，准备整流程重试")
                        continue
                    result.error_message = last_error
                    return result
                except Exception as attempt_error:
                    last_error = str(attempt_error)
                    if attempt < self.max_retries - 1 and self._should_retry(last_error):
                        self._log(f"本轮出现异常，准备整流程重试: {last_error}")
                        continue
                    raise

            result.error_message = last_error or "注册失败"
            return result
                
        except Exception as e:
            self._log(f"V2 注册全流程执行异常: {e}", "error")
            import traceback
            traceback.print_exc()
            result.error_message = str(e)
            return result
