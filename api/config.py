from fastapi import APIRouter
from pydantic import BaseModel
from core.config_store import config_store

router = APIRouter(prefix="/config", tags=["config"])

CONFIG_KEYS = [
    "laoudo_auth", "laoudo_email", "laoudo_account_id",
    "yescaptcha_key", "twocaptcha_key",
    "default_executor", "default_captcha_solver",
    "duckmail_api_url", "duckmail_provider_url", "duckmail_bearer",
    "freemail_api_url", "freemail_admin_token", "freemail_username", "freemail_password",
    "moemail_api_url",
    "mail_provider",
    "imap_mailbox_secret_path", "imap_target_email", "imap_alias_mode", "imap_alias_prefix",
    "imap_mailbox", "imap_from_filter", "imap_subject_filter", "imap_code_pattern",
    "imap_lookback_seconds", "imap_poll_interval", "imap_max_fetch",
    "outlook_webmail_pool_secret", "outlook_webmail_login_slug", "outlook_webmail_base_email",
    "outlook_webmail_base_url", "outlook_webmail_alias_mode", "outlook_webmail_alias_prefix",
    "outlook_webmail_target_email", "outlook_webmail_poll_interval", "outlook_webmail_timeout",
    "outlook_webmail_proxy",
    "outlook_official_pool_secret", "outlook_official_login_slug", "outlook_official_base_email",
    "outlook_official_alias_mode", "outlook_official_alias_prefix", "outlook_official_target_email",
    "outlook_official_proof_pool_secret", "outlook_official_proof_imap_secret",
    "outlook_official_proof_target_email", "outlook_official_proof_alias_mode",
    "outlook_official_poll_interval", "outlook_official_timeout", "outlook_official_proxy",
    "outlook_official_disable_selenium",
    "outlook_email_base_url", "outlook_email_auth_mode", "outlook_email_api_key",
    "outlook_email_login_password", "outlook_email_group_id", "outlook_email_address_mode",
    "outlook_email_address_pool", "outlook_email_folder", "outlook_email_fetch_top",
    "outlook_email_disable_used_accounts", "outlook_email_disable_used_status",
    "outlook_email_used_addresses_path", "outlook_email_poll_interval",
    "outlook_email_timeout", "outlook_email_proxy",
    "cfworker_api_url", "cfworker_admin_token", "cfworker_domain", "cfworker_fingerprint",
    "luckmail_base_url", "luckmail_api_key", "luckmail_email_type", "luckmail_domain",
    "cpa_api_url", "cpa_api_key",
    "team_manager_url", "team_manager_key",
    "cliproxyapi_management_key",
    "grok2api_url", "grok2api_app_key", "grok2api_pool", "grok2api_quota",
    "kiro_manager_path", "kiro_manager_exe",
]


class ConfigUpdate(BaseModel):
    data: dict


@router.get("")
def get_config():
    all_cfg = config_store.get_all()
    # 只返回已知 key，未设置的返回空字符串
    return {k: all_cfg.get(k, "") for k in CONFIG_KEYS}


@router.put("")
def update_config(body: ConfigUpdate):
    # 只允许更新已知 key
    safe = {k: v for k, v in body.data.items() if k in CONFIG_KEYS}
    config_store.set_many(safe)
    return {"ok": True, "updated": list(safe.keys())}
