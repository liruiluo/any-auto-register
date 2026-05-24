#!/usr/bin/env python3
"""Export any-auto-register accounts (e.g. Tavily keys) into sub2api manifests."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

AUTO_KEY_FIELDS = (
    "api_key",
    "token",
    "access_token",
    "session_token",
    "wos_session",
)

PLATFORM_BASE_URL = {}

DEFAULT_DB = Path(__file__).resolve().parents[1] / "account_manager.db"
DEFAULT_SECRET_DIR = Path.home() / ".openclaw" / "local-secrets" / "sub2api-external-upstreams"
DEFAULT_SUB2API_SCRIPT = Path("/home/leadtek/myagent/skills/sub2api-public-hub-import/scripts/public_hub_to_sub2api.py")
DEFAULT_OPENAI_OAUTH_IMPORT_SCRIPT = Path("/home/leadtek/myagent/skills/sub2api-chatgpt-pool/scripts/import_openai_tokens_to_sub2api.py")
DEFAULT_SUB2API_BASE = "http://127.0.0.1:8080/api/v1"


def ensure_runtime() -> None:
    if importlib.util.find_spec("sqlmodel") is not None:
        return
    venv_python = REPO_ROOT / ".venv" / "bin" / "python"
    current = Path(sys.executable).resolve()
    if venv_python.exists() and current != venv_python.resolve():
        os.execv(str(venv_python), [str(venv_python), __file__, *sys.argv[1:]])


def slugify(value: str) -> str:
    slug = value.strip().lower()
    slug = "".join(ch if ch.isalnum() else "-" for ch in slug)
    slug = "-".join(part for part in slug.split("-") if part)
    return slug or "any-auto-register"


def parse_model_mapping(value: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, val = part.split("=", 1)
            mapping[key.strip()] = val.strip()
        else:
            mapping[part] = part
    return mapping


def load_accounts(engine, account_model, session_cls, select_fn, platform: str | None):
    with session_cls(engine) as session:
        stmt = select_fn(account_model).order_by(account_model.id.desc())
        if platform and platform.lower() != "all":
            stmt = stmt.where(account_model.platform == platform)
        return session.exec(stmt).all()


def find_account(accounts, account_id: int | None, email: str | None):
    if account_id is not None:
        for acct in accounts:
            if acct.id == account_id:
                return acct
    if email:
        for acct in accounts:
            if acct.email == email:
                return acct
    return accounts[0] if accounts else None


def choose_api_key(account, explicit_field: str | None, override: str | None) -> str:
    if override:
        return override.strip()
    if explicit_field:
        value = (account.extra_json and json.loads(account.extra_json).get(explicit_field)) or getattr(account, explicit_field, None)
        if value:
            return str(value)
        raise SystemExit(f"field '{explicit_field}' not found on account {account.email}")
    extra = account.get_extra()
    for field in AUTO_KEY_FIELDS:
        candidate = extra.get(field) or getattr(account, field, None)
        if candidate:
            return str(candidate)
    raise SystemExit("unable to infer api_key/token from account; pass --api-key or --api-key-field")


def platform_base_url(account, override: str | None) -> str:
    if override:
        return override.strip()
    base = PLATFORM_BASE_URL.get(account.platform)
    if base:
        return base
    raise SystemExit(
        "platform %s has no safe default openai-apikey export; pass --force-openai-apikey-export together with --base-url if you really want that route"
        % account.platform
    )


def describe_account(account) -> str:
    extra = account.get_extra()
    token = extra.get("api_key") or extra.get("token") or account.token
    snippet = (token or "").strip()
    if snippet:
        snippet = snippet[:8] + "..."
    return (
        f"[{account.id}] {account.platform} {account.email} status={account.status}"
        f" token={snippet}"
    )


def build_manifest(
    site_name: str,
    account_name: str,
    base_url: str,
    api_key: str,
    group_ids: list[int],
    concurrency: int,
    priority: int,
    notes: str,
    model_mapping: dict[str, str],
) -> dict[str, Any]:
    return {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "site_name": site_name,
        "account_name": account_name,
        "platform": "openai",
        "type": "apikey",
        "base_url": base_url,
        "api_key": api_key,
        "group_ids": group_ids,
        "notes": notes,
        "concurrency": concurrency,
        "priority": priority,
        "model_mapping": model_mapping,
        "source_catalog_url": "https://github.com/lxf746/any-auto-register",
    }


def print_accounts(accounts) -> None:
    if not accounts:
        print("no accounts in database")
        return
    for acct in accounts:
        print(describe_account(acct))


def run_sub2api_import(manifest_path: Path, args: argparse.Namespace) -> None:
    cmd = [
        sys.executable,
        str(args.sub2api_script),
        "import-manifest",
        "--manifest",
        str(manifest_path),
        "--local-secret-dir",
        args.manifest_dir,
    ]
    if args.probe_first:
        cmd.append("--probe-first")
    if args.test_account:
        cmd.append("--test-account")
    if args.sub2api_base_url:
        cmd.extend(["--sub2api-base-url", args.sub2api_base_url])
    if args.admin_email:
        cmd.extend(["--admin-email", args.admin_email])
    if args.admin_password:
        cmd.extend(["--admin-password", args.admin_password])
    if args.env_file:
        cmd.extend(["--env-file", args.env_file])
    if args.dry_run:
        print("dry run:", " ".join(cmd))
        return
    subprocess.run(cmd, check=True)


def read_env_file(path: str | None) -> dict[str, str]:
    if not path:
        return {}
    file = Path(path)
    if not file.exists():
        return {}
    env: dict[str, str] = {}
    for line in file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def resolve_admin_credentials(args: argparse.Namespace) -> tuple[str, str]:
    env = read_env_file(args.env_file)
    email = args.admin_email or env.get("ADMIN_EMAIL") or env.get("SUB2API_ADMIN_EMAIL") or "admin@sub2api.local"
    password = args.admin_password or env.get("ADMIN_PASSWORD") or env.get("SUB2API_ADMIN_PASSWORD")
    if not password:
        raise SystemExit("missing sub2api admin password; pass --admin-password or --env-file")
    return email, password


def build_chatgpt_token_json(account) -> dict[str, Any]:
    extra = account.get_extra()
    return {
        "email": account.email,
        "access_token": extra.get("access_token") or account.token or "",
        "refresh_token": extra.get("refresh_token") or "",
        "id_token": extra.get("id_token") or "",
        "session_token": extra.get("session_token") or "",
        "workspace_id": extra.get("workspace_id") or "",
        "account_id": account.user_id or extra.get("account_id") or "",
        "expired": extra.get("expired") or "",
        "cookies": extra.get("cookies") or "",
        "cookie_bundle": extra.get("cookie_bundle") or {},
        "cf_clearance": extra.get("cf_clearance") or "",
        "oai_did": extra.get("oai_did") or "",
        "oai_sc": extra.get("oai_sc") or "",
    }


def run_openai_oauth_import(token_json_path: Path, args: argparse.Namespace) -> None:
    admin_email, admin_password = resolve_admin_credentials(args)
    cmd = [
        sys.executable,
        str(args.sub2api_openai_oauth_script),
        "--admin-password",
        admin_password,
        "--base-url",
        args.sub2api_base_url,
        "--admin-email",
        admin_email,
        "--token-json",
        str(token_json_path),
        "--name-prefix",
        "any-auto-register-chatgpt",
    ]
    if args.test_account:
        cmd.append("--test")
    subprocess.run(cmd, check=True)


def main() -> None:
    ensure_runtime()
    parser = argparse.ArgumentParser(description="Export any-auto-register accounts to sub2api")
    parser.add_argument("--platform", default="tavily", help="platform slug (default: tavily)")
    parser.add_argument("--account-id", type=int)
    parser.add_argument("--email")
    parser.add_argument("--list-accounts", action="store_true")
    parser.add_argument("--site-name")
    parser.add_argument("--account-name")
    parser.add_argument("--base-url", help="override base URL for sub2api import")
    parser.add_argument("--api-key", help="override API key/token")
    parser.add_argument("--api-key-field", help="field name in account.extra or attribute")
    parser.add_argument("--group-id", type=int, action="append", default=None, help="sub2api group id (repeatable)")
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--priority", type=int, default=1)
    parser.add_argument("--notes", default="registered via any-auto-register")
    parser.add_argument("--model-mapping", default="", help="comma separated OpenAI=>target entries")
    parser.add_argument("--manifest-dir", default=str(DEFAULT_SECRET_DIR))
    parser.add_argument("--manifest-out", help="explicit manifest path")
    parser.add_argument("--write-manifest", action="store_true", default=True)
    parser.add_argument("--import-to-sub2api", action="store_true")
    parser.add_argument("--sub2api-script", default=str(DEFAULT_SUB2API_SCRIPT))
    parser.add_argument("--sub2api-openai-oauth-script", default=str(DEFAULT_OPENAI_OAUTH_IMPORT_SCRIPT))
    parser.add_argument("--sub2api-base-url", default=DEFAULT_SUB2API_BASE)
    parser.add_argument("--admin-email")
    parser.add_argument("--admin-password")
    parser.add_argument("--env-file")
    parser.add_argument("--probe-first", action="store_true")
    parser.add_argument("--test-account", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--force-openai-apikey-export", action="store_true")
    args = parser.parse_args()

    from sqlmodel import Session, create_engine, select
    from core.db import AccountModel

    engine = create_engine(f"sqlite:///{Path(args.db).resolve()}")
    accounts = load_accounts(engine, AccountModel, Session, select, args.platform)
    if args.list_accounts:
        print_accounts(accounts)
        return

    account = find_account(accounts, args.account_id, args.email)
    if not account:
        raise SystemExit("no matching account found")

    if account.platform == "chatgpt":
        token_path = (
            Path(args.manifest_out)
            if args.manifest_out
            else Path(args.manifest_dir) / f"{slugify(f'{account.platform}-{account.email or account.id}')}.token.json"
        )
        token_json = build_chatgpt_token_json(account)

        if args.write_manifest:
            token_path.parent.mkdir(parents=True, exist_ok=True)
            token_path.write_text(
                json.dumps(token_json, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            print(f"token json written to {token_path}")

        if args.import_to_sub2api:
            run_openai_oauth_import(token_path, args)

        print("summary:")
        print(f"  platform: {account.platform}")
        print(f"  email/id: {account.email or account.id}")
        print(f"  token_json: {token_path}")
        return

    if not args.force_openai_apikey_export:
        raise SystemExit(
            f"platform {account.platform} is not auto-exported as openai apikey by default; "
            "use --force-openai-apikey-export only when the upstream is truly OpenAI-compatible"
        )

    api_key = choose_api_key(account, args.api_key_field, args.api_key)
    base_url = platform_base_url(account, args.base_url)
    group_ids = args.group_id or [6]
    site_name = args.site_name or f"{account.platform} {account.email or account.id}"
    account_name = args.account_name or account.email or f"{account.platform}-{account.id}"
    slug = slugify(f"{account.platform}-{account.email or account.id}")
    manifest_path = Path(args.manifest_out) if args.manifest_out else Path(args.manifest_dir) / f"{slug}.json"
    model_mapping = parse_model_mapping(args.model_mapping)
    manifest = build_manifest(
        site_name=site_name,
        account_name=account_name,
        base_url=base_url,
        api_key=api_key,
        group_ids=group_ids,
        concurrency=args.concurrency,
        priority=args.priority,
        notes=args.notes,
        model_mapping=model_mapping,
    )

    if args.write_manifest:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"manifest written to {manifest_path}")

    if args.import_to_sub2api:
        run_sub2api_import(manifest_path, args)

    print("summary:")
    print(f"  platform: {account.platform}")
    print(f"  email/id: {account.email or account.id}")
    print(f"  base_url: {base_url}")
    print(f"  manifest: {manifest_path}")


if __name__ == "__main__":
    main()
