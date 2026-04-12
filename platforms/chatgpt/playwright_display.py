"""Helpers for running headed Playwright safely on Linux servers."""

from __future__ import annotations

import atexit
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Callable

_XVFB_PROC = None
_XVFB_DISPLAY = ""
_FP_PROFILE_CACHE = None


def _cleanup_xvfb():
    global _XVFB_PROC, _XVFB_DISPLAY
    proc = _XVFB_PROC
    _XVFB_PROC = None
    _XVFB_DISPLAY = ""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


atexit.register(_cleanup_xvfb)


def ensure_headed_display(logger: Callable[[str], None] | None = None) -> bool:
    global _XVFB_PROC, _XVFB_DISPLAY
    if os.environ.get("DISPLAY"):
        return True

    if _XVFB_PROC is not None and _XVFB_PROC.poll() is None and _XVFB_DISPLAY:
        os.environ["DISPLAY"] = _XVFB_DISPLAY
        return True

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
                display_num_text = (proc.stdout.readline() or "").strip()
                if display_num_text:
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
                _XVFB_PROC = proc
                _XVFB_DISPLAY = display
                os.environ["DISPLAY"] = display
                if logger:
                    logger(f"Playwright headed 模式自动启动 Xvfb: {display}")
                return True
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
            _XVFB_PROC = proc
            _XVFB_DISPLAY = display
            os.environ["DISPLAY"] = display
            if logger:
                logger(f"Playwright headed 模式自动启动 Xvfb: {display}")
            return True
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    if logger:
        logger("Playwright headed 模式未找到可用 DISPLAY，降级为 headless")
    return False


def prepare_playwright_launch_kwargs(launch_kwargs, browser_mode, logger=None):
    kwargs = dict(launch_kwargs or {})
    args = list(kwargs.get("args") or [])
    if "--disable-blink-features=AutomationControlled" not in args:
        args.append("--disable-blink-features=AutomationControlled")
    kwargs["args"] = args
    fp_profile = load_fingerprint_profile()
    if fp_profile:
        executable_path = str(fp_profile.get("browser_path") or "").strip()
        if executable_path:
            kwargs["executable_path"] = executable_path
        merged_args = list(kwargs.get("args") or [])
        for arg in filtered_fingerprint_launch_args(fp_profile):
            if arg not in merged_args:
                merged_args.append(arg)
        kwargs["args"] = merged_args
        if logger:
            logger(
                "Playwright 使用指纹浏览器内核: "
                f"{kwargs.get('executable_path') or 'default'} "
                f"profile={fp_profile.get('profile_name') or fp_profile.get('profile_slug') or 'unknown'}"
            )
    if browser_mode == "headed" and not ensure_headed_display(logger):
        kwargs["headless"] = True
    return kwargs


def harden_playwright_context(context):
    try:
        context.add_init_script(
            """
            Object.defineProperty(navigator, 'webdriver', {
              get: () => undefined,
            });
            window.chrome = window.chrome || { runtime: {} };
            Object.defineProperty(navigator, 'languages', {
              get: () => ['en-US', 'en'],
            });
            """
        )
    except Exception:
        pass
    return context


def load_fingerprint_profile():
    global _FP_PROFILE_CACHE
    if _FP_PROFILE_CACHE is not None:
        return _FP_PROFILE_CACHE
    path = str(os.environ.get("ANY_AUTO_REGISTER_FP_PROFILE_JSON") or "").strip()
    if not path:
        _FP_PROFILE_CACHE = {}
        return _FP_PROFILE_CACHE
    try:
        profile = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        profile = {}
    _FP_PROFILE_CACHE = profile
    return _FP_PROFILE_CACHE


def filtered_fingerprint_launch_args(profile: dict) -> list[str]:
    launch_args = list(profile.get("launch_args") or [])
    filtered = []
    for arg in launch_args:
        value = str(arg or "").strip()
        if not value:
            continue
        if value.startswith("http://") or value.startswith("https://"):
            continue
        if value.startswith("--user-data-dir="):
            continue
        if value.startswith("--proxy-server="):
            continue
        filtered.append(value)
    return filtered


def fingerprint_context_overrides() -> dict:
    profile = load_fingerprint_profile()
    if not profile:
        return {}
    overrides = {}
    locale = str(profile.get("lang") or "").strip()
    if locale:
        overrides["locale"] = locale
    timezone = str(profile.get("timezone") or "").strip()
    if timezone:
        overrides["timezone_id"] = timezone
    window_size = str(profile.get("window_size") or "").strip()
    if window_size:
        try:
            width_text, height_text = window_size.lower().replace("x", ",").split(",", 1)
            width = int(width_text.strip())
            height = int(height_text.strip())
            overrides["viewport"] = {"width": width, "height": height}
        except Exception:
            pass
    return overrides
