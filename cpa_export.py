"""Register-machine hook: mint CPA xai auth after successful registration.

OIDC package lives at ./cpa_xai (bundled with this project).
Optional override: config `api_reverse_tools` / env `API_REVERSE_TOOLS`
points at a directory that *contains* the `cpa_xai` package.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
import json
from pathlib import Path
from typing import Any, Callable

from curl_cffi import CurlMime, requests

_REG_DIR = Path(__file__).resolve().parent
_DEFAULT_OUT = _REG_DIR / "cpa_auths"
_DEFAULT_CPA = Path("")  # empty = do not assume a machine-local CPA path


def import_auth_file_to_remote_cpa(
    auth_path: str | Path,
    *,
    base_url: str,
    management_key: str,
    timeout: float = 30,
) -> dict:
    """Upload one auth JSON to CLIProxyAPI's management endpoint."""
    path = Path(auth_path)
    url = f"{base_url.rstrip('/')}/v0/management/auth-files"
    headers = {"Authorization": f"Bearer {management_key}"}
    try:
        multipart = CurlMime()
        multipart.addpart(
            name="file",
            filename=path.name,
            content_type="application/json",
            local_path=str(path),
        )
        response = requests.post(
            url,
            headers=headers,
            multipart=multipart,
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"request failed: {exc}"}

    if not 200 <= response.status_code < 300:
        body = (response.text or "").strip().replace("\n", " ")[:300]
        detail = f": {body}" if body else ""
        return {"ok": False, "error": f"HTTP {response.status_code}{detail}"}

    try:
        payload = response.json()
    except Exception:  # noqa: BLE001
        return {"ok": False, "error": "HTTP 2xx but response is not valid JSON"}

    # CLIProxyAPI versions return different success objects. Explicit false/error
    # is failure; otherwise a non-empty JSON object on 2xx is accepted.
    if not isinstance(payload, dict) or not payload:
        return {"ok": False, "error": "HTTP 2xx but response has no success object"}
    if payload.get("success") is False or payload.get("ok") is False or payload.get("error"):
        return {"ok": False, "error": f"remote rejected upload: {json.dumps(payload, ensure_ascii=False)[:300]}"}
    return {"ok": True, "url": url, "response": payload}


def _record_remote_import_failure(out_dir: Path, email: str, error: str) -> None:
    fail_path = out_dir / "cpa_import_failed.txt"
    with fail_path.open("a", encoding="utf-8") as fh:
        fh.write(f"{email}----{error.replace(chr(10), ' ')}----{int(time.time())}\n")


def _ensure_cpa_xai_on_path(tools_dir: str | Path | None = None) -> Path:
    """Put the parent of `cpa_xai` on sys.path. Default: this project root."""
    if tools_dir:
        tools = Path(tools_dir).expanduser().resolve()
    else:
        env = (os.environ.get("API_REVERSE_TOOLS") or "").strip()
        tools = Path(env).expanduser().resolve() if env else _REG_DIR
    # If user pointed at .../cpa_xai itself, use its parent
    if tools.name == "cpa_xai" and (tools / "__init__.py").is_file():
        tools = tools.parent
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    return tools


def export_cookies_from_page(page: Any) -> list[dict]:
    """Best-effort export of cookies from a DrissionPage tab/browser."""
    if page is None:
        return []
    cookies = None
    for getter in (
        lambda: page.cookies(all_domains=True, all_info=True),
        lambda: page.cookies(all_domains=True),
        lambda: page.cookies(),
    ):
        try:
            cookies = getter()
            if cookies:
                break
        except TypeError:
            continue
        except Exception:
            continue
    if not cookies:
        try:
            browser = getattr(page, "browser", None)
            if browser is not None:
                cookies = browser.cookies()
        except Exception:
            cookies = None
    if isinstance(cookies, list):
        return [c for c in cookies if isinstance(c, dict)]
    return []


def export_cpa_xai_for_account(
    email: str,
    password: str,
    *,
    page: Any | None = None,
    cookies: Any | None = None,
    sso: str | None = None,
    config: dict | None = None,
    log_callback: Callable[[str], None] | None = None,
) -> dict:
    """Mint OIDC + write xai-<email>.json under register cpa_auths (and optional CPA auth-dir)."""
    cfg = config or {}
    log = log_callback or (lambda m: print(m, flush=True))

    if not cfg.get("cpa_export_enabled", True):
        log("[cpa] export disabled")
        return {"ok": False, "skipped": True, "reason": "disabled"}

    tools_dir = cfg.get("api_reverse_tools") or cfg.get("cpa_xai_parent") or None
    _ensure_cpa_xai_on_path(tools_dir)

    try:
        from cpa_xai import mint_and_export  # type: ignore
    except Exception as e:  # noqa: BLE001
        log(f"[cpa] import cpa_xai failed: {e}")
        return {"ok": False, "error": f"import: {e}"}

    out_dir = Path(cfg.get("cpa_auth_dir") or _DEFAULT_OUT).expanduser()
    if not out_dir.is_absolute():
        out_dir = (_REG_DIR / out_dir).resolve()

    hotload_raw = (cfg.get("cpa_hotload_dir") or "").strip()
    cpa_dir = Path(hotload_raw).expanduser() if hotload_raw else None
    if cpa_dir and not cpa_dir.is_absolute():
        cpa_dir = (_REG_DIR / cpa_dir).resolve()

    # Priority: cpa_proxy > proxy > env. Config must beat shell https_proxy.
    proxy = (cfg.get("cpa_proxy") or cfg.get("proxy") or "").strip()
    if not proxy:
        proxy = (
            os.environ.get("https_proxy")
            or os.environ.get("HTTPS_PROXY")
            or os.environ.get("http_proxy")
            or ""
        ).strip()
    # Default headed: headless is frequently Cloudflare-blocked on accounts.x.ai
    headless = bool(cfg.get("cpa_headless", False))
    probe = bool(cfg.get("cpa_probe_after_write", True))
    probe_chat = bool(cfg.get("cpa_probe_chat", False))
    timeout = float(cfg.get("cpa_mint_timeout_sec", 240))
    base_url = cfg.get("cpa_base_url") or "https://cli-chat-proxy.grok.com/v1"
    force_standalone = bool(cfg.get("cpa_force_standalone", True))
    cookie_inject = bool(cfg.get("cpa_mint_cookie_inject", True))
    reuse_browser = bool(cfg.get("cpa_mint_browser_reuse", True))
    recycle_every = int(cfg.get("cpa_mint_browser_recycle_every", 15) or 0)

    # cookies: explicit arg > page export > none
    use_cookies = cookies
    if use_cookies is None and cookie_inject and page is not None:
        use_cookies = export_cookies_from_page(page)
    if not cookie_inject:
        use_cookies = None
    else:
        # Always attach SSO cookie clones — register cookies alone often miss accounts.x.ai host
        sso_val = (sso or "").strip()
        if not sso_val and isinstance(use_cookies, list):
            for c in use_cookies:
                if isinstance(c, dict) and c.get("name") in ("sso", "sso-rw") and c.get("value"):
                    sso_val = str(c.get("value"))
                    break
        if sso_val:
            base = list(use_cookies) if isinstance(use_cookies, list) else []
            for name in ("sso", "sso-rw"):
                for dom in (".x.ai", "accounts.x.ai", ".accounts.x.ai", "auth.x.ai", "grok.com", ".grok.com"):
                    base.append({
                        "name": name,
                        "value": sso_val,
                        "domain": dom,
                        "path": "/",
                        "secure": True,
                        "httpOnly": True,
                    })
            use_cookies = base

    out_dir.mkdir(parents=True, exist_ok=True)
    log(
        f"[cpa] mint OIDC for {email} -> {out_dir} proxy={proxy or '(none)'} "
        f"cookies={len(use_cookies) if isinstance(use_cookies, list) else (1 if use_cookies else 0)} "
        f"reuse={reuse_browser}"
    )

    def _log(msg: str) -> None:
        log(f"[cpa] {msg}")

    result = mint_and_export(
        email=email,
        password=password,
        auth_dir=out_dir,
        page=None if force_standalone else page,
        proxy=proxy or None,
        headless=headless,
        base_url=base_url,
        probe=probe,
        probe_chat=probe_chat,
        browser_timeout_sec=timeout,
        force_standalone=force_standalone,
        cookies=use_cookies,
        reuse_browser=reuse_browser,
        recycle_every=recycle_every,
        log=_log,
    )

    if result.get("ok") and result.get("path") and cfg.get("cpa_auto_import_remote", False):
        remote_base = str(cfg.get("cpa_remote_base") or "").strip()
        management_key = str(
            os.environ.get("CPA_MANAGEMENT_KEY") or cfg.get("cpa_management_key") or ""
        ).strip()
        if not remote_base or not management_key:
            log("[cpa] remote import skipped: cpa_remote_base/management key not configured")
            result["cpa_import_skipped"] = True
        else:
            import_result = import_auth_file_to_remote_cpa(
                result["path"],
                base_url=remote_base,
                management_key=management_key,
                timeout=float(cfg.get("cpa_import_timeout_sec", 30) or 30),
            )
            if import_result.get("ok"):
                result["cpa_imported"] = True
                result["cpa_import_url"] = import_result.get("url")
                log(f"[cpa] remote import success -> {remote_base.rstrip('/')} ({Path(result['path']).name})")
            else:
                error = str(import_result.get("error") or "unknown remote import error")
                result["cpa_import_error"] = error
                _record_remote_import_failure(out_dir, email, error)
                log(f"[cpa] remote import failed for {email}: {error}")

    if result.get("ok") and result.get("path") and cfg.get("cpa_copy_to_hotload", False) and cpa_dir:
        try:
            cpa_dir.mkdir(parents=True, exist_ok=True)
            src = Path(result["path"])
            dst = cpa_dir / src.name
            shutil.copy2(src, dst)
            os.chmod(dst, 0o600)
            result["cpa_path"] = str(dst)
            log(f"[cpa] hotload copy -> {dst}")
        except Exception as e:  # noqa: BLE001
            log(f"[cpa] hotload copy failed: {e}")
            result["cpa_copy_error"] = str(e)

    # failure log under register dir
    if not result.get("ok"):
        fail_path = out_dir / "cpa_auth_failed.txt"
        with open(fail_path, "a", encoding="utf-8") as f:
            f.write(f"{email}----{result.get('error') or 'unknown'}----{int(time.time())}\n")
        if cfg.get("cpa_mint_required", False):
            raise RuntimeError(f"CPA mint required but failed: {result.get('error')}")

    return result
