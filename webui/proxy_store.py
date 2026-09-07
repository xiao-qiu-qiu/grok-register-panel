"""Persistent external proxy pool with redacted public views and cooldowns."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

try:
    from secure_files import atomic_write_json, exclusive_file_lock
    from webui.security_utils import redact_log_line, redact_proxy
except ImportError:  # running from webui/
    import sys

    ROOT = Path(__file__).resolve().parent.parent
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from secure_files import atomic_write_json, exclusive_file_lock
    from security_utils import redact_log_line, redact_proxy  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
STATE_PATH = Path(
    os.environ.get("PROXY_POOL_STATE_FILE", str(ROOT / "log" / "proxy_pool.json"))
)
LOCK_PATH = STATE_PATH.with_suffix(STATE_PATH.suffix + ".lock")
LEGACY_PATH = Path(os.environ.get("PROXY_POOL_LEGACY_FILE", str(ROOT / "proxies.txt")))

ALLOWED_SCHEMES = {"http", "https", "socks5", "socks5h"}
ALLOWED_STATUSES = {"unknown", "healthy", "unhealthy", "cooldown"}
MAX_IMPORT_ITEMS = 500
MAX_TEST_ITEMS = 200
DEFAULT_TEST_TIMEOUT = 8.0
NETWORK_COOLDOWN_SECONDS = max(
    10, int(os.environ.get("PROXY_NETWORK_COOLDOWN_SECONDS", "90"))
)
RISK_COOLDOWN_SECONDS = max(
    60, int(os.environ.get("PROXY_RISK_COOLDOWN_SECONDS", "1800"))
)
PROXY_IP_REFRESH_SECONDS = max(
    30, int(os.environ.get("PROXY_IP_REFRESH_SECONDS", "300") or 300)
)
# 家宽口：风控不冷却、不禁用；换口改走 40 分钟内没出现过的 IP
HOME_PROXY_PORTS = set(
    int(p)
    for p in str(os.environ.get("PROXY_HOME_PORTS", "") or "").split(",")
    if str(p).strip().isdigit()
) or (set(range(8001, 8012)) | set(range(17901, 17951)))
IP_FRESH_SECONDS = max(
    60, int(os.environ.get("PROXY_IP_FRESH_SECONDS", str(40 * 60)))
)
# 1024 家宽（mihomo 7901-7920）不参与注册选口，只用 Kookeey 8001-8011
BLOCKED_WORKER_PORTS = set(
    int(p)
    for p in str(os.environ.get("PROXY_BLOCKED_PORTS", "") or "").split(",")
    if str(p).strip().isdigit()
) or set(range(7901, 7921))

_TEST_LOCK = threading.RLock()
_TEST_JOB = {
    "running": False,
    "job_id": None,
    "total": 0,
    "completed": 0,
    "healthy": 0,
    "failed": 0,
    "started_at": None,
    "finished_at": None,
    "testing_ids": [],
}
_REFRESH_LOCK = threading.RLock()
_REFRESH_JOB = {
    "running": False,
    "job_id": None,
    "total": 0,
    "checked": 0,
    "changed": 0,
    "cleared": 0,
    "failed": 0,
    "started_at": None,
    "finished_at": None,
    "error": "",
}
_LOOP_GUARD = threading.Lock()
_LOOP_STATE = {
    "enabled": False,
    "interval_seconds": int(PROXY_IP_REFRESH_SECONDS),
    "next_at": "",
}
_LOOP_THREAD = None
EXIT_IP_REFRESH_TIMEOUT = 4.0
EXIT_IP_REFRESH_WORKERS = 4


class ProxyValidationError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _future_utc(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _url_port(url: object) -> int | None:
    try:
        return urlsplit(str(url or "")).port
    except Exception:
        return None


def is_home_proxy(url: object) -> bool:
    try:
        parsed = urlsplit(str(url or ""))
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except Exception:
        return False
    if port not in HOME_PROXY_PORTS:
        return False
    return host in {"127.0.0.1", "localhost", "::1"}


def _item_usable_for_workers(item: dict) -> bool:
    if not item.get("enabled"):
        return False
    port = _url_port(item.get("url"))
    if port in BLOCKED_WORKER_PORTS:
        return False
    status = str(item.get("status") or "")
    if is_home_proxy(item.get("url")):
        # Kookeey 家宽不因风控冷却踢出；探测失败的 unhealthy 仍排除
        return status in {"healthy", "unknown", "cooldown"}
    return status == "healthy"


def _ip_age_seconds(item: dict, now: datetime | None = None) -> float:
    now = now or datetime.now(timezone.utc)
    ip = str(item.get("exit_ip") or "").strip()
    if not ip:
        return 10**9
    used = _parse_utc(item.get("last_used_at"))
    if used is None:
        return 10**9
    return max(0.0, (now - used).total_seconds())


def note_proxy_exit(url: object, exit_ip: object) -> bool:
    """记下这次实际出口 IP，供 40 分钟去重。"""
    try:
        normalized = normalize_proxy(url)
    except ProxyValidationError:
        return False
    ip = str(exit_ip or "").strip()
    if not ip:
        return False
    changed = False
    with exclusive_file_lock(LOCK_PATH):
        state, _ = _read_unlocked()
        for item in state["items"]:
            if item["url"] != normalized:
                continue
            item["exit_ip"] = _clean_text(ip, 64)
            item["last_used_at"] = _utc_now()
            changed = True
            break
        if changed:
            _write_unlocked(state)
    return changed


def worker_proxy_details() -> list[dict]:
    """Worker 可选出口：url + 最近出口 IP + 上次使用时间。"""
    with exclusive_file_lock(LOCK_PATH):
        state, _ = _read_unlocked()
        changed = _release_expired_cooldowns(state)
        rows = []
        for item in state["items"]:
            if not _item_usable_for_workers(item):
                continue
            rows.append(
                {
                    "url": item["url"],
                    "exit_ip": str(item.get("exit_ip") or ""),
                    "last_used_at": str(item.get("last_used_at") or ""),
                    "status": item.get("status") or "",
                    "home": is_home_proxy(item["url"]),
                }
            )
        if changed:
            _write_unlocked(state)
    return rows


def restore_home_proxies() -> dict:
    """启用全部家宽口并清掉风控冷却。"""
    restored = 0
    with exclusive_file_lock(LOCK_PATH):
        state, _ = _read_unlocked()
        for item in state["items"]:
            if not is_home_proxy(item.get("url")):
                continue
            changed_item = False
            if item.get("enabled") is not True:
                item["enabled"] = True
                changed_item = True
            if item.get("cooldown_reason") == "risk" or item.get("status") == "cooldown":
                item["status"] = "healthy" if item.get("exit_ip") else "unknown"
                item["cooldown_until"] = ""
                item["cooldown_reason"] = ""
                changed_item = True
            if changed_item:
                restored += 1
        if restored:
            _write_unlocked(state)
    return {"ok": True, "restored": restored}


def _parse_utc(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _clean_text(value: object, limit: int = 180) -> str:
    text = redact_log_line(str(value or ""))
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _probe_error_message(exc: object) -> str:
    raw = _clean_text(exc, 240)
    low = raw.lower()
    if "407" in low or "proxy authentication required" in low:
        return "代理鉴权失败"
    if "missing dependencies for socks" in low or "no module named 'socks'" in low:
        return "缺少 SOCKS 依赖 PySocks"
    if "name or service not known" in low or "temporary failure in name resolution" in low or "getaddrinfo failed" in low:
        return "无法解析代理主机"
    if "timeout" in low or "timed out" in low:
        return "代理连接超时"
    if "ssl" in low or "tls" in low or "certificate" in low:
        return "代理 TLS 握手失败"
    if "proxyerror" in low or "unable to connect to proxy" in low or "connection refused" in low:
        return "无法连接代理"
    match = re.search(r"(?:status|http)\s*(?:code)?\s*[:=]?\s*(\d{3})", low)
    if match:
        return f"探测服务返回 HTTP {match.group(1)}"
    return raw[:120] or "代理探测失败"


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def normalize_proxy(value: object) -> str:
    """Return a canonical proxy URL without ever logging the input value."""
    raw = str(value or "").strip()
    if not raw:
        raise ProxyValidationError("代理地址为空")
    if any(char.isspace() for char in raw):
        raise ProxyValidationError("代理地址不能包含空白字符")

    if "://" not in raw:
        parts = raw.split(":")
        if len(parts) == 2:
            host, port = parts
            raw = f"http://{host}:{port}"
        elif len(parts) >= 4:
            host, port, username = parts[:3]
            password = ":".join(parts[3:])
            if not username or not password:
                raise ProxyValidationError("代理账号或密码为空")
            raw = (
                f"http://{quote(username, safe='')}:{quote(password, safe='')}"
                f"@{host}:{port}"
            )
        else:
            raise ProxyValidationError("格式应为 URL、host:port 或 host:port:user:pass")

    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise ProxyValidationError("仅支持 http、https、socks5、socks5h")
        if not parsed.hostname:
            raise ProxyValidationError("缺少代理主机")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ProxyValidationError("代理地址不能包含路径、查询参数或片段")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ProxyValidationError("代理端口无效") from exc
        if port is None or not 1 <= port <= 65535:
            raise ProxyValidationError("代理端口必须在 1-65535 之间")

        host = parsed.hostname.lower().rstrip(".")
        if not host:
            raise ProxyValidationError("缺少代理主机")
        if ":" in host:
            host = f"[{host}]"

        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if (parsed.username is None) != (parsed.password is None):
            raise ProxyValidationError("代理账号和密码必须同时填写")
        auth = ""
        if parsed.username is not None:
            if not username or not password:
                raise ProxyValidationError("代理账号或密码为空")
            auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
        return f"{scheme}://{auth}{host}:{port}"
    except ProxyValidationError:
        raise
    except Exception as exc:
        raise ProxyValidationError("无法解析代理地址") from exc


def _proxy_id(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:20]


def _default_state() -> dict:
    return {"version": 1, "items": [], "updated_at": _utc_now()}


def _normalize_item(raw: object) -> dict | None:
    if not isinstance(raw, dict):
        return None
    try:
        url = normalize_proxy(raw.get("url"))
    except ProxyValidationError:
        return None
    status = str(raw.get("status") or "unknown").strip().lower()
    if status not in ALLOWED_STATUSES:
        status = "unknown"
    asn = raw.get("asn")
    try:
        asn = int(asn) if asn not in (None, "") else None
    except (TypeError, ValueError):
        asn = None
    if asn is not None and asn <= 0:
        asn = None
    latency = raw.get("latency_ms")
    try:
        latency = max(0, int(latency)) if latency not in (None, "") else None
    except (TypeError, ValueError):
        latency = None
    created_at = str(raw.get("created_at") or "").strip() or _utc_now()
    return {
        "id": _proxy_id(url),
        "url": url,
        "enabled": bool(raw.get("enabled", True)),
        "status": status,
        "exit_ip": _clean_text(raw.get("exit_ip"), 64),
        "asn": asn,
        "asn_org": _clean_text(raw.get("asn_org"), 120),
        "latency_ms": latency,
        "last_checked_at": _clean_text(raw.get("last_checked_at"), 40),
        "last_error": _clean_text(raw.get("last_error"), 180),
        "failure_count": _safe_int(raw.get("failure_count")),
        "cooldown_until": _clean_text(raw.get("cooldown_until"), 40),
        "cooldown_reason": _clean_text(raw.get("cooldown_reason"), 24),
        "last_used_at": _clean_text(raw.get("last_used_at"), 40),
        "success_count": _safe_int(raw.get("success_count")),
        "risk_count": _safe_int(raw.get("risk_count")),
        "source": _clean_text(raw.get("source") or "panel", 32),
        "created_at": _clean_text(created_at, 40),
    }


def _normalize_state(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("proxy pool state must be an object")
    items_by_id = {}
    for candidate in raw.get("items") or []:
        item = _normalize_item(candidate)
        if item:
            items_by_id[item["id"]] = item
    return {
        "version": 1,
        "items": list(items_by_id.values()),
        "updated_at": _clean_text(raw.get("updated_at"), 40) or _utc_now(),
    }


def _read_unlocked() -> tuple[dict, list[str]]:
    if not STATE_PATH.exists():
        return _default_state(), []
    try:
        import json

        raw = json.loads(STATE_PATH.read_text(encoding="utf-8") or "{}")
        return _normalize_state(raw), []
    except Exception as exc:
        return _default_state(), [_clean_text(exc)]


def _write_unlocked(state: dict) -> None:
    state["updated_at"] = _utc_now()
    atomic_write_json(STATE_PATH, _normalize_state(state))


def _release_expired_cooldowns(state: dict) -> bool:
    now = datetime.now(timezone.utc)
    changed = False
    for item in state["items"]:
        if item.get("status") != "cooldown":
            continue
        until = _parse_utc(item.get("cooldown_until"))
        if until is not None and until > now:
            continue
        reason = str(item.get("cooldown_reason") or "").strip().lower()
        # A previous exit IP does not prove that a proxy recovered from a
        # network/TLS failure. Require an explicit probe before reusing it.
        item["status"] = (
            "unknown"
            if reason == "network"
            else ("healthy" if item.get("exit_ip") else "unknown")
        )
        item["cooldown_until"] = ""
        item["cooldown_reason"] = ""
        changed = True
    return changed


def _legacy_info() -> dict:
    count = 0
    try:
        if LEGACY_PATH.is_file():
            for line in LEGACY_PATH.read_text(encoding="utf-8").splitlines():
                text = line.strip()
                if text and not text.startswith("#"):
                    count += 1
    except OSError:
        pass
    return {
        "available": count > 0,
        "count": count,
        "filename": LEGACY_PATH.name,
    }


def _public_item(item: dict, testing_ids: set[str], now: datetime) -> dict:
    cooldown_until = _parse_utc(item.get("cooldown_until"))
    remaining = 0
    if cooldown_until and cooldown_until > now:
        remaining = max(0, int((cooldown_until - now).total_seconds()))
    parsed = urlsplit(item["url"])
    return {
        "id": item["id"],
        "display_url": redact_proxy(item["url"]),
        "scheme": parsed.scheme,
        "host": parsed.hostname or "",
        "port": parsed.port,
        "has_auth": parsed.username is not None,
        "enabled": item["enabled"],
        "status": "testing" if item["id"] in testing_ids else item["status"],
        "stored_status": item["status"],
        "exit_ip": item.get("exit_ip") or "",
        "asn": item.get("asn"),
        "asn_org": item.get("asn_org") or "",
        "latency_ms": item.get("latency_ms"),
        "last_checked_at": item.get("last_checked_at") or "",
        "last_error": item.get("last_error") or "",
        "failure_count": item.get("failure_count", 0),
        "cooldown_until": item.get("cooldown_until") or "",
        "cooldown_reason": item.get("cooldown_reason") or "",
        "cooldown_remaining_seconds": remaining,
        "last_used_at": item.get("last_used_at") or "",
        "success_count": item.get("success_count", 0),
        "risk_count": item.get("risk_count", 0),
        "source": item.get("source") or "panel",
        "created_at": item.get("created_at") or "",
    }


def proxy_test_status() -> dict:
    with _TEST_LOCK:
        return {
            key: (list(value) if isinstance(value, list) else value)
            for key, value in _TEST_JOB.items()
        }


def read_proxy_pool() -> dict:
    with exclusive_file_lock(LOCK_PATH):
        state, errors = _read_unlocked()
        if _release_expired_cooldowns(state):
            _write_unlocked(state)
    job = proxy_test_status()
    testing_ids = set(job.get("testing_ids") or [])
    now = datetime.now(timezone.utc)
    items = [_public_item(item, testing_ids, now) for item in state["items"]]
    summary = {
        "total": len(items),
        "enabled": sum(1 for item in items if item["enabled"]),
        "healthy": sum(1 for item in items if item["stored_status"] == "healthy"),
        "unhealthy": sum(1 for item in items if item["stored_status"] == "unhealthy"),
        "cooldown": sum(1 for item in items if item["stored_status"] == "cooldown"),
        "unknown": sum(1 for item in items if item["stored_status"] == "unknown"),
        "usable": sum(
            1
            for item in items
            if item["enabled"] and item["stored_status"] == "healthy"
        ),
    }
    try:
        mtime = STATE_PATH.stat().st_mtime
    except OSError:
        mtime = None
    return {
        "ok": not errors,
        "error": errors[0] if errors else None,
        "errors": errors,
        "summary": summary,
        "items": items,
        "test_job": job,
        "exit_ip_refresh": exit_ip_refresh_status(),
        "legacy": _legacy_info(),
        "updated_at": state.get("updated_at") or "",
        "mtime": mtime,
    }


def _input_lines(values: object) -> list[str]:
    if isinstance(values, str):
        return values.splitlines()
    if isinstance(values, (list, tuple)):
        return [str(value or "") for value in values]
    return []


def import_proxies(values: object, *, source: str = "panel") -> dict:
    lines = _input_lines(values)
    candidates = []
    errors = []
    seen = set()
    for line_number, line in enumerate(lines, 1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if len(candidates) >= MAX_IMPORT_ITEMS:
            errors.append({"line": line_number, "error": f"单次最多导入 {MAX_IMPORT_ITEMS} 条"})
            break
        try:
            normalized = normalize_proxy(text)
        except ProxyValidationError as exc:
            errors.append({"line": line_number, "error": str(exc)})
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        candidates.append(normalized)

    if not candidates:
        return {
            "ok": False,
            "error": "没有可导入的有效代理",
            "errors": errors,
            "imported_count": 0,
            "duplicate_count": 0,
        }

    imported_ids = []
    duplicate_count = 0
    with exclusive_file_lock(LOCK_PATH):
        state, _ = _read_unlocked()
        existing = {item["id"]: item for item in state["items"]}
        for url in candidates:
            item_id = _proxy_id(url)
            if item_id in existing:
                duplicate_count += 1
                continue
            item = _normalize_item(
                {
                    "url": url,
                    "enabled": True,
                    "status": "unknown",
                    "source": source,
                    "created_at": _utc_now(),
                }
            )
            if item:
                existing[item_id] = item
                imported_ids.append(item_id)
        state["items"] = list(existing.values())
        _write_unlocked(state)

    result = read_proxy_pool()
    result.update(
        {
            "ok": True,
            "imported_count": len(imported_ids),
            "duplicate_count": duplicate_count,
            "imported_ids": imported_ids,
            "errors": errors,
        }
    )
    return result


def import_legacy_proxies() -> dict:
    try:
        text = LEGACY_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        return {"ok": False, "error": _clean_text(exc), "imported_count": 0}
    return import_proxies(text, source="proxies.txt")


def update_proxy(proxy_id: str, *, enabled: object | None = None) -> dict:
    proxy_id = str(proxy_id or "").strip()
    found = False
    with exclusive_file_lock(LOCK_PATH):
        state, _ = _read_unlocked()
        for item in state["items"]:
            if item["id"] != proxy_id:
                continue
            found = True
            if enabled is not None:
                if not isinstance(enabled, bool):
                    raise ProxyValidationError("enabled 必须是布尔值")
                if enabled is False and is_home_proxy(item.get("url")):
                    raise ProxyValidationError("家宽出口不能禁用")
                item["enabled"] = enabled
            break
        if not found:
            return {"ok": False, "error": "代理不存在"}
        _write_unlocked(state)
    return read_proxy_pool()


def delete_proxy(proxy_id: str) -> dict:
    proxy_id = str(proxy_id or "").strip()
    with exclusive_file_lock(LOCK_PATH):
        state, _ = _read_unlocked()
        before = len(state["items"])
        state["items"] = [item for item in state["items"] if item["id"] != proxy_id]
        if len(state["items"]) == before:
            return {"ok": False, "error": "代理不存在"}
        _write_unlocked(state)
    result = read_proxy_pool()
    result["deleted_id"] = proxy_id
    return result


def worker_proxy_snapshot() -> dict:
    """Return secret worker URLs plus whether a managed pool is configured."""
    with exclusive_file_lock(LOCK_PATH):
        state, _ = _read_unlocked()
        changed = _release_expired_cooldowns(state)
        urls = [
            item["url"]
            for item in state["items"]
            if _item_usable_for_workers(item)
        ]
        if changed:
            _write_unlocked(state)
    return {"configured": bool(state["items"]), "urls": urls}


def list_worker_proxies() -> list[str]:
    """Return only enabled, currently healthy proxy URLs with credentials."""
    return list(worker_proxy_snapshot()["urls"])


def mark_proxy_used(url: object) -> bool:
    try:
        normalized = normalize_proxy(url)
    except ProxyValidationError:
        return False
    changed = False
    with exclusive_file_lock(LOCK_PATH):
        state, _ = _read_unlocked()
        for item in state["items"]:
            if item["url"] == normalized:
                item["last_used_at"] = _utc_now()
                changed = True
                break
        if changed:
            _write_unlocked(state)
    return changed


def record_proxy_result(url: object, outcome: str, error: object = "") -> bool:
    """Persist runtime feedback. Email/provider failures should not call this."""
    try:
        normalized = normalize_proxy(url)
    except ProxyValidationError:
        return False
    outcome = str(outcome or "").strip().lower()
    if outcome not in {"success", "network", "risk"}:
        raise ValueError(f"unknown proxy outcome: {outcome}")
    changed = False
    with exclusive_file_lock(LOCK_PATH):
        state, _ = _read_unlocked()
        for item in state["items"]:
            if item["url"] != normalized:
                continue
            changed = True
            item["last_used_at"] = _utc_now()
            if outcome == "success":
                item["status"] = "healthy"
                item["success_count"] += 1
                item["last_error"] = ""
                item["cooldown_until"] = ""
                item["cooldown_reason"] = ""
            elif outcome == "risk" and is_home_proxy(normalized):
                # 家宽风控：只记账，不冷却、不禁用；换口靠 40 分钟 IP 去重
                item["risk_count"] += 1
                item["failure_count"] += 1
                item["last_error"] = _clean_text(error) or "运行时风控"
                if item.get("status") == "cooldown":
                    item["status"] = "healthy" if item.get("exit_ip") else "unknown"
                item["cooldown_until"] = ""
                item["cooldown_reason"] = ""
            else:
                item["status"] = "cooldown"
                item["failure_count"] += 1
                item["last_error"] = _clean_text(error) or (
                    "运行时风控" if outcome == "risk" else "运行时网络异常"
                )
                if outcome == "risk":
                    item["risk_count"] += 1
                    item["cooldown_reason"] = "risk"
                    item["cooldown_until"] = _future_utc(RISK_COOLDOWN_SECONDS)
                else:
                    item["cooldown_reason"] = "network"
                    item["cooldown_until"] = _future_utc(NETWORK_COOLDOWN_SECONDS)
            break
        if changed:
            _write_unlocked(state)
    return changed


def _parse_probe_payload(payload: object) -> tuple[str, int | None, str]:
    if not isinstance(payload, dict):
        raise RuntimeError("探测服务返回了无效 JSON")
    ip = str(payload.get("ip") or "").strip()
    if not ip:
        raise RuntimeError("探测服务没有返回出口 IP")
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise RuntimeError("探测服务返回了无效出口 IP") from exc

    asn = None
    org = ""
    connection = payload.get("connection")
    if isinstance(connection, dict):
        raw_asn = connection.get("asn")
        org = str(connection.get("org") or connection.get("isp") or "").strip()
        try:
            asn = int(raw_asn) if raw_asn not in (None, "") else None
        except (TypeError, ValueError):
            asn = None
    raw_org = str(payload.get("org") or "").strip()
    match = re.match(r"AS(\d+)\s*(.*)", raw_org, re.I)
    if match:
        asn = int(match.group(1))
        org = org or match.group(2).strip()
    return ip, asn, _clean_text(org, 120)


def probe_xai_signup(url: object, timeout: float = DEFAULT_TEST_TIMEOUT, *, http_get=None) -> str:
    """Require the proxy to reach the actual registration page, not only an IP API."""
    normalized = normalize_proxy(url)
    timeout = max(2.0, min(float(timeout), 20.0))
    from connectivity import check_xai_signup

    if http_get is None:
        from curl_cffi import requests as curl_requests

        def http_get(target, **kwargs):
            kwargs.pop("_allow_direct_fallback", None)
            kwargs["timeout"] = min(float(kwargs.get("timeout", timeout)), timeout)
            return curl_requests.get(target, **kwargs)

    _name, ok, detail = check_xai_signup(normalized, http_get)
    if not ok:
        raise RuntimeError(f"xAI 注册页不可用: {detail}")
    return detail


def probe_exit_ip(url: object, timeout: float = DEFAULT_TEST_TIMEOUT) -> dict:
    """Look up the current exit IP through the proxy. Does not hit xAI."""
    normalized = normalize_proxy(url)
    timeout = max(1.5, min(float(timeout), 12.0))
    import requests

    session = requests.Session()
    session.trust_env = False
    proxies = {"http": normalized, "https": normalized}
    # Fast JSON first; slower geo endpoints are fallbacks only.
    endpoints = (
        "https://api.ipify.org?format=json",
        "https://ipinfo.io/json",
        "https://ipwho.is/",
    )
    last_error = None
    result = None
    started = time.monotonic()
    connect_timeout = min(2.0, timeout)
    for endpoint in endpoints:
        try:
            response = session.get(
                endpoint,
                proxies=proxies,
                timeout=(connect_timeout, timeout),
                headers={"Accept": "application/json", "User-Agent": "GrokRegister/1"},
            )
            response.raise_for_status()
            payload = response.json()
            if endpoint.startswith("https://ipwho.is") and payload.get("success") is False:
                raise RuntimeError("探测服务拒绝了请求")
            ip, asn, org = _parse_probe_payload(payload)
            result = {
                "ok": True,
                "exit_ip": ip,
                "asn": asn,
                "asn_org": org,
                "latency_ms": max(1, int((time.monotonic() - started) * 1000)),
                "checked_at": _utc_now(),
            }
            break
        except Exception as exc:
            last_error = exc
    if result is None:
        raise RuntimeError(_probe_error_message(last_error))
    return result


def probe_proxy(url: object, timeout: float = DEFAULT_TEST_TIMEOUT) -> dict:
    """Probe one proxy via public IP services and return non-secret metadata."""
    result = probe_exit_ip(url, timeout=timeout)
    probe_xai_signup(url, timeout=timeout)
    return result


def apply_changed_exit_ip(
    url: object,
    new_exit_ip: object,
    *,
    asn=None,
    asn_org: object = "",
    checked_at: object = "",
) -> dict:
    """Update a proxy's exit IP. On change, clear last_error only — not cooldown."""
    try:
        normalized = normalize_proxy(url)
    except ProxyValidationError:
        return {"ok": False, "cleared": False, "ip_changed": False}
    new_ip = _clean_text(new_exit_ip, 64)
    if not new_ip:
        return {
            "ok": False,
            "cleared": False,
            "ip_changed": False,
            "url": normalized,
        }
    applied = {
        "ok": False,
        "cleared": False,
        "ip_changed": False,
        "url": normalized,
        "old_ip": "",
        "new_ip": new_ip,
    }
    with exclusive_file_lock(LOCK_PATH):
        state, _ = _read_unlocked()
        for item in state["items"]:
            if item["url"] != normalized:
                continue
            old_ip = str(item.get("exit_ip") or "").strip()
            ip_changed = bool(old_ip and new_ip and old_ip != new_ip)
            had_error = bool(str(item.get("last_error") or "").strip())
            item["exit_ip"] = new_ip
            item["last_checked_at"] = _clean_text(checked_at, 40) or _utc_now()
            if asn is not None:
                try:
                    item["asn"] = int(asn) if asn not in ("",) else item.get("asn")
                except (TypeError, ValueError):
                    pass
            if asn_org:
                item["asn_org"] = _clean_text(asn_org, 120)
            cleared = False
            if ip_changed:
                item["last_error"] = ""
                cleared = had_error
            applied.update(
                {
                    "ok": True,
                    "cleared": cleared,
                    "ip_changed": ip_changed,
                    "old_ip": old_ip,
                    "new_ip": new_ip,
                }
            )
            _write_unlocked(state)
            break
    return applied


def refresh_dynamic_exit_ips(
    *,
    timeout: float = EXIT_IP_REFRESH_TIMEOUT,
    extra_urls: list[str] | None = None,
    probe_fn=None,
    on_progress=None,
) -> dict:
    """Probe enabled nodes and clear risk when a dynamic exit IP has changed."""
    probe = probe_fn or probe_exit_ip
    timeout = max(1.5, min(float(timeout), 12.0))
    urls: list[str] = []
    seen: set[str] = set()
    with exclusive_file_lock(LOCK_PATH):
        state, _ = _read_unlocked()
        for item in state["items"]:
            if not item.get("enabled"):
                continue
            if _url_port(item.get("url")) in BLOCKED_WORKER_PORTS:
                continue
            url = str(item.get("url") or "")
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
    for raw in extra_urls or []:
        try:
            url = normalize_proxy(raw)
        except ProxyValidationError:
            continue
        if url not in seen:
            seen.add(url)
            urls.append(url)
    changed: list[dict] = []
    cleared: list[dict] = []
    failed = 0
    done = 0

    def _emit() -> None:
        if not callable(on_progress):
            return
        on_progress(
            {
                "total": len(urls),
                "checked": done,
                "changed": len(changed),
                "cleared": len(cleared),
                "failed": failed,
            }
        )

    _emit()
    if not urls:
        return {
            "ok": True,
            "checked": 0,
            "changed": changed,
            "cleared": cleared,
            "failed": 0,
        }

    def _probe_one(url: str) -> tuple[str, dict | None]:
        try:
            return url, probe(url, timeout=timeout)
        except Exception:
            return url, None

    workers = min(EXIT_IP_REFRESH_WORKERS, max(1, len(urls)))
    overall = max(8.0, (len(urls) / max(workers, 1)) * (timeout + 1.5) + 4.0)
    executor = ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="proxy-ip-refresh"
    )
    try:
        futures = [executor.submit(_probe_one, url) for url in urls]
        try:
            completed = as_completed(futures, timeout=overall)
            for future in completed:
                try:
                    url, probed = future.result(timeout=0.1)
                except Exception:
                    failed += 1
                    done += 1
                    _emit()
                    continue
                if not probed:
                    failed += 1
                    done += 1
                    _emit()
                    continue
                try:
                    applied = apply_changed_exit_ip(
                        url,
                        probed.get("exit_ip"),
                        asn=probed.get("asn"),
                        asn_org=probed.get("asn_org") or "",
                        checked_at=probed.get("checked_at") or "",
                    )
                except Exception:
                    failed += 1
                    done += 1
                    _emit()
                    continue
                if applied.get("ip_changed"):
                    changed.append(applied)
                if applied.get("cleared"):
                    cleared.append(applied)
                done += 1
                _emit()
        except TimeoutError:
            unfinished = sum(1 for future in futures if not future.done())
            failed += unfinished
            done = min(len(urls), done + unfinished)
            _emit()
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return {
        "ok": True,
        "checked": len(urls),
        "changed": changed,
        "cleared": cleared,
        "failed": failed,
    }


def _apply_probe_result(proxy_id: str, result: dict) -> None:
    with exclusive_file_lock(LOCK_PATH):
        state, _ = _read_unlocked()
        found = False
        for item in state["items"]:
            if item["id"] != proxy_id:
                continue
            found = True
            item["last_checked_at"] = result.get("checked_at") or _utc_now()
            if result.get("ok"):
                item["status"] = "healthy"
                item["exit_ip"] = _clean_text(result.get("exit_ip"), 64)
                item["asn"] = result.get("asn")
                item["asn_org"] = _clean_text(result.get("asn_org"), 120)
                item["latency_ms"] = result.get("latency_ms")
                item["last_error"] = ""
                item["cooldown_until"] = ""
                item["cooldown_reason"] = ""
            else:
                item["status"] = "unhealthy"
                item["latency_ms"] = None
                item["last_error"] = _clean_text(result.get("error")) or "代理探测失败"
                item["failure_count"] += 1
                item["cooldown_until"] = ""
                item["cooldown_reason"] = ""
            break
        if found:
            _write_unlocked(state)


def _probe_task(proxy_id: str, url: str, timeout: float) -> tuple[str, dict]:
    try:
        return proxy_id, probe_proxy(url, timeout=timeout)
    except Exception as exc:
        return proxy_id, {
            "ok": False,
            "error": _probe_error_message(exc),
            "checked_at": _utc_now(),
        }


def _run_test_job(job_id: str, selected: list[tuple[str, str]], timeout: float) -> None:
    try:
        workers = min(4, max(1, len(selected)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="proxy-test") as executor:
            futures = [
                executor.submit(_probe_task, proxy_id, url, timeout)
                for proxy_id, url in selected
            ]
            for future in as_completed(futures):
                proxy_id, result = future.result()
                _apply_probe_result(proxy_id, result)
                with _TEST_LOCK:
                    if _TEST_JOB.get("job_id") != job_id:
                        continue
                    _TEST_JOB["completed"] += 1
                    key = "healthy" if result.get("ok") else "failed"
                    _TEST_JOB[key] += 1
                    _TEST_JOB["testing_ids"] = [
                        value for value in _TEST_JOB["testing_ids"] if value != proxy_id
                    ]
    finally:
        with _TEST_LOCK:
            if _TEST_JOB.get("job_id") == job_id:
                _TEST_JOB["running"] = False
                _TEST_JOB["finished_at"] = _utc_now()
                _TEST_JOB["testing_ids"] = []


def exit_ip_refresh_status() -> dict:
    with _REFRESH_LOCK:
        job = dict(_REFRESH_JOB)
    with _LOOP_GUARD:
        job["loop_enabled"] = bool(_LOOP_STATE.get("enabled"))
        job["interval_seconds"] = int(
            _LOOP_STATE.get("interval_seconds") or PROXY_IP_REFRESH_SECONDS
        )
        job["next_at"] = str(_LOOP_STATE.get("next_at") or "")
    return job


def start_exit_ip_refresh(*, timeout: float = EXIT_IP_REFRESH_TIMEOUT) -> dict:
    """Manually probe exit IPs and clear risk when a dynamic node rotated."""
    with _REFRESH_LOCK:
        if _REFRESH_JOB.get("running"):
            return {"ok": True, "already_running": True, **dict(_REFRESH_JOB)}
        job_id = hashlib.sha256(f"ip-refresh:{time.time_ns()}".encode()).hexdigest()[:12]
        _REFRESH_JOB.update(
            {
                "running": True,
                "job_id": job_id,
                "total": 0,
                "checked": 0,
                "changed": 0,
                "cleared": 0,
                "failed": 0,
                "started_at": _utc_now(),
                "finished_at": None,
                "error": "",
            }
        )

    def _on_progress(progress: dict) -> None:
        with _REFRESH_LOCK:
            if _REFRESH_JOB.get("job_id") != job_id:
                return
            _REFRESH_JOB.update(
                {
                    "total": int(progress.get("total") or 0),
                    "checked": int(progress.get("checked") or 0),
                    "changed": int(progress.get("changed") or 0),
                    "cleared": int(progress.get("cleared") or 0),
                    "failed": int(progress.get("failed") or 0),
                }
            )

    def _run() -> None:
        try:
            result = refresh_dynamic_exit_ips(
                timeout=timeout,
                on_progress=_on_progress,
            )
            with _REFRESH_LOCK:
                if _REFRESH_JOB.get("job_id") != job_id:
                    return
                _REFRESH_JOB.update(
                    {
                        "total": int(result.get("checked") or _REFRESH_JOB.get("total") or 0),
                        "checked": int(result.get("checked") or 0),
                        "changed": len(result.get("changed") or []),
                        "cleared": len(result.get("cleared") or []),
                        "failed": int(result.get("failed") or 0),
                        "error": "",
                    }
                )
        except Exception as exc:
            with _REFRESH_LOCK:
                if _REFRESH_JOB.get("job_id") == job_id:
                    _REFRESH_JOB["error"] = _probe_error_message(exc)
        finally:
            with _REFRESH_LOCK:
                if _REFRESH_JOB.get("job_id") == job_id:
                    _REFRESH_JOB["running"] = False
                    _REFRESH_JOB["finished_at"] = _utc_now()

    threading.Thread(target=_run, name=f"proxy-ip-refresh-{job_id}", daemon=True).start()
    return {"ok": True, **exit_ip_refresh_status()}


def _exit_ip_refresh_loop() -> None:
    while True:
        with _LOOP_GUARD:
            enabled = bool(_LOOP_STATE.get("enabled"))
            next_at = _parse_utc(_LOOP_STATE.get("next_at"))
            interval = int(
                _LOOP_STATE.get("interval_seconds") or PROXY_IP_REFRESH_SECONDS
            )
        if not enabled:
            time.sleep(0.4)
            continue
        now = datetime.now(timezone.utc)
        delay = (next_at - now).total_seconds() if next_at else 0.0
        if delay > 0:
            time.sleep(min(delay, 0.4))
            continue
        with _REFRESH_LOCK:
            running = bool(_REFRESH_JOB.get("running"))
        if running:
            time.sleep(0.4)
            continue
        start_exit_ip_refresh()
        with _LOOP_GUARD:
            if _LOOP_STATE.get("enabled"):
                _LOOP_STATE["next_at"] = _future_utc(max(30, interval))


def _ensure_exit_ip_refresh_loop_thread() -> None:
    global _LOOP_THREAD
    with _LOOP_GUARD:
        if _LOOP_THREAD is not None and _LOOP_THREAD.is_alive():
            return
        _LOOP_THREAD = threading.Thread(
            target=_exit_ip_refresh_loop,
            name="proxy-ip-refresh-loop",
            daemon=True,
        )
        _LOOP_THREAD.start()


def set_exit_ip_refresh_enabled(enabled: object = None) -> dict:
    """Toggle the 300s exit-IP refresh loop. Enabling fires one refresh immediately."""
    with _LOOP_GUARD:
        if enabled is None:
            turn_on = not bool(_LOOP_STATE.get("enabled"))
        else:
            turn_on = bool(enabled)
        interval = max(30, int(_LOOP_STATE.get("interval_seconds") or PROXY_IP_REFRESH_SECONDS))
        _LOOP_STATE["enabled"] = turn_on
        _LOOP_STATE["interval_seconds"] = interval
        if turn_on:
            _LOOP_STATE["next_at"] = _future_utc(interval)
        else:
            _LOOP_STATE["next_at"] = ""
    if turn_on:
        _ensure_exit_ip_refresh_loop_thread()
        start_exit_ip_refresh()
    return {"ok": True, **exit_ip_refresh_status()}


def start_proxy_tests(ids: object = None, *, timeout: float = DEFAULT_TEST_TIMEOUT) -> dict:
    requested = {
        str(value or "").strip()
        for value in (ids if isinstance(ids, (list, tuple, set)) else [])
        if str(value or "").strip()
    }
    with _TEST_LOCK:
        if _TEST_JOB.get("running"):
            return {"ok": False, "error": "已有代理检测任务正在运行", **proxy_test_status()}
        with exclusive_file_lock(LOCK_PATH):
            state, _ = _read_unlocked()
            selected = [
                (item["id"], item["url"])
                for item in state["items"]
                if (item["id"] in requested if requested else item["enabled"])
            ]
        if not selected:
            return {"ok": False, "error": "没有可检测的代理"}
        if len(selected) > MAX_TEST_ITEMS:
            return {"ok": False, "error": f"单次最多检测 {MAX_TEST_ITEMS} 条代理"}
        job_id = hashlib.sha256(f"{time.time_ns()}:{len(selected)}".encode()).hexdigest()[:12]
        _TEST_JOB.update(
            {
                "running": True,
                "job_id": job_id,
                "total": len(selected),
                "completed": 0,
                "healthy": 0,
                "failed": 0,
                "started_at": _utc_now(),
                "finished_at": None,
                "testing_ids": [proxy_id for proxy_id, _ in selected],
            }
        )
        thread = threading.Thread(
            target=_run_test_job,
            args=(job_id, selected, max(2.0, min(float(timeout), 20.0))),
            name=f"proxy-test-{job_id}",
            daemon=True,
        )
        thread.start()
        return {"ok": True, **proxy_test_status()}
