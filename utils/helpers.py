"""
CyberSword - Common helpers, caching, rate limiting, and network utilities.
"""

import os
import re
import json
import time
import socket
import hashlib
import ipaddress
import threading
from datetime import datetime
from pathlib import Path
from functools import wraps
from typing import Optional, Any

import requests
import yaml
from cachetools import TTLCache
from rich.console import Console

console = Console()
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

_config: dict = {}
_config_lock = threading.Lock()

def load_config(path: str = "config.yaml") -> dict:
    global _config
    with _config_lock:
        if _config:
            return _config
        config_path = Path(path)
        if not config_path.exists():
            config_path = PROJECT_ROOT / path
        if not config_path.exists() and path == "config.yaml":
            config_path = PROJECT_ROOT / "config.example.yaml"
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                _config = yaml.safe_load(f) or {}
        else:
            _config = {}
        return _config


def get_api_key(service: str) -> str:
    """Clave de un servicio: la variable de entorno (si no está vacía) tiene prioridad sobre config.yaml."""
    cfg = load_config()
    env_value = os.environ.get(f"CYBERSWORD_{service.upper()}_API_KEY", "").strip()
    return env_value or cfg.get("api_keys", {}).get(service, "") or ""


def get_setting(key: str, default: Any = None) -> Any:
    cfg = load_config()
    return cfg.get("settings", {}).get(key, default)


# ---------------------------------------------------------------------------
# Result cache
# ---------------------------------------------------------------------------

_cache: TTLCache = TTLCache(maxsize=512, ttl=3600)
_cache_lock = threading.Lock()


def cache_get(key: str) -> Optional[Any]:
    with _cache_lock:
        return _cache.get(key)


def cache_set(key: str, value: Any) -> None:
    with _cache_lock:
        _cache[key] = value


def cached(prefix: str):
    """Decorator: cache function results by prefix + args hash."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            raw = f"{prefix}:{args}:{kwargs}"
            key = hashlib.sha256(raw.encode()).hexdigest()
            hit = cache_get(key)
            if hit is not None:
                return hit
            result = fn(*args, **kwargs)
            if result is not None:
                cache_set(key, result)
            return result
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

_rate_limiters: dict = {}
_rl_lock = threading.Lock()


class RateLimiter:
    def __init__(self, calls: int, period: float):
        self.calls = calls
        self.period = period
        self._timestamps: list = []
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.time()
            self._timestamps = [t for t in self._timestamps if now - t < self.period]
            if len(self._timestamps) >= self.calls:
                sleep_for = self.period - (now - self._timestamps[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
            self._timestamps.append(time.time())


def get_rate_limiter(service: str) -> RateLimiter:
    cfg = load_config()
    limits = cfg.get("rate_limits", {})
    with _rl_lock:
        if service not in _rate_limiters:
            calls = limits.get(service, 10)
            period = 60.0 if service == "virustotal" else 1.0
            _rate_limiters[service] = RateLimiter(calls, period)
        return _rate_limiters[service]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def make_session() -> requests.Session:
    cfg = load_config()
    s = requests.Session()
    proxy = cfg.get("settings", {}).get("proxy", "")
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    ua = cfg.get("settings", {}).get("user_agent", "CyberSword/1.0")
    s.headers.update({"User-Agent": ua})
    return s


def safe_get(url: str, *, timeout: Optional[float] = None, session: Optional[requests.Session] = None,
             headers: dict = None, params: dict = None, verify: bool = True) -> Optional[requests.Response]:
    """GET que devuelve None ante errores de red. Un timeout explícito tiene prioridad sobre la configuración."""
    try:
        cfg = load_config()
        t = timeout if timeout is not None else cfg.get("settings", {}).get("timeout", 15)
        sess = session or make_session()
        verify_tls = cfg.get("settings", {}).get("verify_tls", verify)
        resp = sess.get(
            url,
            timeout=t,
            headers=headers or {},
            params=params or {},
            verify=verify_tls,
        )
        return resp
    except requests.RequestException:
        return None


def check_connectivity(host: str = "8.8.8.8", port: int = 53, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Validators / Parsers
# ---------------------------------------------------------------------------

def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip()).is_private
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value.strip()))


def is_valid_email(value: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value.strip()))


def is_valid_hash(value: str) -> Optional[str]:
    v = value.strip()
    lengths = {32: "MD5", 40: "SHA1", 56: "SHA224", 64: "SHA256", 96: "SHA384", 128: "SHA512"}
    if re.match(r"^[a-fA-F0-9]+$", v):
        return lengths.get(len(v))
    return None


URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
    "rb.gy", "tiny.cc", "is.gd", "buff.ly", "su.pr", "cli.gs",
    "snipurl.com", "wp.me", "adf.ly", "cutt.ly", "shorturl.at",
    "x.co", "dl.fy", "viralurl.net",
})


def hostname_matches(host: str, domain: str) -> bool:
    """True si `host` es `domain` o un subdominio suyo (no basta con contener el texto)."""
    host = host.lower().rstrip(".")
    domain = domain.lower()
    return host == domain or host.endswith("." + domain)


def is_url_shortener(host: str) -> bool:
    return any(hostname_matches(host, shortener) for shortener in URL_SHORTENERS)


def contains_term(text: str, term: str) -> bool:
    """Busca `term` como palabra o expresión completa (evita que "ing" coincida con "shipping")."""
    pattern = r"(?<!\w)" + re.escape(term.lower()) + r"(?!\w)"
    return re.search(pattern, text.lower()) is not None


def contains_pattern(text: str, pattern: str) -> bool:
    """Como `contains_term`, pero para una expresión regular."""
    return re.search(r"(?<!\w)(?:" + pattern + r")(?!\w)", text, re.IGNORECASE) is not None


def extract_urls(text: str) -> list:
    pattern = r"https?://[^\s\"\'\<\>\)\(]+"
    return list(set(re.findall(pattern, text)))


def extract_ips(text: str) -> list:
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    candidates = re.findall(pattern, text)
    return [ip for ip in candidates if is_valid_ip(ip)]


def extract_emails(text: str) -> list:
    pattern = r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    return list(set(re.findall(pattern, text)))


def extract_domains(text: str) -> list:
    pattern = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    return list(set(re.findall(pattern, text)))


# ---------------------------------------------------------------------------
# Logging / Session
# ---------------------------------------------------------------------------

_session_log: list = []
_session_start: datetime = datetime.now()


def log_analysis(module: str, target: str, result: dict) -> None:
    entry = {
        "timestamp": datetime.now().isoformat(),
        "module": module,
        "target": target,
        "result": result,
    }
    _session_log.append(entry)
    cfg = load_config()
    # Los logs pueden contener datos de la investigación: solo se guardan si se pide expresamente.
    if cfg.get("output", {}).get("save_logs", False):
        _persist_log(entry)


def _persist_log(entry: dict) -> None:
    cfg = load_config()
    log_dir = Path(cfg.get("output", {}).get("log_dir", "logs"))
    if not log_dir.is_absolute():
        log_dir = PROJECT_ROOT / log_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    log_file = log_dir / f"cybersword_{date_str}.jsonl"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")


def get_session_log() -> list:
    return _session_log


def get_session_start() -> datetime:
    return _session_start


# ---------------------------------------------------------------------------
# String utilities
# ---------------------------------------------------------------------------

def truncate(s: str, max_len: int = 80) -> str:
    return s if len(s) <= max_len else s[:max_len - 3] + "..."


def human_size(size_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def risk_color(score: int) -> str:
    if score >= 70:
        return "red"
    elif score >= 40:
        return "yellow"
    return "green"


def risk_label(score: int) -> str:
    if score >= 70:
        return "HIGH RISK"
    elif score >= 40:
        return "MEDIUM RISK"
    elif score >= 10:
        return "LOW RISK"
    return "CLEAN"
