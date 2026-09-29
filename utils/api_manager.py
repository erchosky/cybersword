"""
CyberSword - Centralized API manager with rate limiting and error handling.
"""

from typing import Optional
from urllib.parse import quote

from rich.console import Console

import requests

from utils.helpers import (
    load_config, get_api_key, get_rate_limiter,
    make_session, cache_get, cache_set
)

console = Console()


def _rl_get(service: str, url: str, *, params: dict = None, headers: dict = None,
            timeout: int = 15, cache_key: str = None) -> Optional[dict]:
    """Rate-limited GET with optional caching."""
    if cache_key:
        hit = cache_get(cache_key)
        if hit is not None:
            return hit

    rl = get_rate_limiter(service)
    rl.wait()

    cfg = load_config()
    t = cfg.get("settings", {}).get("timeout", timeout)
    sess = make_session()
    try:
        resp = sess.get(url, params=params or {}, headers=headers or {}, timeout=t)
        resp.raise_for_status()
        data = resp.json()
        if cache_key:
            cache_set(cache_key, data)
        return data
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else None
        if status == 429:
            # Sin espera bloqueante: el usuario puede repetir la consulta más tarde.
            return {"error": f"{service}: límite de peticiones alcanzado, inténtalo más tarde"}
        if status in (401, 403):
            return {"error": f"{service}: clave de API no válida o sin permisos"}
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def vt_url_report(url: str) -> Optional[dict]:
    key = get_api_key("virustotal")
    if not key:
        return {"error": "VirusTotal API key not configured"}
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    result = _rl_get(
        "virustotal",
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": key},
        cache_key=f"vt_url:{url}",
    )
    return result


def vt_ip_report(ip: str) -> Optional[dict]:
    key = get_api_key("virustotal")
    if not key:
        return {"error": "VirusTotal API key not configured"}
    return _rl_get(
        "virustotal",
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": key},
        cache_key=f"vt_ip:{ip}",
    )


def vt_domain_report(domain: str) -> Optional[dict]:
    key = get_api_key("virustotal")
    if not key:
        return {"error": "VirusTotal API key not configured"}
    return _rl_get(
        "virustotal",
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": key},
        cache_key=f"vt_domain:{domain}",
    )


def vt_file_report(file_hash: str) -> Optional[dict]:
    key = get_api_key("virustotal")
    if not key:
        return {"error": "VirusTotal API key not configured"}
    return _rl_get(
        "virustotal",
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": key},
        cache_key=f"vt_file:{file_hash}",
    )


def vt_submit_url(target_url: str) -> Optional[dict]:
    """Submit a URL to VirusTotal for scanning."""
    key = get_api_key("virustotal")
    if not key:
        return {"error": "VirusTotal API key not configured"}
    rl = get_rate_limiter("virustotal")
    rl.wait()
    sess = make_session()
    try:
        resp = sess.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": key},
            data={"url": target_url},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

def abuseipdb_check(ip: str) -> Optional[dict]:
    key = get_api_key("abuseipdb")
    if not key:
        return {"error": "AbuseIPDB API key not configured"}
    return _rl_get(
        "abuseipdb",
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        headers={"Key": key, "Accept": "application/json"},
        cache_key=f"abuseipdb:{ip}",
    )


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

def shodan_host(ip: str) -> Optional[dict]:
    key = get_api_key("shodan")
    if not key:
        return {"error": "Shodan API key not configured"}
    return _rl_get(
        "shodan",
        f"https://api.shodan.io/shodan/host/{ip}",
        params={"key": key},
        cache_key=f"shodan:{ip}",
    )


# ---------------------------------------------------------------------------
# ipinfo.io
# ---------------------------------------------------------------------------

def ipinfo_lookup(ip: str) -> Optional[dict]:
    key = get_api_key("ipinfo")
    params = {}
    if key:
        params["token"] = key
    return _rl_get(
        "ipinfo",
        f"https://ipinfo.io/{ip}/json",
        params=params,
        cache_key=f"ipinfo:{ip}",
    )


# ---------------------------------------------------------------------------
# HaveIBeenPwned
# ---------------------------------------------------------------------------

def hibp_check_email(email: str) -> Optional[list]:
    key = get_api_key("haveibeenpwned")
    if not key:
        return {"error": "HaveIBeenPwned API key not configured"}
    rl = get_rate_limiter("hibp")
    rl.wait()
    sess = make_session()
    try:
        resp = sess.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}",
            headers={
                "hibp-api-key": key,
                "user-agent": "CyberSword-OSINT/1.0",
            },
            params={"truncateResponse": False},
            timeout=15,
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def hibp_check_password(password: str) -> Optional[int]:
    """k-anonymity HIBP password check — never sends full password."""
    import hashlib
    # The HIBP k-anonymity protocol requires SHA-1 as an identifier, not as a
    # password-storage primitive.
    sha1 = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    sess = make_session()
    try:
        resp = sess.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=10,
        )
        resp.raise_for_status()
        for line in resp.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
        return 0
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------------------------

def google_safe_browsing(url: str) -> Optional[dict]:
    key = get_api_key("google_safe_browsing")
    if not key:
        return {"error": "Google Safe Browsing API key not configured"}
    payload = {
        "client": {"clientId": "cybersword", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    sess = make_session()
    try:
        resp = sess.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": key},
            json=payload,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

def otx_indicator(indicator_type: str, indicator: str, section: str = "general") -> Optional[dict]:
    """indicator_type: IPv4, domain, hostname, url, FileHash-MD5, FileHash-SHA256, email"""
    key = get_api_key("alienvault_otx")
    headers = {}
    if key:
        headers["X-OTX-API-KEY"] = key
    return _rl_get(
        "otx",
        f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/{section}",
        headers=headers,
        cache_key=f"otx:{indicator_type}:{indicator}:{section}",
    )


# ---------------------------------------------------------------------------
# abuse.ch (MalwareBazaar, URLhaus)
# ---------------------------------------------------------------------------

def _abusech_headers() -> Optional[dict]:
    """Desde 2025 las APIs de abuse.ch exigen una Auth-Key gratuita (https://auth.abuse.ch/)."""
    key = get_api_key("abusech")
    return {"Auth-Key": key} if key else None


def malwarebazaar_hash(file_hash: str) -> Optional[dict]:
    headers = _abusech_headers()
    if headers is None:
        return {"error": "abuse.ch API key not configured"}
    sess = make_session()
    try:
        resp = sess.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": file_hash},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# IPQualityScore
# ---------------------------------------------------------------------------

def ipqs_ip(ip: str) -> Optional[dict]:
    key = get_api_key("ipqualityscore")
    if not key:
        return {"error": "IPQualityScore API key not configured"}
    return _rl_get(
        "ipqs",
        f"https://www.ipqualityscore.com/api/json/ip/{key}/{ip}",
        params={"strictness": 1, "allow_public_access_points": True},
        cache_key=f"ipqs:{ip}",
    )


def ipqs_email(email: str) -> Optional[dict]:
    key = get_api_key("ipqualityscore")
    if not key:
        return {"error": "IPQualityScore API key not configured"}
    return _rl_get(
        "ipqs",
        f"https://www.ipqualityscore.com/api/json/email/{key}/{email}",
        params={"strictness": 1},
        cache_key=f"ipqs_email:{email}",
    )


def ipqs_phone(phone: str) -> Optional[dict]:
    key = get_api_key("ipqualityscore")
    if not key:
        return {"error": "IPQualityScore API key not configured"}
    return _rl_get(
        "ipqs",
        f"https://www.ipqualityscore.com/api/json/phone/{key}/{phone}",
        cache_key=f"ipqs_phone:{phone}",
    )


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------

def urlhaus_check(url: str) -> Optional[dict]:
    headers = _abusech_headers()
    if headers is None:
        return {"error": "abuse.ch API key not configured"}
    sess = make_session()
    try:
        resp = sess.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def urlhaus_host(host: str) -> Optional[dict]:
    headers = _abusech_headers()
    if headers is None:
        return {"error": "abuse.ch API key not configured"}
    sess = make_session()
    try:
        resp = sess.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": host},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# PhishTank
# ---------------------------------------------------------------------------

def phishtank_check(url: str) -> Optional[dict]:
    sess = make_session()
    try:
        resp = sess.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json"},
            headers={"User-Agent": "phishtank/CyberSword"},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None
