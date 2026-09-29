"""
CyberSword - Email Analyzer
Parses headers, traces hops, detects spoofing, scores phishing risk.
"""

import re
import hashlib
from email import policy
from email.parser import BytesParser, Parser
from typing import Optional
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

from urllib.parse import urlparse

from utils.helpers import (
    contains_term, extract_urls, is_url_shortener, is_valid_ip, is_private_ip,
    log_analysis
)
from utils.output import (
    print_section, print_result_table, print_risk_score,
    print_error, save_results
)

console = Console()

# Phishing keywords weighted by severity
PHISHING_KEYWORDS = {
    "urgente": 10, "urgent": 10, "immediately": 10, "account suspended": 15,
    "verify your account": 12, "confirm your identity": 12, "click here": 5,
    "limited time": 8, "act now": 8, "free": 3, "winner": 8, "prize": 8,
    "congratulations": 5, "password expired": 12, "unusual activity": 10,
    "login attempt": 8, "suspended": 10, "blocked": 8, "verify": 6,
    "update your": 6, "confirm your": 6, "bank": 4, "paypal": 5,
    "amazon": 4, "microsoft": 4, "apple": 4, "google": 3,
    "click the link": 8, "your account": 4, "security alert": 10,
    "cuentabloqueada": 12, "verificar": 6, "contraseña": 4,
}

BRAND_IMPERSONATION = [
    "paypal", "amazon", "ebay", "microsoft", "apple", "google",
    "facebook", "instagram", "twitter", "netflix", "spotify",
    "bankofamerica", "chase", "wellsfargo", "santander", "bbva",
    "caixabank", "ing", "correos", "dhl", "fedex", "ups",
]


def analyze_email(source: str, is_file: bool = False) -> dict:
    """Main email analysis entry point."""
    print_section("Email Analyzer", "📧")

    try:
        if is_file:
            p = Path(source)
            if not p.exists():
                print_error(f"File not found: {source}")
                return {}
            with open(p, "rb") as f:
                msg = BytesParser(policy=policy.default).parse(f)
        else:
            msg = Parser(policy=policy.default).parsestr(source)
    except Exception as e:
        print_error(f"Failed to parse email: {e}")
        return {}

    result = {}

    result["headers"] = _analyze_headers(msg)
    result["auth"] = _check_auth(msg)
    result["hops"] = _trace_hops(msg)
    result["body"] = _analyze_body(msg)
    result["links"] = _extract_links(msg)
    result["attachments"] = _analyze_attachments(msg)
    result["risk_score"], result["risk_details"] = _calculate_risk(result)

    _display_results(result)
    log_analysis("email", source[:80], result)

    return result


def _analyze_headers(msg) -> dict:
    headers = {}
    important = [
        "From", "To", "Cc", "Reply-To", "Return-Path", "Date",
        "Subject", "Message-ID", "X-Originating-IP", "X-Mailer",
        "X-Sender", "X-Forwarded-To", "Delivered-To",
        "Authentication-Results", "DKIM-Signature",
    ]
    for h in important:
        val = msg.get(h, "")
        if val:
            headers[h] = str(val)

    # Detect mismatches
    from_addr = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    return_path = headers.get("Return-Path", "")

    headers["_analysis"] = {}
    if reply_to and from_addr:
        from_domain = _extract_domain(from_addr)
        reply_domain = _extract_domain(reply_to)
        if from_domain and reply_domain and from_domain != reply_domain:
            headers["_analysis"]["reply_to_mismatch"] = True
            headers["_analysis"]["from_domain"] = from_domain
            headers["_analysis"]["reply_to_domain"] = reply_domain

    if return_path and from_addr:
        rp_domain = _extract_domain(return_path)
        from_domain = _extract_domain(from_addr)
        if rp_domain and from_domain and rp_domain != from_domain:
            headers["_analysis"]["return_path_mismatch"] = True

    return headers


def _check_auth(msg) -> dict:
    auth = {
        "spf": "not found",
        "dkim": "not found",
        "dmarc": "not found",
        "spf_pass": False,
        "dkim_pass": False,
        "dmarc_pass": False,
    }

    auth_results = str(msg.get("Authentication-Results", ""))
    received_spf = str(msg.get("Received-SPF", ""))

    # Received-SPF usa otro formato ("Received-SPF: Pass (...)"): se normaliza a "spf=pass".
    spf_word = received_spf.strip().split(" ", 1)[0].lower()
    combined = (auth_results + (f" spf={spf_word}" if spf_word else "")).lower()

    # SPF
    if "spf=pass" in combined:
        auth["spf"] = "PASS"
        auth["spf_pass"] = True
    elif "spf=fail" in combined:
        auth["spf"] = "FAIL"
    elif "spf=softfail" in combined:
        auth["spf"] = "SOFTFAIL"
    elif "spf=neutral" in combined:
        auth["spf"] = "NEUTRAL"
    elif "spf=none" in combined:
        auth["spf"] = "NONE"

    # DKIM
    dkim_sig = msg.get("DKIM-Signature", "")
    if "dkim=pass" in combined:
        auth["dkim"] = "PASS"
        auth["dkim_pass"] = True
    elif "dkim=fail" in combined:
        auth["dkim"] = "FAIL"
    elif dkim_sig:
        auth["dkim"] = "SIGNATURE PRESENT (unverified)"

    # DMARC
    if "dmarc=pass" in combined:
        auth["dmarc"] = "PASS"
        auth["dmarc_pass"] = True
    elif "dmarc=fail" in combined:
        auth["dmarc"] = "FAIL"
    elif "dmarc=none" in combined:
        auth["dmarc"] = "NONE"

    # Try DNS lookup for domain's DMARC
    from_addr = msg.get("From", "")
    domain = _extract_domain(from_addr)
    if domain:
        auth["from_domain"] = domain
        try:
            import dns.resolver
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                auth["dmarc_record"] = str(rdata)
        except Exception:
            auth["dmarc_record"] = "not found"

    return auth


def _trace_hops(msg) -> list:
    hops = []
    received_headers = msg.get_all("Received") or []

    for i, received in enumerate(reversed(received_headers)):
        hop = {"hop": i + 1, "raw": received[:200]}
        # Extract IPs
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", received)
        valid_ips = [ip for ip in ips if is_valid_ip(ip) and not is_private_ip(ip)]
        hop["ips"] = valid_ips

        # Extract timestamp
        time_match = re.search(
            r"(\d{1,2}\s+\w+\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})", received
        )
        if time_match:
            hop["timestamp"] = time_match.group(1)

        # Extract hostnames
        by_match = re.search(r"by\s+([^\s;]+)", received)
        from_match = re.search(r"from\s+([^\s(]+)", received)
        if by_match:
            hop["by"] = by_match.group(1)
        if from_match:
            hop["from"] = from_match.group(1)

        # Geolocate non-private IPs
        if valid_ips:
            hop["geo"] = {}
            for ip in valid_ips[:2]:
                geo = _geolocate_ip(ip)
                if geo:
                    hop["geo"][ip] = geo

        hops.append(hop)

    return hops


def _analyze_body(msg) -> dict:
    body_data = {"text": "", "html": "", "phishing_indicators": [], "score": 0}

    # Extract text/plain and text/html
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            charset = part.get_content_charset() or "utf-8"
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                decoded = payload.decode(charset, errors="replace")
                if ct == "text/plain":
                    body_data["text"] = decoded[:5000]
                elif ct == "text/html":
                    body_data["html"] = decoded[:5000]
            except Exception:
                continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body_data["text"] = payload.decode(
                    msg.get_content_charset() or "utf-8", errors="replace"
                )[:5000]
        except Exception:
            pass

    text_lower = (body_data["text"] + " " + body_data["html"]).lower()

    # Check phishing keywords
    score = 0
    found = []
    for kw, weight in PHISHING_KEYWORDS.items():
        if contains_term(text_lower, kw):
            found.append({"keyword": kw, "weight": weight})
            score += weight

    body_data["phishing_indicators"] = found
    body_data["score"] = min(score, 100)

    # Check brand impersonation
    # Palabra completa: "ing" no debe coincidir con "shipping" ni "ups" con "groups".
    impersonated = [b for b in BRAND_IMPERSONATION if contains_term(text_lower, b)]
    body_data["impersonated_brands"] = impersonated

    # Check urgency patterns
    urgency_patterns = [
        r"within\s+\d+\s+(hours?|minutes?|days?)",
        r"expires?\s+(today|soon|in \d+)",
        r"\d+\s+hours?\s+left",
        r"act\s+(now|immediately|fast)",
    ]
    urgency_matches = []
    for pat in urgency_patterns:
        m = re.search(pat, text_lower)
        if m:
            urgency_matches.append(m.group(0))
    body_data["urgency_patterns"] = urgency_matches

    return body_data


def _extract_links(msg) -> list:
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text += payload.decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
            except Exception:
                continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body_text = payload.decode(
                    msg.get_content_charset() or "utf-8", errors="replace"
                )
        except Exception:
            pass

    urls = extract_urls(body_text)

    # Also extract from HTML href attributes
    href_pattern = r'href=["\']([^"\']+)["\']'
    html_urls = re.findall(href_pattern, body_text, re.IGNORECASE)
    urls = list(set(urls + [u for u in html_urls if u.startswith("http")]))

    links = []
    for url in urls[:20]:  # Limit to 20 links
        link = {"url": url}
        link["is_shortened"] = is_url_shortener(urlparse(url).hostname or "")
        # Check domain mismatch in display text vs URL
        link["domain"] = _extract_domain(url)
        links.append(link)

    return links


def _analyze_attachments(msg) -> list:
    attachments = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            att = {}
            att["filename"] = part.get_filename() or "unknown"
            att["content_type"] = part.get_content_type()
            payload = part.get_payload(decode=True)
            if payload:
                att["size"] = len(payload)
                att["md5"] = hashlib.md5(payload, usedforsecurity=False).hexdigest()
                att["sha256"] = hashlib.sha256(payload).hexdigest()
                # Detect real file type by magic bytes
                att["magic_type"] = _detect_magic(payload[:16])
                # Extract printable strings
                strings = re.findall(rb"[ -~]{6,}", payload)
                att["suspicious_strings"] = [
                    s.decode("ascii", errors="replace")
                    for s in strings[:10]
                    if any(kw in s.lower() for kw in
                           [b"http", b"cmd", b"powershell", b"exec", b"eval",
                            b"base64", b"shell", b"download"])
                ]
                # Extension mismatch check
                ext = Path(att["filename"]).suffix.lower()
                att["extension_mismatch"] = (
                    att["magic_type"] not in ["unknown", ""] and
                    ext and not _ext_matches_magic(ext, att["magic_type"])
                )
            attachments.append(att)

    return attachments


def _calculate_risk(result: dict) -> tuple[int, list]:
    score = 0
    details = []

    auth = result.get("auth", {})
    if not auth.get("spf_pass"):
        score += 15
        details.append("SPF failed or missing (+15)")
    if not auth.get("dkim_pass"):
        score += 15
        details.append("DKIM failed or missing (+15)")
    if not auth.get("dmarc_pass"):
        score += 10
        details.append("DMARC failed or missing (+10)")

    headers = result.get("headers", {})
    analysis = headers.get("_analysis", {})
    if analysis.get("reply_to_mismatch"):
        score += 20
        details.append("Reply-To domain differs from From domain (+20)")
    if analysis.get("return_path_mismatch"):
        score += 15
        details.append("Return-Path domain differs from From domain (+15)")

    body = result.get("body", {})
    body_score = body.get("score", 0)
    if body_score > 0:
        contribution = min(body_score, 30)
        score += contribution
        details.append(f"Phishing keywords in body (+{contribution})")

    if body.get("impersonated_brands"):
        score += 10
        details.append(f"Brand impersonation: {', '.join(body['impersonated_brands'][:3])} (+10)")

    if body.get("urgency_patterns"):
        score += 10
        details.append("Artificial urgency patterns detected (+10)")

    links = result.get("links", [])
    shortened = [link for link in links if link.get("is_shortened")]
    if shortened:
        score += 10
        details.append(f"{len(shortened)} shortened URLs detected (+10)")

    for att in result.get("attachments", []):
        if att.get("extension_mismatch"):
            score += 20
            details.append(f"Attachment extension mismatch: {att['filename']} (+20)")
        if att.get("suspicious_strings"):
            score += 15
            details.append(f"Suspicious strings in attachment: {att['filename']} (+15)")

    hops = result.get("hops", [])
    if len(hops) > 8:
        score += 5
        details.append(f"Unusual number of mail hops ({len(hops)}) (+5)")

    return min(score, 100), details


def _display_results(result: dict) -> None:
    # Headers summary
    headers = result.get("headers", {})
    header_rows = [
        (k, str(v)[:100]) for k, v in headers.items()
        if not k.startswith("_") and v
    ]
    print_result_table("Email Headers", header_rows)

    # Auth results
    auth = result.get("auth", {})
    auth_rows = [
        ("SPF", f"[{'green' if auth.get('spf_pass') else 'red'}]{auth.get('spf', 'N/A')}[/]"),
        ("DKIM", f"[{'green' if auth.get('dkim_pass') else 'red'}]{auth.get('dkim', 'N/A')}[/]"),
        ("DMARC", f"[{'green' if auth.get('dmarc_pass') else 'red'}]{auth.get('dmarc', 'N/A')}[/]"),
        ("DMARC Record", auth.get("dmarc_record", "N/A")),
    ]
    print_result_table("Authentication Results", auth_rows)

    # Hops
    hops = result.get("hops", [])
    if hops:
        t = Table(title=f"Mail Route ({len(hops)} hops)", box=box.ROUNDED,
                  header_style="bold blue")
        t.add_column("Hop", width=5)
        t.add_column("From")
        t.add_column("By")
        t.add_column("IPs")
        t.add_column("Geo")
        for hop in hops:
            geo_info = "; ".join(
                f"{ip}: {geo.get('country','?')}/{geo.get('city','?')}"
                for ip, geo in hop.get("geo", {}).items()
            )
            t.add_row(
                str(hop.get("hop", "")),
                hop.get("from", ""),
                hop.get("by", ""),
                ", ".join(hop.get("ips", [])),
                geo_info or "—",
            )
        console.print(t)

    # Body analysis
    body = result.get("body", {})
    if body.get("phishing_indicators"):
        kw_rows = [(f["keyword"], str(f["weight"])) for f in body["phishing_indicators"][:10]]
        print_result_table("Phishing Keywords Found", kw_rows, ["Keyword", "Weight"])

    if body.get("impersonated_brands"):
        console.print(f"[bold red]Brand Impersonation:[/] {', '.join(body['impersonated_brands'])}")

    # Links
    links = result.get("links", [])
    if links:
        link_rows = [
            (link.get("url", "")[:80], link.get("domain", ""),
             "[red]YES[/]" if link.get("is_shortened") else "No")
            for link in links[:15]
        ]
        print_result_table("Links Found", link_rows, ["URL", "Domain", "Shortened?"])

    # Attachments
    for att in result.get("attachments", []):
        att_rows = [
            ("Filename", att.get("filename", "")),
            ("Content-Type", att.get("content_type", "")),
            ("Size", f"{att.get('size', 0):,} bytes"),
            ("MD5", att.get("md5", "")),
            ("SHA256", att.get("sha256", "")),
            ("Detected Type", att.get("magic_type", "")),
            ("Extension Mismatch", "[red]YES[/]" if att.get("extension_mismatch") else "No"),
        ]
        print_result_table(f"Attachment: {att.get('filename')}", att_rows)

    # Risk score
    score = result.get("risk_score", 0)
    print_risk_score(score)
    if result.get("risk_details"):
        console.print("[bold]Risk Factors:[/]")
        for d in result.get("risk_details", []):
            console.print(f"  [yellow]•[/] {d}")


def _geolocate_ip(ip: str) -> Optional[dict]:
    try:
        from utils.api_manager import ipinfo_lookup
        data = ipinfo_lookup(ip)
        if data:
            return {
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "org": data.get("org", ""),
            }
    except Exception:
        pass
    return None


def _extract_domain(addr: str) -> Optional[str]:
    match = re.search(r"@([\w.\-]+)", addr)
    return match.group(1).lower() if match else None


def _detect_magic(header: bytes) -> str:
    signatures = {
        b"\x4d\x5a": "PE/EXE",
        b"\x50\x4b\x03\x04": "ZIP",
        b"\x25\x50\x44\x46": "PDF",
        b"\xff\xd8\xff": "JPEG",
        b"\x89\x50\x4e\x47": "PNG",
        b"\x47\x49\x46\x38": "GIF",
        b"\x7f\x45\x4c\x46": "ELF",
        b"\xd0\xcf\x11\xe0": "Office/OLE",
        b"\x1f\x8b": "GZIP",
        b"\x42\x5a\x68": "BZIP2",
        b"\x52\x61\x72\x21": "RAR",
    }
    for sig, name in signatures.items():
        if header.startswith(sig):
            return name
    return "unknown"


def _ext_matches_magic(ext: str, magic: str) -> bool:
    mapping = {
        ".exe": ["PE/EXE"], ".dll": ["PE/EXE"],
        ".pdf": ["PDF"], ".jpg": ["JPEG"], ".jpeg": ["JPEG"],
        ".png": ["PNG"], ".gif": ["GIF"],
        ".zip": ["ZIP"], ".docx": ["ZIP"], ".xlsx": ["ZIP"],
        ".elf": ["ELF"], ".gz": ["GZIP"], ".bz2": ["BZIP2"],
        ".rar": ["RAR"], ".doc": ["Office/OLE"], ".xls": ["Office/OLE"],
    }
    return magic in mapping.get(ext, [magic])


def run():
    console.print("\n[bold cyan]Email Analyzer[/]")
    console.print("1. Analyze raw email headers (paste text)")
    console.print("2. Analyze .eml file")
    choice = console.input("\n[bold]>[/] ").strip()

    if choice == "1":
        console.print("[dim]Paste email headers/source (end with '---END---' on its own line):[/]")
        lines = []
        while True:
            line = input()
            if line == "---END---":
                break
            lines.append(line)
        source = "\n".join(lines)
        if source.strip():
            result = analyze_email(source)
            if result:
                _offer_export(result)
    elif choice == "2":
        path = console.input("[bold]Path to .eml file:[/] ").strip()
        result = analyze_email(path, is_file=True)
        if result:
            _offer_export(result)
    else:
        print_error("Invalid option")


def _offer_export(result: dict):
    export = console.input("\n[bold]Export results? (json/txt/html/all/no):[/] ").strip().lower()
    if export == "no" or not export:
        return
    formats = ["json", "txt", "html"] if export == "all" else [export]
    saved = save_results("email", result.get("headers", {}).get("From", "email"), result, formats)
    for fmt, path in saved.items():
        console.print(f"[green]Saved {fmt.upper()}:[/] {path}")
