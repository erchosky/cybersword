"""
CyberSword - URL & Domain Analyzer
Unshortens URLs, WHOIS, DNS, SSL, VirusTotal, blacklists, tech detection.
"""

import ssl
import socket
import datetime
from urllib.parse import urljoin, urlparse

import dns.resolver
import whois
from rich.console import Console

from utils.helpers import (
    is_url_shortener, log_analysis,
    make_session, safe_get
)
from utils.output import (
    print_section, print_result_table, print_risk_score,
    print_error, print_info, save_results
)
from utils.api_manager import (
    vt_url_report, google_safe_browsing, urlhaus_check, phishtank_check
)

console = Console()

TYPOSQUAT_BRANDS = [
    "google", "facebook", "amazon", "microsoft", "apple", "paypal",
    "netflix", "instagram", "twitter", "linkedin", "github", "dropbox",
    "spotify", "youtube", "whatsapp", "telegram", "bankofamerica",
    "chase", "wellsfargo", "santander", "bbva", "correos", "dhl",
]

SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/config.php", "/wp-config.php",
    "/backup.zip", "/backup.sql", "/database.sql", "/.htpasswd",
    "/admin/", "/phpmyadmin/", "/wp-admin/", "/cpanel/",
    "/.DS_Store", "/robots.txt", "/sitemap.xml",
]

CMS_SIGNATURES = {
    "WordPress": ["/wp-content/", "/wp-includes/", "wp-login.php", "WordPress"],
    "Joomla": ["/components/com_", "/templates/", "Joomla"],
    "Drupal": ["/sites/default/", "Drupal.settings", "X-Generator: Drupal"],
    "Magento": ["/skin/frontend/", "Mage.Cookies", "Magento"],
    "PrestaShop": ["/modules/", "PrestaShop"],
    "Shopify": ["cdn.shopify.com", "Shopify.theme"],
    "Wix": ["wix.com", "static.wixstatic.com"],
}

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
    "X-XSS-Protection", "Cache-Control",
]

TECH_SIGNATURES = {
    "jQuery": [r"jquery[\./](\d+[\.\d]+)", "jquery.min.js"],
    "Bootstrap": ["bootstrap.min.js", "bootstrap.css"],
    "React": ["react.min.js", "__REACT_DEVTOOLS", "react-dom"],
    "Angular": ["ng-version", "angular.min.js"],
    "Vue.js": ["vue.min.js", "__vue__"],
    "Nginx": ["nginx"],
    "Apache": ["Apache/"],
    "PHP": ["X-Powered-By: PHP", ".php"],
    "ASP.NET": ["X-Powered-By: ASP.NET", ".aspx"],
    "CloudFlare": ["cloudflare", "CF-RAY"],
    "Google Analytics": ["google-analytics.com/ga.js", "gtag/js"],
    "WordPress": ["wp-content", "wp-json"],
}


def analyze_url(url: str) -> dict:
    """Full URL analysis pipeline."""
    print_section("URL & Domain Analyzer", "🔗")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print_error(f"Invalid HTTP(S) URL: {url}")
        return {}
    original_domain = parsed.hostname.removeprefix("www.")

    result = {"original_url": url, "original_domain": original_domain}

    console.print(f"\n[bold]Analyzing:[/] [cyan]{url}[/]")

    with console.status("[bold green]Unshortening & following redirects..."):
        result["redirect_chain"] = _follow_redirects(url)
        result["final_url"] = result["redirect_chain"][-1] if result["redirect_chain"] else url
        result["is_shortened"] = is_url_shortener(original_domain)

    # Lo relevante es el destino real: en un enlace acortado o con redirecciones,
    # WHOIS, DNS, certificado, reputación y typosquatting se evalúan sobre el dominio final.
    final_url = result["final_url"]
    domain = (urlparse(final_url).hostname or original_domain).removeprefix("www.")
    result["domain"] = domain
    if domain != original_domain:
        console.print(f"[bold]Final destination:[/] [cyan]{final_url}[/]")

    with console.status("[bold green]WHOIS lookup..."):
        result["whois"] = _whois_lookup(domain)

    with console.status("[bold green]DNS records..."):
        result["dns"] = _dns_lookup(domain)

    with console.status("[bold green]SSL certificate..."):
        result["ssl"] = _ssl_check(domain)

    with console.status("[bold green]Reputation checks..."):
        result["reputation"] = _check_reputation(final_url, domain)

    with console.status("[bold green]Technology detection..."):
        result["technologies"] = _detect_technologies(final_url)

    with console.status("[bold green]Security headers..."):
        result["security_headers"] = _check_security_headers(final_url)

    result["typosquatting"] = _check_typosquatting(domain)
    result["domain_age_warning"] = _is_new_domain(result.get("whois", {}))
    result["risk_score"], result["risk_details"] = _calculate_risk(result)

    _display_results(result)
    log_analysis("url", url, result)

    return result


def _follow_redirects(url: str, max_hops: int = 10) -> list:
    chain = [url]
    sess = make_session()
    sess.max_redirects = max_hops
    current = url
    try:
        for _ in range(max_hops):
            try:
                resp = sess.head(current, allow_redirects=False, timeout=10)
            except Exception:
                resp = sess.get(current, allow_redirects=False, timeout=10,
                                stream=True)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if location and location != current:
                    next_url = urljoin(current, location)
                    parsed_next = urlparse(next_url)
                    if parsed_next.scheme not in ("http", "https"):
                        break
                    chain.append(next_url)
                    current = next_url
                else:
                    break
            else:
                break
    except Exception:
        pass
    return chain


def _whois_lookup(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        expiration = w.expiration_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiration, list):
            expiration = expiration[0]
        return {
            "registrar": str(w.registrar or ""),
            "creation_date": str(creation or ""),
            "expiration_date": str(expiration or ""),
            "name_servers": list(w.name_servers or [])[:6],
            "status": str(w.status or ""),
            "registrant_country": str(w.country or ""),
            "emails": list(w.emails or []) if isinstance(w.emails, list) else [str(w.emails or "")],
        }
    except Exception as e:
        return {"error": str(e)}


def _dns_lookup(domain: str) -> dict:
    records = {}
    types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
    for rtype in types:
        try:
            answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
            records[rtype] = [str(r) for r in answers]
        except dns.resolver.NXDOMAIN:
            records["NXDOMAIN"] = True
            break
        except dns.exception.DNSException:
            records[rtype] = []
        except Exception:
            records[rtype] = []

    # Reverse DNS for A records
    if records.get("A"):
        records["reverse_dns"] = {}
        for ip in records["A"][:3]:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                records["reverse_dns"][ip] = hostname
            except Exception:
                records["reverse_dns"][ip] = "N/A"

    return records


def _ssl_check(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

        not_before = datetime.datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notBefore"]), tz=datetime.timezone.utc
        )
        not_after = datetime.datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]), tz=datetime.timezone.utc
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        days_left = (not_after - now).days

        san_list = []
        for san_type, san_value in cert.get("subjectAltName", []):
            san_list.append(san_value)

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        return {
            "valid": True,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
            "subject": subject.get("commonName", ""),
            "not_before": str(not_before.date()),
            "not_after": str(not_after.date()),
            "days_remaining": days_left,
            "expired": days_left < 0,
            "expiring_soon": 0 <= days_left <= 30,
            "san_count": len(san_list),
            "sans": san_list[:10],
            "version": tls_version,
        }
    except ssl.SSLCertVerificationError:
        return {"valid": False, "error": "Certificate verification failed"}
    except ConnectionRefusedError:
        return {"valid": None, "error": "Port 443 not open"}
    except Exception as e:
        return {"valid": None, "error": str(e)}


def _check_reputation(url: str, domain: str) -> dict:
    rep = {}

    # VirusTotal
    print_info("Querying VirusTotal...")
    vt = vt_url_report(url)
    if vt and "error" not in vt:
        attrs = vt.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        rep["virustotal"] = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "categories": attrs.get("categories", {}),
        }
    elif vt and "error" in vt:
        rep["virustotal"] = {"info": vt["error"]}
    else:
        rep["virustotal"] = {"info": "No data (submit for scan?)"}

    # URLhaus
    print_info("Querying URLhaus...")
    uh = urlhaus_check(url)
    if uh and "error" in uh:
        rep["urlhaus"] = {"info": uh["error"]}
    elif uh:
        rep["urlhaus"] = {
            "status": uh.get("query_status", ""),
            "threat": uh.get("threat", ""),
            "urls_count": uh.get("urls_count", 0),
        }

    # Google Safe Browsing
    print_info("Querying Google Safe Browsing...")
    gsb = google_safe_browsing(url)
    if gsb and "error" not in gsb:
        matches = gsb.get("matches", [])
        rep["google_safe_browsing"] = {
            "safe": len(matches) == 0,
            "threats": [m.get("threatType", "") for m in matches],
        }
    elif gsb and "error" in gsb:
        rep["google_safe_browsing"] = {"info": gsb["error"]}

    # PhishTank
    print_info("Querying PhishTank...")
    pt = phishtank_check(url)
    if pt:
        rep["phishtank"] = {
            "in_database": pt.get("results", {}).get("in_database", False),
            "verified": pt.get("results", {}).get("verified", False),
        }

    return rep


def _detect_technologies(url: str) -> dict:
    techs = {}
    try:
        resp = safe_get(url, timeout=15)
        if not resp:
            return techs
        html = resp.text[:50000]
        headers = resp.headers

        for tech, patterns in TECH_SIGNATURES.items():
            found = False
            for pat in patterns:
                if pat.lower() in html.lower():
                    found = True
                    break
                header_val = headers.get("Server", "") + headers.get("X-Powered-By", "")
                if pat.lower() in header_val.lower():
                    found = True
                    break
            if found:
                techs[tech] = True

        # CMS detection
        for cms, sigs in CMS_SIGNATURES.items():
            if any(sig in html for sig in sigs):
                techs["CMS"] = cms
                break

        # Server
        if "Server" in headers:
            techs["Server"] = headers["Server"]
        if "X-Powered-By" in headers:
            techs["Powered-By"] = headers["X-Powered-By"]

    except Exception:
        pass
    return techs


def _check_security_headers(url: str) -> dict:
    result = {}
    try:
        resp = safe_get(url, timeout=15)
        if not resp:
            return result
        for h in SECURITY_HEADERS:
            result[h] = resp.headers.get(h, "[MISSING]")
    except Exception:
        pass
    return result


def _check_typosquatting(domain: str) -> dict:
    """Detecta dominios parecidos a marcas conocidas (paypa1.com, secure-amaz0n.net...).

    Se comparan todas las etiquetas del dominio (menos el TLD) y sus partes separadas por
    guiones; una marca exacta entre guiones (paypal-secure-login) también cuenta. Para marcas cortas se exige más parecido: con distancia 2, "dhl" coincidiría
    con casi cualquier palabra de tres letras.
    """
    result = {"is_typosquat": False, "similar_to": []}
    labels = domain.lower().split(".")[:-1]
    tokens = {part for label in labels for part in [label, *label.split("-")] if part}

    hyphenated_parts = {part for label in labels if "-" in label for part in label.split("-")}

    for brand in TYPOSQUAT_BRANDS:
        # Marca exacta dentro de una etiqueta con guiones: paypal-secure-login.com
        if brand in hyphenated_parts:
            result["is_typosquat"] = True
            result["similar_to"].append({"brand": brand, "distance": 0})
            continue
        # Marcas de 3 letras solo cuentan exactas (entre guiones): dhs.gov no es DHL.
        max_distance = 0 if len(brand) <= 3 else (1 if len(brand) <= 5 else 2)
        best = min((_levenshtein(token, brand) for token in tokens), default=None)
        if best is not None and 0 < best <= max_distance:
            result["is_typosquat"] = True
            result["similar_to"].append({"brand": brand, "distance": best})

    return result


def _is_new_domain(whois_data: dict) -> bool:
    """True si el dominio se registró hace menos de 90 días (fecha WHOIS en formato AAAA-MM-DD...)."""
    creation_str = whois_data.get("creation_date", "")
    try:
        creation = datetime.datetime.strptime(creation_str[:10], "%Y-%m-%d")
    except ValueError:
        return False
    return (datetime.datetime.now() - creation).days < 90


def _calculate_risk(result: dict) -> tuple[int, list]:
    score = 0
    details = []

    # Redirect chain
    chain = result.get("redirect_chain", [])
    if len(chain) > 3:
        score += 10
        details.append(f"Long redirect chain ({len(chain)} hops) (+10)")

    # VirusTotal
    vt = result.get("reputation", {}).get("virustotal", {})
    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    if malicious > 0:
        score += min(malicious * 5, 40)
        details.append(f"VirusTotal: {malicious} malicious detections (+{min(malicious*5,40)})")
    if suspicious > 0:
        score += min(suspicious * 2, 20)
        details.append(f"VirusTotal: {suspicious} suspicious detections (+{min(suspicious*2,20)})")

    # URLhaus
    uh = result.get("reputation", {}).get("urlhaus", {})
    if uh.get("status") == "ok":
        score += 40
        details.append("URLhaus: URL listed as malicious (+40)")
    elif uh.get("status") == "is_host" and uh.get("threat"):
        score += 30
        details.append("URLhaus: known malware host (+30)")

    # Google Safe Browsing
    gsb = result.get("reputation", {}).get("google_safe_browsing", {})
    if not gsb.get("safe", True) and gsb.get("threats"):
        score += 35
        details.append(f"Google Safe Browsing: {', '.join(gsb['threats'])} (+35)")

    # PhishTank
    pt = result.get("reputation", {}).get("phishtank", {})
    if pt.get("verified"):
        score += 40
        details.append("PhishTank: verified phishing site (+40)")

    # SSL
    ssl_data = result.get("ssl", {})
    if ssl_data.get("valid") is False:
        score += 15
        details.append("Invalid SSL certificate (+15)")
    if ssl_data.get("expired"):
        score += 10
        details.append("Expired SSL certificate (+10)")

    # Typosquatting
    ts = result.get("typosquatting", {})
    if ts.get("is_typosquat"):
        brands = [s["brand"] for s in ts.get("similar_to", [])]
        score += 25
        details.append(f"Typosquatting of: {', '.join(brands)} (+25)")

    # New domain
    if result.get("domain_age_warning"):
        score += 10
        details.append("Domain registered less than 90 days ago (+10)")

    # Shortened URL
    if result.get("is_shortened"):
        score += 5
        details.append("URL is shortened (original hidden) (+5)")

    # Missing security headers
    headers = result.get("security_headers", {})
    missing = [h for h, v in headers.items() if v == "[MISSING]"]
    if len(missing) >= 4:
        score += 5
        details.append(f"{len(missing)} security headers missing (+5)")

    return min(score, 100), details


def _display_results(result: dict) -> None:
    console.print(f"\n[bold]URL:[/] [cyan]{result.get('original_url')}[/]")
    console.print(f"[bold]Domain:[/] [white]{result.get('domain')}[/]")

    # Redirect chain
    chain = result.get("redirect_chain", [])
    if len(chain) > 1:
        console.print(f"\n[bold yellow]Redirect Chain ({len(chain)} hops):[/]")
        for i, url in enumerate(chain):
            console.print(f"  [dim]{i+1}.[/] {url}")

    # WHOIS
    w = result.get("whois", {})
    if w and "error" not in w:
        whois_rows = [
            ("Registrar", w.get("registrar", "")),
            ("Creation Date", w.get("creation_date", "")),
            ("Expiration Date", w.get("expiration_date", "")),
            ("Country", w.get("registrant_country", "")),
            ("Name Servers", ", ".join(w.get("name_servers", [])[:3])),
        ]
        print_result_table("WHOIS Information", whois_rows)
        if result.get("domain_age_warning"):
            console.print("[bold red]⚠ WARNING: Domain registered less than 90 days ago![/]")

    # DNS
    dns_data = result.get("dns", {})
    if dns_data:
        dns_rows = [
            (rtype, "\n".join(vals[:3]) if isinstance(vals, list) else str(vals))
            for rtype, vals in dns_data.items()
            if rtype != "reverse_dns" and vals
        ]
        if dns_rows:
            print_result_table("DNS Records", dns_rows)

    # SSL
    ssl_data = result.get("ssl", {})
    if ssl_data and "error" not in ssl_data:
        color = "green" if ssl_data.get("valid") and not ssl_data.get("expired") else "red"
        ssl_rows = [
            ("Valid", f"[{color}]{'YES' if ssl_data.get('valid') else 'NO'}[/]"),
            ("Issuer", ssl_data.get("issuer", "")),
            ("Subject", ssl_data.get("subject", "")),
            ("Not Before", ssl_data.get("not_before", "")),
            ("Not After", ssl_data.get("not_after", "")),
            ("Days Remaining", str(ssl_data.get("days_remaining", ""))),
            ("SANs", str(ssl_data.get("san_count", 0))),
            ("TLS Version", ssl_data.get("version", "")),
        ]
        print_result_table("SSL Certificate", ssl_rows)
        if ssl_data.get("expiring_soon"):
            console.print("[bold yellow]⚠ Certificate expires within 30 days![/]")

    # Reputation
    rep = result.get("reputation", {})
    rep_rows = []
    vt = rep.get("virustotal", {})
    if "malicious" in vt:
        m, s = vt.get("malicious", 0), vt.get("suspicious", 0)
        color = "red" if m > 0 else ("yellow" if s > 0 else "green")
        rep_rows.append(("VirusTotal", f"[{color}]{m} malicious / {s} suspicious[/]"))

    gsb = rep.get("google_safe_browsing", {})
    if "safe" in gsb:
        color = "green" if gsb["safe"] else "red"
        rep_rows.append(("Google Safe Browsing", f"[{color}]{'SAFE' if gsb['safe'] else 'UNSAFE: ' + str(gsb.get('threats', []))}[/]"))

    uh = rep.get("urlhaus", {})
    if uh.get("status"):
        rep_rows.append(("URLhaus", uh.get("status", "")))

    pt = rep.get("phishtank", {})
    if pt.get("in_database") is not None:
        color = "red" if pt.get("verified") else "yellow"
        rep_rows.append(("PhishTank", f"[{color}]{'PHISHING (verified)' if pt.get('verified') else 'Not verified'}[/]"))

    if rep_rows:
        print_result_table("Reputation", rep_rows)

    # Technologies
    techs = result.get("technologies", {})
    if techs:
        tech_rows = [(k, str(v)) for k, v in techs.items()]
        print_result_table("Detected Technologies", tech_rows)

    # Security headers
    sec_headers = result.get("security_headers", {})
    if sec_headers:
        header_rows = [
            (h, f"[red]{v}[/]" if v == "[MISSING]" else f"[green]{v[:60]}[/]")
            for h, v in sec_headers.items()
        ]
        print_result_table("Security Headers", header_rows)

    # Typosquatting
    ts = result.get("typosquatting", {})
    if ts.get("is_typosquat"):
        console.print("\n[bold red]⚠ TYPOSQUATTING DETECTED![/]")
        for sim in ts.get("similar_to", []):
            console.print(f"  Similar to [bold]{sim['brand']}[/] (distance: {sim['distance']})")

    print_risk_score(result.get("risk_score", 0))
    if result.get("risk_details"):
        console.print("[bold]Risk Factors:[/]")
        for d in result.get("risk_details", []):
            console.print(f"  [yellow]•[/] {d}")


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def run():
    print_section("URL & Domain Analyzer", "🔗")
    url = console.input("\n[bold]Enter URL or domain to analyze:[/] ").strip()
    if not url:
        print_error("No URL provided")
        return

    result = analyze_url(url)
    if result:
        export = console.input("\n[bold]Export results? (json/txt/html/all/no):[/] ").strip().lower()
        if export and export != "no":
            formats = ["json", "txt", "html"] if export == "all" else [export]
            saved = save_results("url", result.get("domain", url), result, formats)
            for fmt, path in saved.items():
                console.print(f"[green]Saved {fmt.upper()}:[/] {path}")
