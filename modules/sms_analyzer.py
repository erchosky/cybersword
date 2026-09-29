"""
CyberSword - SMS & Message Analyzer
Phishing detection, URL extraction, urgency patterns, brand impersonation.
"""

import re
from urllib.parse import quote

from rich.console import Console
from rich.panel import Panel

from utils.helpers import contains_pattern, contains_term, extract_urls, is_url_shortener, log_analysis
from utils.output import (
    print_section, print_result_table, print_risk_score,
    print_error, save_results
)

console = Console()

PHISHING_KEYWORDS = {
    "urgent": 10, "urgente": 10, "immediately": 10, "act now": 10,
    "verify": 8, "verificar": 8, "confirm": 8, "confirmar": 8,
    "suspended": 12, "suspendida": 12, "blocked": 10, "bloqueada": 10,
    "click here": 8, "click the link": 8, "haz clic": 8,
    "free": 5, "gratis": 5, "prize": 10, "premio": 10, "winner": 10, "ganador": 10,
    "limited time": 8, "tiempo limitado": 8, "expires": 8, "expira": 8,
    "account": 4, "cuenta": 4, "password": 6, "contraseña": 6,
    "bank": 5, "banco": 5, "pin": 6, "otp": 8, "one-time": 8,
    "refund": 6, "reembolso": 6, "tax": 5, "hacienda": 8, "agencia tributaria": 12,
    "dhl": 8, "fedex": 8, "correos": 8, "entrega": 5,
    "amazon": 6, "paypal": 8, "visa": 6, "mastercard": 6,
    "microsoft": 5, "apple": 5, "google": 4,
    "police": 8, "policia": 8, "fbi": 10, "fraud": 8, "fraude": 8,
    "covid": 5, "vaccine": 5, "vacuna": 5,
}

URGENCY_PATTERNS = [
    (r"\d+\s*(hours?|horas?)\s*(left|quedan|remaining)", "Time pressure"),
    (r"expires?\s+in\s+\d+", "Expiration threat"),
    (r"expira\s+(en|hoy)", "Expiration threat"),
    (r"act\s+(now|immediately|fast)", "Immediate action"),
    (r"actúa?\s+(ahora|inmediatamente)", "Immediate action"),
    (r"last\s+(chance|warning|notice)", "Last warning"),
    (r"última\s+(oportunidad|advertencia|notificación)", "Last warning"),
    (r"account\s+will\s+be\s+(closed|deleted|suspended)", "Account threat"),
    (r"cuenta\s+(será|va\s+a ser)\s+(cerrada|eliminada|suspendida)", "Account threat"),
    (r"respond\s+within\s+\d+", "Response deadline"),
]

BRAND_PATTERNS = [
    (r"amazon", "Amazon"),
    (r"paypal", "PayPal"),
    (r"netflix", "Netflix"),
    (r"bank\s*of\s*america|bankofamerica", "Bank of America"),
    (r"bbva", "BBVA"),
    (r"santander", "Santander"),
    (r"ing\s+direc", "ING Direct"),
    (r"caixabank|la\s*caixa", "CaixaBank"),
    (r"hacienda|agencia\s+tributaria|aeat", "AEAT"),
    (r"correos", "Correos"),
    (r"dhl", "DHL"),
    (r"fedex", "FedEx"),
    (r"ups", "UPS"),
    (r"apple", "Apple"),
    (r"microsoft", "Microsoft"),
    (r"google", "Google"),
    (r"facebook|meta", "Meta"),
    (r"instagram", "Instagram"),
    (r"whatsapp", "WhatsApp"),
    (r"seguridad\s+social|sepe", "SEPE/SS"),
    (r"seguro\s+(medico|social|health)", "Insurance"),
]

def analyze_sms(message: str) -> dict:
    """Analyze SMS/message for phishing indicators."""
    print_section("SMS & Message Analyzer", "💬")

    if not message.strip():
        print_error("Empty message")
        return {}

    result = {
        "message": message,
        "length": len(message),
    }

    text_lower = message.lower()

    # Extract URLs
    urls = extract_urls(message)
    result["urls"] = []
    for url in urls:
        url_info = {
            "url": url,
            "is_shortened": is_url_shortener(_extract_domain(url)),
            "domain": _extract_domain(url),
        }
        result["urls"].append(url_info)

    # Phishing keywords
    found_keywords = []
    score = 0
    for kw, weight in PHISHING_KEYWORDS.items():
        if contains_term(text_lower, kw):
            found_keywords.append({"keyword": kw, "weight": weight})
            score += weight
    result["phishing_keywords"] = found_keywords
    result["keyword_score"] = min(score, 50)

    # Urgency patterns
    urgency = []
    for pattern, label in URGENCY_PATTERNS:
        if re.search(pattern, text_lower):
            urgency.append(label)
    result["urgency_patterns"] = urgency

    # Brand impersonation
    brands = []
    for pattern, name in BRAND_PATTERNS:
        if contains_pattern(text_lower, pattern):
            brands.append(name)
    result["impersonated_brands"] = brands

    # Suspicious characteristics
    characteristics = []
    if len(message) < 100:
        characteristics.append("Very short message (typical of smishing)")
    if urls and any(u["is_shortened"] for u in result["urls"]):
        characteristics.append("Contains shortened URL (hides destination)")
    if re.search(r"\+\d{10,}", message):
        characteristics.append("Contains international phone number")
    if re.search(r"(?i)(call|llama|llamar)\s+\+?\d{6,}", message):
        characteristics.append("Asks you to call a number")
    if re.search(r"(?i)(reply|responde)\s+(yes|si|no|stop|1|2)", message):
        characteristics.append("Asks for reply (data harvesting)")
    if re.search(r"don.t\s+(share|tell|give)", message, re.I):
        characteristics.append("Instructs not to share (social engineering)")
    if re.search(r"código|code|otp|one.time|verification", message, re.I):
        characteristics.append("Asks for OTP/verification code (credential theft)")

    result["characteristics"] = characteristics

    # Check sender number if present in message
    numbers = re.findall(r"\+?[\d\s\-().]{10,20}", message)
    result["numbers_found"] = [re.sub(r"[^\d+]", "", n) for n in numbers[:5]]

    # Google dork links for numbers
    result["dork_links"] = []
    for n in result["numbers_found"][:2]:
        if len(n) >= 7:
            result["dork_links"].append(
                f"https://www.google.com/search?q={quote(n)}+spam+OR+scam+OR+complaints"
            )

    result["risk_score"], result["risk_details"] = _calculate_risk(result)

    _display_results(result)
    log_analysis("sms", message[:50], result)

    return result


def _extract_domain(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return (urlparse(url).hostname or "").removeprefix("www.")
    except Exception:
        return ""


def _calculate_risk(result: dict) -> tuple[int, list]:
    score = 0
    details = []

    # Keywords
    kw_score = result.get("keyword_score", 0)
    if kw_score > 0:
        score += kw_score
        details.append(f"Phishing keywords detected (score: {kw_score}) (+{kw_score})")

    # Urgency
    urgency = result.get("urgency_patterns", [])
    if urgency:
        score += 15
        details.append(f"Urgency patterns: {', '.join(urgency[:3])} (+15)")

    # Brand impersonation
    brands = result.get("impersonated_brands", [])
    if brands:
        score += 20
        details.append(f"Brand impersonation: {', '.join(brands[:3])} (+20)")

    # URLs
    urls = result.get("urls", [])
    if urls:
        score += 5
        details.append(f"{len(urls)} URL(s) in message (+5)")
        shortened = [u for u in urls if u.get("is_shortened")]
        if shortened:
            score += 15
            details.append(f"{len(shortened)} shortened URL(s) — destination hidden (+15)")

    # Characteristics
    characteristics = result.get("characteristics", [])
    if characteristics:
        score += min(len(characteristics) * 5, 25)
        details.append(f"{len(characteristics)} suspicious characteristics (+{min(len(characteristics)*5,25)})")

    return min(score, 100), details


def _display_results(result: dict) -> None:
    console.print("\n[bold]Message:[/]")
    console.print(Panel(result.get("message", ""), border_style="dim"))
    console.print(f"[bold]Length:[/] {result.get('length')} characters")

    # URLs
    urls = result.get("urls", [])
    if urls:
        url_rows = [
            (u["url"][:70], u["domain"],
             "[red]YES[/]" if u.get("is_shortened") else "No")
            for u in urls
        ]
        print_result_table("URLs Found", url_rows, ["URL", "Domain", "Shortened?"])
    else:
        console.print("[dim]No URLs found[/]")

    # Brands
    brands = result.get("impersonated_brands", [])
    if brands:
        console.print(f"\n[bold red]⚠ Possible Brand Impersonation:[/] {', '.join(brands)}")

    # Urgency
    urgency = result.get("urgency_patterns", [])
    if urgency:
        console.print(f"[bold yellow]⚠ Urgency Patterns:[/] {', '.join(urgency)}")

    # Keywords
    keywords = result.get("phishing_keywords", [])
    if keywords:
        kw_rows = [(k["keyword"], str(k["weight"])) for k in keywords[:10]]
        print_result_table("Phishing Keywords", kw_rows, ["Keyword", "Risk Weight"])

    # Characteristics
    chars = result.get("characteristics", [])
    if chars:
        console.print("\n[bold]Suspicious Characteristics:[/]")
        for c in chars:
            console.print(f"  [yellow]•[/] {c}")

    # Numbers
    numbers = result.get("numbers_found", [])
    if numbers:
        console.print(f"\n[bold]Phone Numbers in Message:[/] {', '.join(numbers)}")

    # Dork links
    dorks = result.get("dork_links", [])
    if dorks:
        console.print("\n[bold]Search for spam reports:[/]")
        for link in dorks:
            console.print(f"  [blue]{link}[/]")

    print_risk_score(result.get("risk_score", 0))
    if result.get("risk_details"):
        console.print("[bold]Risk Factors:[/]")
        for d in result.get("risk_details", []):
            console.print(f"  [yellow]•[/] {d}")


def run():
    print_section("SMS & Message Analyzer", "💬")
    console.print("[dim]Paste the SMS/message text (end with '---END---'):[/]")
    lines = []
    while True:
        line = input()
        if line == "---END---":
            break
        lines.append(line)

    message = "\n".join(lines).strip()
    if not message:
        print_error("No message provided")
        return

    result = analyze_sms(message)
    if result:
        export = console.input("\n[bold]Export results? (json/txt/html/all/no):[/] ").strip().lower()
        if export and export != "no":
            formats = ["json", "txt", "html"] if export == "all" else [export]
            saved = save_results("sms", "message", result, formats)
            for fmt, path in saved.items():
                console.print(f"[green]Saved {fmt.upper()}:[/] {path}")
