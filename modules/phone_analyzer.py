"""
CyberSword - Phone Number Analyzer
Format validation, carrier, country, VoIP detection, spam lookup.
"""

import re

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone
    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False

from rich.console import Console

from urllib.parse import quote_plus

from utils.helpers import get_api_key, log_analysis, safe_get
from utils.output import (
    print_section, print_result_table, print_risk_score,
    print_error, print_warning, save_results
)
from utils.api_manager import ipqs_phone

console = Console()

VOIP_PROVIDERS = [
    "twilio", "vonage", "google voice", "skype", "magicjack",
    "ringcentral", "grasshopper", "ooma", "8x8", "bandwidth",
    "telnyx", "signalwire", "plivo", "textmagic",
]

KNOWN_SPAM_PATTERNS = [
    r"^(\+1|1)?900",
    r"^(\+1|1)?976",
]


def analyze_phone(phone_number: str) -> dict:
    """Full phone number analysis."""
    print_section("Phone Number Analyzer", "📱")

    raw = phone_number.strip()
    console.print(f"\n[bold]Analyzing:[/] [cyan]{raw}[/]")

    result = {"input": raw}

    if not PHONENUMBERS_AVAILABLE:
        print_warning("phonenumbers library not available. Install it for full analysis.")
        result["error"] = "phonenumbers not available"
        return result

    # Parse
    parsed = _parse_number(raw)
    if not parsed:
        print_error(f"Cannot parse phone number: {raw}")
        result["valid"] = False
        return result

    result["valid"] = phonenumbers.is_valid_number(parsed)
    result["possible"] = phonenumbers.is_possible_number(parsed)
    result["international"] = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
    )
    result["national"] = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.NATIONAL
    )
    result["e164"] = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.E164
    )
    result["country_code"] = parsed.country_code
    result["national_number"] = str(parsed.national_number)

    # Geocoding
    result["country"] = geocoder.description_for_number(parsed, "en")
    result["region"] = geocoder.description_for_number(parsed, "es")

    # Carrier
    result["carrier"] = carrier.name_for_number(parsed, "en")

    # Timezone
    result["timezones"] = list(timezone.time_zones_for_number(parsed))

    # Number type
    num_type = phonenumbers.number_type(parsed)
    result["type"] = _type_to_string(num_type)
    result["is_mobile"] = num_type == phonenumbers.PhoneNumberType.MOBILE
    result["is_voip"] = num_type == phonenumbers.PhoneNumberType.VOIP
    result["is_fixed_line"] = num_type == phonenumbers.PhoneNumberType.FIXED_LINE
    result["is_toll_free"] = num_type == phonenumbers.PhoneNumberType.TOLL_FREE
    result["is_premium_rate"] = num_type == phonenumbers.PhoneNumberType.PREMIUM_RATE

    # VoIP detection
    carrier_lower = result.get("carrier", "").lower()
    result["carrier_is_voip"] = any(vp in carrier_lower for vp in VOIP_PROVIDERS)
    if not result["is_voip"] and result["carrier_is_voip"]:
        result["is_voip"] = True

    # Spam pattern check
    result["matches_spam_pattern"] = any(
        re.match(pat, result.get("e164", "")) for pat in KNOWN_SPAM_PATTERNS
    )

    # IPQualityScore
    with console.status("[bold green]Checking reputation..."):
        result["reputation"] = _check_reputation(result.get("e164", raw))

    # Google dork links
    result["search_links"] = _generate_dork_links(result.get("international", raw))

    result["risk_score"], result["risk_details"] = _calculate_risk(result)

    _display_results(result)
    log_analysis("phone", raw, result)

    return result


def _parse_number(number: str):
    if not PHONENUMBERS_AVAILABLE:
        return None
    # Try with different assumptions
    attempts = [
        (number, None),
        (number, "US"),
        (number, "ES"),
        (number, "MX"),
        ("+" + number.lstrip("+"), None),
    ]
    for num, region in attempts:
        try:
            parsed = phonenumbers.parse(num, region)
            if phonenumbers.is_possible_number(parsed):
                return parsed
        except Exception:
            continue
    return None


def _check_reputation(phone: str) -> dict:
    rep = {}

    # IPQualityScore
    ipqs = ipqs_phone(phone)
    if ipqs and "error" not in ipqs:
        rep["ipqualityscore"] = {
            "valid": ipqs.get("valid", False),
            "fraud_score": ipqs.get("fraud_score", 0),
            "recent_abuse": ipqs.get("recent_abuse", False),
            "SPAMMER": ipqs.get("SPAMMER", False),
            "risky": ipqs.get("risky", False),
            "line_type": ipqs.get("line_type", ""),
            "carrier": ipqs.get("carrier", ""),
            "country": ipqs.get("country", ""),
            "city": ipqs.get("city", ""),
            "timezone": ipqs.get("timezone", ""),
            "active": ipqs.get("active", False),
            "leaked": ipqs.get("leaked", False),
            "prepaid": ipqs.get("prepaid", False),
            "do_not_call": ipqs.get("do_not_call", False),
        }
    elif ipqs and "error" in ipqs:
        rep["ipqualityscore"] = {"info": ipqs["error"]}

    # NumVerify: solo con clave y siempre por HTTPS (nunca enviar el número en claro).
    numverify_key = get_api_key("numverify")
    if not numverify_key:
        return rep
    try:
        resp = safe_get(
            "https://apilayer.net/api/validate",
            params={"access_key": numverify_key, "number": phone, "format": 1},
            timeout=10,
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get("error"):
                rep["numverify"] = {"info": data["error"].get("info", "NumVerify error")}
            elif data.get("valid"):
                rep["numverify"] = {
                    "carrier": data.get("carrier", ""),
                    "line_type": data.get("line_type", ""),
                    "country": data.get("country_name", ""),
                    "location": data.get("location", ""),
                }
    except Exception:
        pass

    return rep


def _generate_dork_links(phone: str) -> dict:
    clean = re.sub(r"[^\d+]", "", phone)
    variants = [clean, phone, phone.replace("+", "").replace(" ", "")]
    query = " OR ".join(f'"{v}"' for v in set(variants))
    return {
        "google": f"https://www.google.com/search?q={quote_plus(query)}",
        "google_truecaller": f"https://www.google.com/search?q={quote_plus('site:truecaller.com ' + clean)}",
        "google_complaints": f"https://www.google.com/search?q={quote_plus(clean + ' spam complaints')}",
        "numspy": f"https://numspy.org/lookup/{clean}",
    }


def _calculate_risk(result: dict) -> tuple[int, list]:
    score = 0
    details = []

    if not result.get("valid"):
        return 0, ["Invalid number — cannot assess risk"]

    if result.get("is_premium_rate"):
        score += 40
        details.append("Premium rate number (+40)")

    if result.get("matches_spam_pattern"):
        score += 30
        details.append("Matches known spam number pattern (+30)")

    if result.get("is_voip") or result.get("carrier_is_voip"):
        score += 15
        details.append("VoIP number — harder to trace (+15)")

    rep = result.get("reputation", {})
    ipqs = rep.get("ipqualityscore", {})
    fraud = ipqs.get("fraud_score", 0)
    if fraud >= 75:
        score += 30
        details.append(f"IPQualityScore fraud: {fraud} (+30)")
    elif fraud >= 50:
        score += 15
        details.append(f"IPQualityScore fraud: {fraud} (+15)")

    if ipqs.get("SPAMMER"):
        score += 25
        details.append("Flagged as SPAMMER by IPQualityScore (+25)")

    if ipqs.get("recent_abuse"):
        score += 15
        details.append("Recent abuse reported (+15)")

    if ipqs.get("leaked"):
        score += 10
        details.append("Number found in data breach (+10)")

    if ipqs.get("do_not_call"):
        score += 5
        details.append("Number on Do Not Call list (+5)")

    return min(score, 100), details


def _type_to_string(num_type) -> str:
    if not PHONENUMBERS_AVAILABLE:
        return "unknown"
    mapping = {
        phonenumbers.PhoneNumberType.MOBILE: "Mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
        phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
        phonenumbers.PhoneNumberType.VOIP: "VoIP",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal",
        phonenumbers.PhoneNumberType.PAGER: "Pager",
        phonenumbers.PhoneNumberType.UAN: "UAN",
        phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
    }
    return mapping.get(num_type, "Unknown")


def _display_results(result: dict) -> None:
    console.print(f"\n[bold]Number:[/] [cyan]{result.get('international', result.get('input'))}[/]")

    valid_color = "green" if result.get("valid") else "red"
    basic_rows = [
        ("Valid", f"[{valid_color}]{'YES' if result.get('valid') else 'NO'}[/]"),
        ("Format (E.164)", result.get("e164", "")),
        ("Format (Intl)", result.get("international", "")),
        ("Format (National)", result.get("national", "")),
        ("Country Code", str(result.get("country_code", ""))),
        ("Country", result.get("country", "")),
        ("Region", result.get("region", "")),
        ("Carrier/Operator", result.get("carrier", "")),
        ("Number Type", result.get("type", "")),
        ("Is Mobile", "[green]Yes[/]" if result.get("is_mobile") else "No"),
        ("Is VoIP", "[yellow]Yes[/]" if result.get("is_voip") else "No"),
        ("Is Toll-Free", "[blue]Yes[/]" if result.get("is_toll_free") else "No"),
        ("Is Premium Rate", "[red]Yes[/]" if result.get("is_premium_rate") else "No"),
        ("Timezones", ", ".join(result.get("timezones", []))),
    ]
    print_result_table("Phone Number Information", basic_rows)

    if result.get("carrier_is_voip") or result.get("is_voip"):
        console.print("[bold yellow]⚠ VoIP number detected — may be anonymous/disposable[/]")

    if result.get("matches_spam_pattern"):
        console.print("[bold red]⚠ Matches known spam/premium rate number pattern![/]")

    # Reputation
    rep = result.get("reputation", {})
    ipqs = rep.get("ipqualityscore", {})
    if ipqs and "fraud_score" in ipqs:
        fraud = ipqs.get("fraud_score", 0)
        color = "red" if fraud >= 75 else ("yellow" if fraud >= 40 else "green")
        ipqs_rows = [
            ("Fraud Score", f"[{color}]{fraud}[/]"),
            ("Spammer", "[red]YES[/]" if ipqs.get("SPAMMER") else "No"),
            ("Recent Abuse", "[red]YES[/]" if ipqs.get("recent_abuse") else "No"),
            ("Leaked", "[yellow]YES[/]" if ipqs.get("leaked") else "No"),
            ("Prepaid", "[yellow]Yes[/]" if ipqs.get("prepaid") else "No"),
            ("Do Not Call", "[yellow]Yes[/]" if ipqs.get("do_not_call") else "No"),
            ("Line Type", ipqs.get("line_type", "")),
            ("Active", "Yes" if ipqs.get("active") else "No"),
        ]
        print_result_table("IPQualityScore Reputation", ipqs_rows)
    elif ipqs and "info" in ipqs:
        print_warning(f"IPQualityScore: {ipqs['info']}")

    # Search links
    links = result.get("search_links", {})
    if links:
        console.print("\n[bold]Search Links:[/]")
        for name, link in links.items():
            console.print(f"  [blue]{name}:[/] {link}")

    print_risk_score(result.get("risk_score", 0))
    if result.get("risk_details"):
        console.print("[bold]Risk Factors:[/]")
        for d in result.get("risk_details", []):
            console.print(f"  [yellow]•[/] {d}")


def run():
    print_section("Phone Number Analyzer", "📱")
    phone = console.input("\n[bold]Enter phone number (with country code, e.g. +34612345678):[/] ").strip()
    if not phone:
        print_error("No phone number provided")
        return

    result = analyze_phone(phone)
    if result:
        export = console.input("\n[bold]Export results? (json/txt/html/all/no):[/] ").strip().lower()
        if export and export != "no":
            formats = ["json", "txt", "html"] if export == "all" else [export]
            saved = save_results("phone", phone, result, formats)
            for fmt, path in saved.items():
                console.print(f"[green]Saved {fmt.upper()}:[/] {path}")
