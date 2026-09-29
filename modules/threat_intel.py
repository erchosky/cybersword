"""
CyberSword - Threat Intelligence
Multi-source IOC lookup: OTX, MalwareBazaar, VT, AbuseIPDB, URLhaus.
"""

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from utils.helpers import (
    is_valid_ip, is_valid_email, is_valid_hash,
    is_valid_domain, log_analysis
)
from utils.output import (
    print_section, print_warning, save_results
)
from utils.api_manager import (
    otx_indicator, vt_ip_report, vt_domain_report,
    vt_file_report, abuseipdb_check, urlhaus_check, urlhaus_host,
    malwarebazaar_hash, ipinfo_lookup, ipqs_ip,
    vt_url_report
)

console = Console()


def lookup_ioc(ioc: str) -> dict:
    """Auto-detect IOC type and query all relevant sources."""
    print_section("Threat Intelligence", "🔎")
    console.print(f"\n[bold]IOC:[/] [cyan]{ioc}[/]")

    ioc = ioc.strip()
    result = {"ioc": ioc, "sources": {}, "summary": {}}

    # Determine IOC type
    ioc_type = _classify_ioc(ioc)
    result["type"] = ioc_type
    console.print(f"[bold]Type:[/] [yellow]{ioc_type}[/]")

    if ioc_type == "Unknown":
        print_warning("Cannot determine IOC type. Trying as domain...")
        ioc_type = "domain"

    # Query sources concurrently
    tasks = _build_tasks(ioc, ioc_type)
    console.print(f"[dim]Querying {len(tasks)} threat intelligence sources...[/]")

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(task["fn"], *task.get("args", []), **task.get("kwargs", {})): task["name"]
            for task in tasks
        }
        for future in as_completed(futures):
            source_name = futures[future]
            with console.status(f"[dim]Waiting for {source_name}...[/]"):
                try:
                    data = future.result(timeout=30)
                    if data:
                        result["sources"][source_name] = data
                except Exception as e:
                    result["sources"][source_name] = {"error": str(e)}

    result["summary"] = _build_summary(result["sources"], ioc_type)
    result["verdict"], result["verdict_color"] = _determine_verdict(result["summary"])
    result["timestamp"] = datetime.now().isoformat()

    _display_results(result)
    log_analysis("threat_intel", ioc, result)

    return result


def bulk_lookup(iocs: list) -> list:
    """Lookup multiple IOCs."""
    print_section("Bulk IOC Lookup", "🔎")
    console.print(f"[bold]Looking up {len(iocs)} IOCs...[/]\n")
    results = []
    for ioc in iocs:
        console.print(f"\n[bold cyan]─── {ioc} ───[/]")
        result = lookup_ioc(ioc)
        results.append(result)
    return results


def _classify_ioc(ioc: str) -> str:
    if is_valid_ip(ioc):
        return "ip"
    if is_valid_email(ioc):
        return "email"
    hash_type = is_valid_hash(ioc)
    if hash_type:
        return f"hash:{hash_type}"
    if is_valid_domain(ioc):
        return "domain"
    if ioc.startswith(("http://", "https://")):
        return "url"
    return "Unknown"


def _build_tasks(ioc: str, ioc_type: str) -> list:
    tasks = []

    if ioc_type == "ip":
        tasks = [
            {"name": "VirusTotal", "fn": vt_ip_report, "args": [ioc]},
            {"name": "AbuseIPDB", "fn": abuseipdb_check, "args": [ioc]},
            {"name": "AlienVault OTX", "fn": _otx_ip, "args": [ioc]},
            {"name": "IPQualityScore", "fn": ipqs_ip, "args": [ioc]},
            {"name": "ipinfo.io", "fn": ipinfo_lookup, "args": [ioc]},
        ]
    elif ioc_type == "domain":
        tasks = [
            {"name": "VirusTotal", "fn": vt_domain_report, "args": [ioc]},
            {"name": "AlienVault OTX", "fn": _otx_domain, "args": [ioc]},
            {"name": "URLhaus", "fn": urlhaus_host, "args": [ioc]},
        ]
    elif ioc_type == "url":
        tasks = [
            {"name": "VirusTotal", "fn": vt_url_report, "args": [ioc]},
            {"name": "URLhaus", "fn": urlhaus_check, "args": [ioc]},
            {"name": "AlienVault OTX", "fn": _otx_url, "args": [ioc]},
        ]
    elif ioc_type.startswith("hash:"):
        tasks = [
            {"name": "VirusTotal", "fn": vt_file_report, "args": [ioc]},
            {"name": "MalwareBazaar", "fn": malwarebazaar_hash, "args": [ioc]},
            {"name": "AlienVault OTX", "fn": _otx_hash, "args": [ioc]},
        ]
    elif ioc_type == "email":
        tasks = [
            {"name": "AlienVault OTX", "fn": _otx_email, "args": [ioc]},
        ]

    return tasks


def _otx_ip(ip: str) -> Optional[dict]:
    indicator_type = "IPv6" if ":" in ip else "IPv4"
    general = otx_indicator(indicator_type, ip, "general")
    reputation = otx_indicator(indicator_type, ip, "reputation")
    malware = otx_indicator(indicator_type, ip, "malware")

    return {
        "pulse_count": general.get("pulse_info", {}).get("count", 0) if general else 0,
        "reputation": reputation.get("reputation", {}) if reputation else {},
        "malware_samples": malware.get("data", [])[:3] if malware else [],
        "country": (general or {}).get("country_name", ""),
        "asn": (general or {}).get("asn", ""),
    }


def _otx_domain(domain: str) -> Optional[dict]:
    general = otx_indicator("domain", domain, "general")
    malware = otx_indicator("domain", domain, "malware")

    return {
        "pulse_count": general.get("pulse_info", {}).get("count", 0) if general else 0,
        "malware_samples": malware.get("data", [])[:3] if malware else [],
        "validation": (general or {}).get("validation", []),
    }


def _otx_url(url: str) -> Optional[dict]:
    from urllib.parse import quote
    general = otx_indicator("url", quote(url, safe=""), "general")
    return {
        "pulse_count": general.get("pulse_info", {}).get("count", 0) if general else 0,
        "validation": (general or {}).get("validation", []),
    }


def _otx_hash(file_hash: str) -> Optional[dict]:
    hash_type_map = {32: "FileHash-MD5", 40: "FileHash-SHA1", 64: "FileHash-SHA256"}
    hash_type = hash_type_map.get(len(file_hash), "FileHash-SHA256")
    general = otx_indicator(hash_type, file_hash, "general")
    analysis = otx_indicator(hash_type, file_hash, "analysis")

    return {
        "pulse_count": general.get("pulse_info", {}).get("count", 0) if general else 0,
        "malware_family": (analysis or {}).get("malware", {}).get("family", ""),
        "file_class": (analysis or {}).get("analysis", {}).get("info", {}).get("results", {}).get("file_class", ""),
    }


def _otx_email(email: str) -> Optional[dict]:
    general = otx_indicator("email", email, "general")
    return {
        "pulse_count": general.get("pulse_info", {}).get("count", 0) if general else 0,
        "validation": (general or {}).get("validation", []),
    }


def _build_summary(sources: dict, ioc_type: str) -> dict:
    summary = {
        "malicious_count": 0,
        "suspicious_count": 0,
        "pulse_count": 0,
        "detection_ratio": "",
        "tags": [],
        "malware_family": "",
        "asn": "",
        "country": "",
        "abuse_score": 0,
        "fraud_score": 0,
        "is_tor": False,
        "is_vpn": False,
        "in_malwarebazaar": False,
    }

    # VirusTotal
    vt = sources.get("VirusTotal", {})
    if vt and "data" in vt:
        attrs = vt["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        m = stats.get("malicious", 0)
        s = stats.get("suspicious", 0)
        total = sum(stats.values())
        summary["malicious_count"] = m
        summary["suspicious_count"] = s
        if total > 0:
            summary["detection_ratio"] = f"{m+s}/{total}"
        tags = attrs.get("tags", [])
        summary["tags"].extend(tags)
        threat_label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "")
        if threat_label:
            summary["malware_family"] = threat_label

    # AbuseIPDB
    abuse = sources.get("AbuseIPDB", {})
    if abuse and "data" in abuse:
        summary["abuse_score"] = abuse["data"].get("abuseConfidenceScore", 0)

    # OTX
    otx_data = sources.get("AlienVault OTX", {})
    if otx_data:
        summary["pulse_count"] = otx_data.get("pulse_count", 0)
        if not summary["malware_family"] and otx_data.get("malware_family"):
            summary["malware_family"] = otx_data["malware_family"]

    # IPQualityScore
    ipqs = sources.get("IPQualityScore", {})
    if ipqs:
        summary["fraud_score"] = ipqs.get("fraud_score", 0)
        summary["is_tor"] = ipqs.get("tor", False)
        summary["is_vpn"] = ipqs.get("vpn", False)

    # MalwareBazaar
    mb = sources.get("MalwareBazaar", {})
    if mb and mb.get("query_status") == "ok":
        summary["in_malwarebazaar"] = True
        data = mb.get("data", [{}])[0]
        if data.get("signature"):
            summary["malware_family"] = data["signature"]
        summary["tags"].extend(data.get("tags", []) or [])

    # ipinfo.io
    ipinfo = sources.get("ipinfo.io", {})
    if ipinfo:
        summary["asn"] = ipinfo.get("org", "")
        summary["country"] = ipinfo.get("country", "")

    return summary


def _determine_verdict(summary: dict) -> tuple[str, str]:
    m = summary.get("malicious_count", 0)
    s = summary.get("suspicious_count", 0)
    abuse = summary.get("abuse_score", 0)
    fraud = summary.get("fraud_score", 0)
    in_mb = summary.get("in_malwarebazaar", False)
    pulses = summary.get("pulse_count", 0)
    is_tor = summary.get("is_tor", False)

    if in_mb or m >= 5:
        return "MALICIOUS", "red"
    elif m > 0 or abuse >= 75 or fraud >= 75:
        return "LIKELY MALICIOUS", "red"
    elif s > 0 or abuse >= 30 or fraud >= 50 or pulses >= 3 or is_tor:
        return "SUSPICIOUS", "yellow"
    elif pulses > 0 or abuse >= 10:
        return "LOW RISK", "yellow"
    else:
        return "CLEAN / UNKNOWN", "green"


def _display_results(result: dict) -> None:
    ioc = result.get("ioc", "")
    ioc_type = result.get("type", "")
    verdict = result.get("verdict", "")
    verdict_color = result.get("verdict_color", "white")
    summary = result.get("summary", {})

    console.print(Panel(
        f"[bold]{ioc}[/]\n"
        f"Type: [cyan]{ioc_type}[/]\n"
        f"Verdict: [{verdict_color}][bold]{verdict}[/][/]\n"
        f"Detection: [yellow]{summary.get('detection_ratio', 'N/A')}[/] | "
        f"Pulses: {summary.get('pulse_count', 0)} | "
        f"AbuseScore: {summary.get('abuse_score', 0)}%",
        title="[bold]Threat Intelligence Summary[/]",
        border_style=verdict_color,
    ))

    if summary.get("malware_family"):
        console.print(f"[bold red]Malware Family:[/] {summary['malware_family']}")
    if summary.get("tags"):
        console.print(f"[bold]Tags:[/] {', '.join(set(summary['tags']))}")
    if summary.get("is_tor"):
        console.print("[bold red]⚠ Tor Exit Node[/]")
    if summary.get("is_vpn"):
        console.print("[bold yellow]⚠ VPN[/]")
    if summary.get("in_malwarebazaar"):
        console.print("[bold red]⚠ FOUND IN MALWAREBAZAAR[/]")

    # Source details
    console.print("\n[bold]Source Details:[/]")
    sources = result.get("sources", {})

    # VirusTotal
    vt = sources.get("VirusTotal", {})
    if vt and "data" in vt:
        attrs = vt["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        m = stats.get("malicious", 0)
        s = stats.get("suspicious", 0)
        color = "red" if m > 0 else ("yellow" if s > 0 else "green")
        console.print(f"  [bold]VirusTotal:[/] [{color}]{m} malicious / {s} suspicious[/] "
                     f"(harmless: {stats.get('harmless',0)}, undetected: {stats.get('undetected',0)})")
        if attrs.get("popular_threat_classification", {}).get("suggested_threat_label"):
            console.print(f"    Threat: {attrs['popular_threat_classification']['suggested_threat_label']}")

    # AbuseIPDB
    abuse = sources.get("AbuseIPDB", {})
    if abuse and "data" in abuse:
        score = abuse["data"].get("abuseConfidenceScore", 0)
        color = "red" if score >= 50 else ("yellow" if score >= 20 else "green")
        console.print(f"  [bold]AbuseIPDB:[/] [{color}]{score}%[/] confidence "
                     f"({abuse['data'].get('totalReports', 0)} reports)")

    # OTX
    otx = sources.get("AlienVault OTX", {})
    if otx:
        pulses = otx.get("pulse_count", 0)
        color = "red" if pulses >= 5 else ("yellow" if pulses > 0 else "green")
        console.print(f"  [bold]AlienVault OTX:[/] [{color}]{pulses} pulses[/]")

    # IPQualityScore
    ipqs = sources.get("IPQualityScore", {})
    if ipqs and "fraud_score" in ipqs:
        fs = ipqs.get("fraud_score", 0)
        color = "red" if fs >= 75 else ("yellow" if fs >= 50 else "green")
        flags = []
        if ipqs.get("tor"):
            flags.append("[red]TOR[/]")
        if ipqs.get("vpn"):
            flags.append("[yellow]VPN[/]")
        if ipqs.get("proxy"):
            flags.append("[yellow]PROXY[/]")
        console.print(f"  [bold]IPQualityScore:[/] [{color}]{fs}[/]"
                     + (f" | {' '.join(flags)}" if flags else ""))

    # URLhaus
    uh = sources.get("URLhaus", {})
    if uh:
        status = uh.get("query_status", "")
        color = "red" if status in ("is_host", "ok") else "green"
        console.print(f"  [bold]URLhaus:[/] [{color}]{status}[/]")

    # MalwareBazaar
    mb = sources.get("MalwareBazaar", {})
    if mb:
        status = mb.get("query_status", "")
        if status == "ok":
            data = mb.get("data", [{}])[0]
            console.print(f"  [bold red]MalwareBazaar:[/] FOUND — {data.get('signature', '')} "
                         f"({data.get('file_type', '')})")
        else:
            console.print("  [bold]MalwareBazaar:[/] [green]Not found[/]")

    # ipinfo.io
    ipinfo = sources.get("ipinfo.io", {})
    if ipinfo:
        console.print(f"  [bold]ipinfo.io:[/] {ipinfo.get('country', '')} | "
                     f"{ipinfo.get('city', '')} | {ipinfo.get('org', '')}")

    # Errors
    for source, data in sources.items():
        if isinstance(data, dict) and "error" in data:
            console.print(f"  [dim]{source}: {data['error']}[/]")


def run():
    print_section("Threat Intelligence", "🔎")
    console.print("\nOptions:")
    console.print("1. Single IOC lookup (IP, domain, URL, hash, email)")
    console.print("2. Bulk IOC lookup (one per line)")

    choice = console.input("\n[bold]>[/] ").strip()

    if choice == "1":
        ioc = console.input("[bold]IOC to lookup:[/] ").strip()
        if ioc:
            result = lookup_ioc(ioc)
            if result:
                export = console.input("\n[bold]Export? (json/html/all/no):[/] ").strip().lower()
                if export and export != "no":
                    formats = ["json", "txt", "html"] if export == "all" else [export]
                    saved = save_results("threat_intel", ioc, result, formats)
                    for fmt, p in saved.items():
                        console.print(f"[green]Saved {fmt.upper()}:[/] {p}")

    elif choice == "2":
        console.print("[dim]Enter IOCs (one per line), empty line to start:[/]")
        iocs = []
        while True:
            line = input().strip()
            if not line:
                break
            iocs.append(line)

        if iocs:
            results = bulk_lookup(iocs)
            # Summary table
            t = Table(title="Bulk Lookup Summary", box=box.ROUNDED)
            t.add_column("IOC")
            t.add_column("Type")
            t.add_column("Verdict")
            t.add_column("VT")
            t.add_column("Abuse%")
            for r in results:
                verdict = r.get("verdict", "")
                color = r.get("verdict_color", "white")
                summary = r.get("summary", {})
                t.add_row(
                    r.get("ioc", "")[:40],
                    r.get("type", ""),
                    f"[{color}]{verdict}[/]",
                    summary.get("detection_ratio", ""),
                    str(summary.get("abuse_score", "")),
                )
            console.print(t)
    else:
        from utils.output import print_error
        print_error("Invalid option")
