"""
CyberSword - IP & Network Analyzer
Geolocation, reputation, Shodan, Tor/VPN detection, port scan, traceroute.
"""

import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

from utils.helpers import (
    is_valid_ip, is_private_ip, load_config, log_analysis,
    safe_get
)
from utils.output import (
    print_section, print_result_table, print_risk_score,
    print_error, print_warning, print_info, save_results, confirm_authorized
)
from utils.api_manager import (
    ipinfo_lookup, abuseipdb_check, shodan_host, vt_ip_report, ipqs_ip
)

console = Console()

# Top 1000 ports (abbreviated to top 100 for speed)
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 631, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049,
    2082, 2083, 2086, 2087, 2095, 2096, 3306, 3389, 4444, 5432,
    5900, 5901, 6379, 6881, 6969, 7001, 8000, 8008, 8080, 8443,
    8888, 9000, 9090, 9200, 9300, 9418, 10000, 27017, 27018,
    28017, 50000, 50070, 50075, 50470,
]

TOP_1000_PORTS = list(range(1, 1024)) + [
    1025, 1028, 1029, 1110, 1243, 1433, 1521, 1720, 1723, 1900,
    2000, 2001, 2049, 2082, 2083, 2100, 2121, 2222, 2433, 2869,
    3000, 3128, 3268, 3306, 3389, 4000, 4444, 4899, 5000, 5432,
    5800, 5900, 6000, 6112, 6346, 6379, 6667, 7000, 7070, 7777,
    8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9200,
    9300, 9418, 10000, 27017, 27018, 28017, 49152,
]

SERVICE_BANNERS = {
    21: b"",
    22: b"",
    25: b"EHLO cybersword\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"",
    143: b"",
    443: b"",
    3306: b"",
    3389: b"",
    5432: b"",
    6379: b"PING\r\n",
    27017: b"\x3b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
             b"\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00"
             b"\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61"
             b"\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00",
}

TOR_EXIT_NODES_URL = "https://check.torproject.org/torbulkexitlist"
TOR_CHECK_URL = "https://check.torproject.org/api/ip"


def analyze_ip(ip: str, scan_ports: bool = False) -> dict:
    """Análisis de una IP. Es pasivo salvo `scan_ports=True`, que conecta con los puertos del objetivo."""
    print_section("IP & Network Analyzer", "🌐")

    ip = ip.strip()
    if not is_valid_ip(ip):
        print_error(f"Invalid IP address: {ip}")
        return {}

    if is_private_ip(ip):
        print_warning(f"{ip} is a private/reserved IP address. External lookups will be limited.")

    console.print(f"\n[bold]Analyzing IP:[/] [cyan]{ip}[/]")
    result = {"ip": ip, "is_private": is_private_ip(ip)}

    if not result["is_private"]:
        with console.status("[bold green]Geolocation..."):
            result["geolocation"] = _geolocate(ip)

        with console.status("[bold green]Reputation checks..."):
            result["reputation"] = _check_reputation(ip)

        with console.status("[bold green]Checking Tor/VPN/proxy status..."):
            result["threat_info"] = _check_threat_info(ip)

    with console.status("[bold green]Reverse DNS..."):
        result["reverse_dns"] = _reverse_dns(ip)

    if scan_ports:
        cfg = load_config()
        top_n = cfg.get("settings", {}).get("port_scan_top", 100)
        ports_to_scan = TOP_100_PORTS if top_n <= 100 else TOP_1000_PORTS

        console.print(f"\n[bold]Port Scan:[/] scanning {len(ports_to_scan)} common ports...")
        result["open_ports"] = _port_scan(ip, ports_to_scan)

        if result["open_ports"]:
            with console.status("[bold green]Banner grabbing..."):
                result["banners"] = _grab_banners(ip, [p["port"] for p in result["open_ports"][:10]])
    else:
        result["port_scan"] = "not performed (passive analysis)"

    result["risk_score"], result["risk_details"] = _calculate_risk(result)

    _display_results(result)
    log_analysis("ip", ip, result)

    return result


def _geolocate(ip: str) -> dict:
    geo = {}

    # ipinfo.io
    data = ipinfo_lookup(ip)
    if data:
        loc = data.get("loc", ",").split(",")
        geo["country"] = data.get("country", "")
        geo["country_name"] = data.get("country_name", data.get("country", ""))
        geo["region"] = data.get("region", "")
        geo["city"] = data.get("city", "")
        geo["postal"] = data.get("postal", "")
        geo["org"] = data.get("org", "")
        geo["timezone"] = data.get("timezone", "")
        geo["latitude"] = loc[0] if len(loc) == 2 else ""
        geo["longitude"] = loc[1] if len(loc) == 2 else ""

    # ASN from ipinfo
    asn_raw = geo.get("org", "")
    if asn_raw:
        parts = asn_raw.split(" ", 1)
        geo["asn"] = parts[0]
        geo["asn_name"] = parts[1] if len(parts) > 1 else ""

    return geo


def _check_reputation(ip: str) -> dict:
    rep = {}

    # AbuseIPDB
    print_info("Querying AbuseIPDB...")
    abuse = abuseipdb_check(ip)
    if abuse and "error" not in abuse:
        data = abuse.get("data", {})
        rep["abuseipdb"] = {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", ""),
            "isp": data.get("isp", ""),
            "usage_type": data.get("usageType", ""),
            "domain": data.get("domain", ""),
            "is_whitelisted": data.get("isWhitelisted", False),
            "country_code": data.get("countryCode", ""),
        }
    elif abuse and "error" in abuse:
        rep["abuseipdb"] = {"info": abuse["error"]}

    # VirusTotal
    print_info("Querying VirusTotal...")
    vt = vt_ip_report(ip)
    if vt and "error" not in vt:
        attrs = vt.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        rep["virustotal"] = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": attrs.get("reputation", 0),
            "asn": attrs.get("asn", ""),
            "network": attrs.get("network", ""),
        }
    elif vt and "error" in vt:
        rep["virustotal"] = {"info": vt["error"]}

    # Shodan
    print_info("Querying Shodan...")
    sh = shodan_host(ip)
    if sh and "error" not in sh:
        rep["shodan"] = {
            "org": sh.get("org", ""),
            "isp": sh.get("isp", ""),
            "asn": sh.get("asn", ""),
            "open_ports": sh.get("ports", []),
            "hostnames": sh.get("hostnames", []),
            "tags": sh.get("tags", []),
            "vulns": list(sh.get("vulns", {}).keys())[:10],
            "country": sh.get("country_name", ""),
        }
    elif sh and "error" in sh:
        rep["shodan"] = {"info": sh["error"]}

    # IPQualityScore
    print_info("Querying IPQualityScore...")
    ipqs = ipqs_ip(ip)
    if ipqs and "error" not in ipqs:
        rep["ipqualityscore"] = {
            "fraud_score": ipqs.get("fraud_score", 0),
            "is_proxy": ipqs.get("proxy", False),
            "is_vpn": ipqs.get("vpn", False),
            "is_tor": ipqs.get("tor", False),
            "is_bot": ipqs.get("bot_status", False),
            "isp": ipqs.get("ISP", ""),
            "abuse_velocity": ipqs.get("abuse_velocity", ""),
        }
    elif ipqs and "error" in ipqs:
        rep["ipqualityscore"] = {"info": ipqs["error"]}

    return rep


def _check_threat_info(ip: str) -> dict:
    threat = {
        "is_tor": False,
        "is_vpn": False,
        "is_proxy": False,
        "is_datacenter": False,
    }

    # Check IPQualityScore for combined threat info
    ipqs = ipqs_ip(ip)
    if ipqs and "error" not in ipqs:
        threat["is_tor"] = ipqs.get("tor", False)
        threat["is_vpn"] = ipqs.get("vpn", False)
        threat["is_proxy"] = ipqs.get("proxy", False)
        threat["is_datacenter"] = ipqs.get("active_vpn", False) or ipqs.get("recent_abuse", False)

    # Confirm Tor exit node via Tor Project API
    try:
        resp = safe_get(f"https://check.torproject.org/api/ip/{ip}", timeout=10)
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get("IsTor"):
                threat["is_tor"] = True
    except Exception:
        pass

    return threat


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def _address_family(ip: str) -> int:
    return socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET


def _port_scan(ip: str, ports: list) -> list:
    cfg = load_config()
    timeout = cfg.get("settings", {}).get("port_scan_timeout", 0.5)
    open_ports = []
    lock = threading.Lock()

    family = _address_family(ip)

    def check_port(port: int):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
            if result == 0:
                service = _get_service_name(port)
                with lock:
                    open_ports.append({"port": port, "service": service, "state": "open"})
        except Exception:
            pass

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning ports...", total=len(ports))
        with ThreadPoolExecutor(max_workers=200) as executor:
            futures = {executor.submit(check_port, p): p for p in ports}
            for future in as_completed(futures):
                future.result()
                progress.advance(task)

    return sorted(open_ports, key=lambda x: x["port"])


def _grab_banners(ip: str, ports: list) -> dict:
    cfg = load_config()
    timeout = cfg.get("settings", {}).get("port_scan_timeout", 0.5) * 4
    banners = {}

    family = _address_family(ip)
    for port in ports[:10]:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))

                probe = SERVICE_BANNERS.get(port, b"")
                if probe:
                    sock.send(probe)

                banner = sock.recv(1024)
            if banner:
                banners[port] = banner.decode("utf-8", errors="replace").strip()[:200]
        except Exception:
            pass

    return banners


def _calculate_risk(result: dict) -> tuple[int, list]:
    score = 0
    details = []

    rep = result.get("reputation", {})

    # AbuseIPDB
    abuse = rep.get("abuseipdb", {})
    abuse_score = abuse.get("abuse_score", 0)
    if abuse_score >= 80:
        score += 35
        details.append(f"AbuseIPDB: very high confidence score {abuse_score}% (+35)")
    elif abuse_score >= 50:
        score += 20
        details.append(f"AbuseIPDB: high confidence score {abuse_score}% (+20)")
    elif abuse_score >= 20:
        score += 10
        details.append(f"AbuseIPDB: moderate confidence score {abuse_score}% (+10)")

    reports = abuse.get("total_reports", 0)
    if reports > 100:
        score += 15
        details.append(f"AbuseIPDB: {reports} total abuse reports (+15)")
    elif reports > 10:
        score += 5
        details.append(f"AbuseIPDB: {reports} total abuse reports (+5)")

    # VirusTotal
    vt = rep.get("virustotal", {})
    mal = vt.get("malicious", 0)
    sus = vt.get("suspicious", 0)
    if mal > 0:
        score += min(mal * 4, 30)
        details.append(f"VirusTotal: {mal} malicious detections (+{min(mal*4,30)})")
    if sus > 0:
        score += min(sus * 2, 10)
        details.append(f"VirusTotal: {sus} suspicious detections (+{min(sus*2,10)})")

    # Shodan vulns
    sh = rep.get("shodan", {})
    vulns = sh.get("vulns", [])
    if vulns:
        score += min(len(vulns) * 5, 25)
        details.append(f"Shodan: {len(vulns)} known vulnerabilities (+{min(len(vulns)*5,25)})")

    # Threat info
    threat = result.get("threat_info", {})
    if threat.get("is_tor"):
        score += 20
        details.append("IP is a Tor exit node (+20)")
    if threat.get("is_vpn"):
        score += 10
        details.append("IP is a VPN (+10)")
    if threat.get("is_proxy"):
        score += 10
        details.append("IP is a proxy (+10)")

    # IPQualityScore
    ipqs = rep.get("ipqualityscore", {})
    fraud = ipqs.get("fraud_score", 0)
    if fraud >= 75:
        score += 15
        details.append(f"IPQualityScore: fraud score {fraud} (+15)")

    # Many open ports
    open_ports = result.get("open_ports", [])
    if len(open_ports) > 20:
        score += 10
        details.append(f"{len(open_ports)} open ports detected (+10)")

    # Dangerous ports
    dangerous = [p["port"] for p in open_ports if p["port"] in [23, 4444, 6667, 31337]]
    if dangerous:
        score += 15
        details.append(f"Dangerous ports open: {dangerous} (+15)")

    return min(score, 100), details


def _display_results(result: dict) -> None:
    console.print(f"\n[bold]IP:[/] [cyan]{result.get('ip')}[/]")
    if result.get("is_private"):
        console.print("[yellow]Private/Internal IP address[/]")

    # Geolocation
    geo = result.get("geolocation", {})
    if geo:
        geo_rows = [
            ("Country", f"{geo.get('country', '')} {geo.get('country_name', '')}"),
            ("Region", geo.get("region", "")),
            ("City", geo.get("city", "")),
            ("Postal Code", geo.get("postal", "")),
            ("ISP/Org", geo.get("org", "")),
            ("ASN", geo.get("asn", "")),
            ("ASN Name", geo.get("asn_name", "")),
            ("Timezone", geo.get("timezone", "")),
            ("Coordinates", f"{geo.get('latitude', '')}, {geo.get('longitude', '')}"),
        ]
        print_result_table("Geolocation", [(r[0], r[1]) for r in geo_rows if r[1]])

    # Reverse DNS
    rdns = result.get("reverse_dns", "N/A")
    console.print(f"\n[bold]Reverse DNS:[/] {rdns}")

    # Threat info
    threat = result.get("threat_info", {})
    if threat:
        t_rows = [
            ("Tor Exit Node", "[red]YES[/]" if threat.get("is_tor") else "[green]No[/]"),
            ("VPN", "[yellow]YES[/]" if threat.get("is_vpn") else "[green]No[/]"),
            ("Proxy", "[yellow]YES[/]" if threat.get("is_proxy") else "[green]No[/]"),
            ("Datacenter/Hosting", "[yellow]YES[/]" if threat.get("is_datacenter") else "[green]No[/]"),
        ]
        print_result_table("Threat Classification", t_rows)

    # Reputation
    rep = result.get("reputation", {})
    abuse = rep.get("abuseipdb", {})
    if "abuse_score" in abuse:
        score = abuse.get("abuse_score", 0)
        color = "red" if score >= 50 else ("yellow" if score >= 20 else "green")
        rep_rows = [
            ("AbuseIPDB Score", f"[{color}]{score}%[/]"),
            ("Total Reports", str(abuse.get("total_reports", 0))),
            ("Last Reported", abuse.get("last_reported", "Never")),
            ("Usage Type", abuse.get("usage_type", "")),
            ("ISP", abuse.get("isp", "")),
        ]
        print_result_table("AbuseIPDB", rep_rows)

    vt = rep.get("virustotal", {})
    if "malicious" in vt:
        m, s = vt.get("malicious", 0), vt.get("suspicious", 0)
        color = "red" if m > 0 else ("yellow" if s > 0 else "green")
        vt_rows = [
            ("Malicious", f"[{color}]{m}[/]"),
            ("Suspicious", f"[yellow]{s}[/]" if s else "0"),
            ("Harmless", str(vt.get("harmless", 0))),
            ("VT Reputation", str(vt.get("reputation", 0))),
            ("Network", vt.get("network", "")),
        ]
        print_result_table("VirusTotal", vt_rows)

    sh = rep.get("shodan", {})
    if sh and "error" not in sh and "info" not in sh:
        sh_rows = [
            ("Organization", sh.get("org", "")),
            ("ISP", sh.get("isp", "")),
            ("ASN", sh.get("asn", "")),
            ("Open Ports (Shodan)", ", ".join(str(p) for p in sh.get("open_ports", [])[:20])),
            ("Hostnames", ", ".join(sh.get("hostnames", [])[:5])),
            ("Tags", ", ".join(sh.get("tags", []))),
            ("Known Vulnerabilities", ", ".join(sh.get("vulns", [])[:5])),
        ]
        print_result_table("Shodan", [(r[0], r[1]) for r in sh_rows if r[1]])

    ipqs = rep.get("ipqualityscore", {})
    if "fraud_score" in ipqs:
        fs = ipqs.get("fraud_score", 0)
        color = "red" if fs >= 75 else ("yellow" if fs >= 50 else "green")
        ipqs_rows = [
            ("Fraud Score", f"[{color}]{fs}[/]"),
            ("Is Proxy", "[red]YES[/]" if ipqs.get("is_proxy") else "No"),
            ("Is VPN", "[yellow]YES[/]" if ipqs.get("is_vpn") else "No"),
            ("Is Tor", "[red]YES[/]" if ipqs.get("is_tor") else "No"),
            ("Is Bot", "[red]YES[/]" if ipqs.get("is_bot") else "No"),
            ("Abuse Velocity", ipqs.get("abuse_velocity", "")),
        ]
        print_result_table("IPQualityScore", ipqs_rows)

    # Open ports
    open_ports = result.get("open_ports", [])
    if open_ports:
        t = Table(title=f"Open Ports ({len(open_ports)} found)", box=box.ROUNDED,
                  header_style="bold green")
        t.add_column("Port", width=8)
        t.add_column("Service")
        t.add_column("Banner")
        banners = result.get("banners", {})
        for p in open_ports:
            banner = banners.get(p["port"], "")
            t.add_row(
                str(p["port"]),
                p.get("service", ""),
                banner[:60] if banner else "",
            )
        console.print(t)
    elif "open_ports" in result:
        console.print("\n[green]No open ports found in top ports scan[/]")
    else:
        console.print("\n[dim]Port scan not performed (passive analysis).[/]")

    print_risk_score(result.get("risk_score", 0))
    if result.get("risk_details"):
        console.print("[bold]Risk Factors:[/]")
        for d in result.get("risk_details", []):
            console.print(f"  [yellow]•[/] {d}")


def _get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return ""


def run():
    print_section("IP & Network Analyzer", "🌐")
    ip = console.input("\n[bold]Enter IP address to analyze:[/] ").strip()
    if not ip:
        print_error("No IP provided")
        return

    scan_ports = confirm_authorized("Escaneo de puertos", ip)
    result = analyze_ip(ip, scan_ports=scan_ports)
    if result:
        export = console.input("\n[bold]Export results? (json/txt/html/all/no):[/] ").strip().lower()
        if export and export != "no":
            formats = ["json", "txt", "html"] if export == "all" else [export]
            saved = save_results("ip", ip, result, formats)
            for fmt, path in saved.items():
                console.print(f"[green]Saved {fmt.upper()}:[/] {path}")
