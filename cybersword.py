#!/usr/bin/env python3
"""
CyberSword - Personal Cybersecurity Swiss Army Knife
Defensive OSINT & Analysis Platform

Usage:
    python cybersword.py                    # Interactive menu
    python cybersword.py --setup            # Configure API keys
    python cybersword.py -q --ip 1.2.3.4   # Quiet mode, passive IP analysis
    python cybersword.py --ip 1.2.3.4 --scan-ports  # Also scan ports (authorized targets only)
    python cybersword.py --url evil.com     # Analyze URL
    python cybersword.py --email x@y.com   # Analyze email
    python cybersword.py --hash <sha256>   # Hash lookup
    python cybersword.py --file /tmp/a.exe # File analysis
    python cybersword.py --phone +34612... # Phone lookup
    python cybersword.py --ioc 1.2.3.4     # Threat intel lookup
"""

import sys
import argparse
import contextlib
import io
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent))

# Check Python version
if sys.version_info < (3, 12):
    print("[ERROR] CyberSword requires Python 3.12 or higher.")
    sys.exit(1)

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich import box

from utils.helpers import load_config, check_connectivity
from utils.output import print_banner, print_section, print_error, print_warning

console = Console()

__version__ = "1.1.0"

MENU_ITEMS = [
    ("1", "📧", "Email Analyzer", "Analyze headers, SPF/DKIM/DMARC, phishing detection"),
    ("2", "🔗", "URL & Domain Analyzer", "WHOIS, DNS, SSL, reputation, typosquatting"),
    ("3", "🌐", "IP & Network Analyzer", "Geolocation, reputation, port scan, Shodan"),
    ("4", "📱", "Phone Analyzer", "Carrier, VoIP detection, spam lookup"),
    ("5", "💬", "SMS & Message Analyzer", "Phishing patterns, brand impersonation"),
    ("6", "🔍", "OSINT", "Google dorks, breach check, username search, EXIF"),
    ("7", "🔐", "Cryptography & Analysis", "AES, hashing, encoding, steganography, passwords"),
    ("8", "📁", "File Analyzer", "Hash, VirusTotal, PE headers, IOCs, strings"),
    ("9", "🌍", "Web Scanner", "Fuzzing, security headers, CMS, sensitive files"),
    ("10", "🔎", "Threat Intelligence", "Multi-source IOC lookup: VT, OTX, AbuseIPDB..."),
    ("11", "📊", "Dashboard & Reports", "Session summary, export HTML report"),
    ("0", "🚪", "Exit", ""),
]


def show_menu():
    """Display the main interactive menu."""
    print_banner()

    # Connectivity check
    if not check_connectivity():
        print_warning("No internet connection detected. Network features may be limited.")

    # Config status
    cfg = load_config()
    api_keys = cfg.get("api_keys", {})
    configured = sum(1 for v in api_keys.values() if v)
    total = len(api_keys)

    if configured == 0:
        console.print(Panel(
            "[yellow]No API keys configured. Run [bold]--setup[/] to configure them.\n"
            "Many features work without keys, but reputation lookups require them.[/]",
            style="yellow",
            title="⚠ Configuration",
        ))
    else:
        console.print(f"[dim]API keys: {configured}/{total} configured | "
                     f"Logs: {cfg.get('output', {}).get('log_dir', 'logs')} | "
                     f"Reports: {cfg.get('output', {}).get('report_dir', 'reports')}[/]")

    console.print()
    t = Table(box=box.ROUNDED, show_header=False, border_style="cyan", padding=(0, 1))
    t.add_column("Key", style="bold cyan", width=4)
    t.add_column("Icon", width=3)
    t.add_column("Module", style="bold white")
    t.add_column("Description", style="dim")

    for key, icon, name, desc in MENU_ITEMS:
        t.add_row(key, icon, name, desc)

    console.print(t)


def run_module(choice: str) -> None:
    """Dispatch to the selected module."""
    dispatch = {
        "1": ("modules.email_analyzer", "run"),
        "2": ("modules.url_analyzer", "run"),
        "3": ("modules.ip_analyzer", "run"),
        "4": ("modules.phone_analyzer", "run"),
        "5": ("modules.sms_analyzer", "run"),
        "6": ("modules.osint", "run"),
        "7": ("modules.crypto", "run"),
        "8": ("modules.file_analyzer", "run"),
        "9": ("modules.web_scanner", "run"),
        "10": ("modules.threat_intel", "run"),
        "11": ("modules.reporter", "run"),
    }

    if choice not in dispatch:
        print_error(f"Unknown option: {choice}")
        return

    module_path, fn_name = dispatch[choice]
    try:
        import importlib
        module = importlib.import_module(module_path)
        fn = getattr(module, fn_name)
        fn()
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/]")
    except ImportError as e:
        print_error(f"Module import error: {e}")
        console.print("[dim]Try: pip install -r requirements.txt[/]")
    except Exception as e:
        print_error(f"Error in module: {e}")
        cfg = load_config()
        if cfg.get("settings", {}).get("verbose"):
            import traceback
            traceback.print_exc()


def setup_wizard() -> None:
    """Interactive API key configuration wizard."""
    print_section("CyberSword Setup", "⚙️")
    console.print("[bold]Welcome! Let's configure your API keys.[/]")
    console.print("[dim]Press Enter to skip any key.[/]\n")

    config_path = Path(__file__).parent / "config.yaml"
    template_path = Path(__file__).parent / "config.example.yaml"
    source_path = config_path if config_path.exists() else template_path
    if source_path.exists():
        with open(source_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    else:
        cfg = {}

    if "api_keys" not in cfg:
        cfg["api_keys"] = {}
    if "settings" not in cfg:
        cfg["settings"] = {}

    api_configs = [
        ("virustotal", "VirusTotal", "https://www.virustotal.com/gui/join-us", "4 req/min free"),
        ("abuseipdb", "AbuseIPDB", "https://www.abuseipdb.com/account/api", "1000 req/day free"),
        ("shodan", "Shodan", "https://account.shodan.io/", "Free limited"),
        ("ipinfo", "ipinfo.io", "https://ipinfo.io/account", "50k req/month free"),
        ("haveibeenpwned", "HaveIBeenPwned", "https://haveibeenpwned.com/API/Key", "Paid (cheap)"),
        ("google_safe_browsing", "Google Safe Browsing", "https://developers.google.com/safe-browsing", "Free"),
        ("alienvault_otx", "AlienVault OTX", "https://otx.alienvault.com/api", "Free"),
        ("ipqualityscore", "IPQualityScore", "https://www.ipqualityscore.com/", "200/day free"),
        ("abusech", "abuse.ch (URLhaus, MalwareBazaar)", "https://auth.abuse.ch/", "Free"),
        ("numverify", "NumVerify", "https://numverify.com/", "100/month free"),
    ]

    for key, name, url, tier in api_configs:
        current = cfg["api_keys"].get(key, "")
        masked = ("*" * (len(current) - 4) + current[-4:]) if len(current) > 4 else "not set"
        console.print(f"\n[bold cyan]{name}[/] [dim]({tier})[/]")
        console.print(f"  Get key: [blue]{url}[/]")
        console.print(f"  Current: [dim]{masked}[/]")
        value = Prompt.ask("  Enter API key", default="", password=True).strip()
        if value:
            cfg["api_keys"][key] = value

    console.print("\n[bold]Settings:[/]")
    timeout = Prompt.ask("HTTP timeout (seconds)", default=str(cfg["settings"].get("timeout", 15)))
    proxy = Prompt.ask("Proxy (e.g. http://127.0.0.1:8080, or blank)", default=cfg["settings"].get("proxy", ""))
    port_top = Prompt.ask("Port scan top N (100/1000)", choices=["100", "1000"],
                          default=str(cfg["settings"].get("port_scan_top", 100)))

    cfg["settings"]["timeout"] = int(timeout) if timeout.isdigit() else 15
    cfg["settings"]["proxy"] = proxy
    cfg["settings"]["port_scan_top"] = int(port_top)

    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)
    config_path.chmod(0o600)

    console.print(f"\n[bold green]Configuration saved to {config_path}[/]")


def main():
    # Ctrl+C se gestiona con KeyboardInterrupt: dentro de un módulo cancela la
    # operación y vuelve al menú; en el menú, sale.
    parser = argparse.ArgumentParser(
        description="CyberSword — Personal Cybersecurity Swiss Army Knife",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--setup", action="store_true", help="Run setup wizard")
    parser.add_argument("--ip", metavar="IP", help="Analyze an IP address (passive)")
    parser.add_argument("--scan-ports", action="store_true",
                        help="With --ip: also scan common TCP ports (only on targets you are authorized to test)")
    parser.add_argument("--url", metavar="URL", help="Analyze a URL or domain")
    parser.add_argument("--email", metavar="EMAIL", help="Analyze an email address")
    parser.add_argument("--hash", metavar="HASH", help="Lookup a file hash")
    parser.add_argument("--file", metavar="FILE", help="Analyze a local file")
    parser.add_argument("--phone", metavar="PHONE", help="Analyze a phone number")
    parser.add_argument("--ioc", metavar="IOC", help="Threat intelligence IOC lookup")
    parser.add_argument("--username", metavar="USER", help="OSINT username search")
    parser.add_argument("--sms", metavar="TEXT", help="Analyze SMS message text")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (JSON output)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument("-o", "--output", choices=["json", "txt", "html", "all"],
                        help="Export format")
    parser.add_argument("--version", action="version", version=f"CyberSword v{__version__}")

    args = parser.parse_args()

    # Update config with CLI flags
    cfg = load_config()
    if args.quiet:
        cfg.setdefault("settings", {})["quiet"] = True
    if args.verbose:
        cfg.setdefault("settings", {})["verbose"] = True

    if args.scan_ports and not args.ip:
        parser.error("--scan-ports requires --ip")

    if args.setup:
        setup_wizard()
        return

    # CLI mode — direct analysis without menu
    if any([args.ip, args.url, args.email, args.hash, args.file,
            args.phone, args.ioc, args.username, args.sms]):

        import importlib
        import json

        def _run_and_export(module_name: str, fn_name: str, *fn_args):
            m = importlib.import_module(module_name)
            fn = getattr(m, fn_name)
            if args.quiet:
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                    result = fn(*fn_args)
            else:
                result = fn(*fn_args)
            if args.quiet and result:
                print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
            elif result and args.output:
                from utils.output import save_results
                formats = ["json", "txt", "html"] if args.output == "all" else [args.output]
                saved = save_results(module_name.split(".")[-1], str(fn_args[0]), result, formats)
                for fmt, path in saved.items():
                    console.print(f"[green]Saved {fmt.upper()}:[/] {path}")
            return result

        try:
            if args.ip:
                _run_and_export("modules.ip_analyzer", "analyze_ip", args.ip, args.scan_ports)
            elif args.url:
                _run_and_export("modules.url_analyzer", "analyze_url", args.url)
            elif args.email:
                # Try as email OSINT
                _run_and_export("modules.osint", "osint_email", args.email)
            elif args.hash:
                _run_and_export("modules.threat_intel", "lookup_ioc", args.hash)
            elif args.file:
                _run_and_export("modules.file_analyzer", "analyze_file", args.file)
            elif args.phone:
                _run_and_export("modules.phone_analyzer", "analyze_phone", args.phone)
            elif args.ioc:
                _run_and_export("modules.threat_intel", "lookup_ioc", args.ioc)
            elif args.username:
                _run_and_export("modules.osint", "osint_username", args.username)
            elif args.sms:
                _run_and_export("modules.sms_analyzer", "analyze_sms", args.sms)
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled.[/]")
            sys.exit(130)
        except Exception as e:
            if args.quiet:
                print(json.dumps({"error": str(e)}))
            else:
                print_error(str(e))
                if args.verbose:
                    import traceback
                    traceback.print_exc()
            sys.exit(1)
        return

    # Interactive menu loop
    while True:
        try:
            console.clear()
            show_menu()
            choice = console.input("\n[bold cyan]CyberSword >[/] ").strip()

            if choice == "0" or choice.lower() in ("exit", "quit", "q"):
                console.print("\n[bold cyan]Goodbye! Stay safe.[/]")
                break
            elif choice == "":
                continue
            elif choice.lower() == "help":
                console.print(f"\n{__doc__}")
            elif choice.lower() == "dashboard":
                run_module("11")
            else:
                console.clear()
                run_module(choice)

            if choice != "0":
                console.input("\n[dim]Press Enter to return to menu...[/]")

        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold cyan]Goodbye! Stay safe.[/]")
            break


if __name__ == "__main__":
    main()
