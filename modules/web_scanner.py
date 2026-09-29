"""
CyberSword - Web Scanner
Directory fuzzing, security headers, sensitive files, CMS detection, CVE check.
"""

import re
import hashlib
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

from utils.helpers import (
    log_analysis, make_session
)
from utils.output import (
    print_section, print_result_table, print_error,
    print_success, save_results, confirm_authorized
)

console = Console()
_thread_local = threading.local()


def _thread_session():
    """Return one requests session per worker thread."""
    if not hasattr(_thread_local, "session"):
        _thread_local.session = make_session()
    return _thread_local.session

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "critical": True,
        "description": "Forces HTTPS connections",
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "critical": True,
        "description": "Prevents XSS and injection attacks",
        "recommended": "default-src 'self'",
    },
    "X-Frame-Options": {
        "critical": True,
        "description": "Prevents clickjacking",
        "recommended": "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "critical": True,
        "description": "Prevents MIME sniffing",
        "recommended": "nosniff",
    },
    "Referrer-Policy": {
        "critical": False,
        "description": "Controls referrer header",
        "recommended": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "critical": False,
        "description": "Controls browser feature access",
        "recommended": "geolocation=(), microphone=(), camera=()",
    },
    "X-XSS-Protection": {
        "critical": False,
        "description": "Legacy XSS filter (deprecated, use CSP)",
        "recommended": "1; mode=block",
    },
    "Cache-Control": {
        "critical": False,
        "description": "Caching directives",
        "recommended": "no-store for sensitive pages",
    },
    "Cross-Origin-Embedder-Policy": {
        "critical": False,
        "description": "Cross-origin isolation",
        "recommended": "require-corp",
    },
    "Cross-Origin-Opener-Policy": {
        "critical": False,
        "description": "Opener isolation",
        "recommended": "same-origin",
    },
}

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.backup", "/.env.bak",
    "/.git/HEAD", "/.git/config", "/.gitignore",
    "/.htaccess", "/.htpasswd",
    "/web.config", "/config.php", "/config.yml", "/config.yaml",
    "/wp-config.php", "/wp-config.php.bak",
    "/database.sql", "/dump.sql", "/backup.sql", "/db.sql",
    "/backup.zip", "/backup.tar.gz", "/www.zip",
    "/phpinfo.php", "/info.php",
    "/admin/", "/admin/login", "/admin/index.php",
    "/phpmyadmin/", "/phpmyadmin/index.php",
    "/wp-admin/", "/wp-login.php",
    "/cpanel/", "/cPanel/", "/webmail/",
    "/server-status", "/server-info",
    "/.DS_Store", "/Thumbs.db",
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.svn/entries", "/.svn/wc.db",
    "/composer.json", "/package.json", "/yarn.lock",
    "/Gemfile", "/requirements.txt", "/Pipfile",
    "/docker-compose.yml", "/Dockerfile",
    "/proc/self/environ",
    "/api/swagger.json", "/api-docs", "/swagger-ui.html",
    "/graphql", "/graphiql",
    "/actuator", "/actuator/env", "/actuator/health",
    "/_profiler/", "/debug/",
    "/test/", "/testing/", "/dev/", "/staging/",
    "/log/", "/logs/", "/error.log", "/access.log",
    "/id_rsa", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/credentials.json", "/secrets.json", "/token.json",
]

CMS_FINGERPRINTS = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/xmlrpc.php"],
        "headers": [],
        "content": ["wp-content", "WordPress", "wp-json"],
        "version_regex": r'<meta name="generator" content="WordPress ([0-9.]+)',
        "vuln_check": "wordpress",
    },
    "Joomla": {
        "paths": ["/administrator/", "/components/", "/modules/"],
        "headers": [],
        "content": ["Joomla", "/components/com_"],
        "version_regex": r'"generator":"\s*Joomla! ([0-9.]+)',
        "vuln_check": "joomla",
    },
    "Drupal": {
        "paths": ["/sites/default/", "/core/install.php"],
        "headers": ["X-Generator"],
        "content": ["Drupal.settings", "drupal"],
        "version_regex": r'<meta name="Generator" content="Drupal ([0-9.]+)',
        "vuln_check": "drupal",
    },
    "Magento": {
        "paths": ["/skin/frontend/", "/media/", "/downloader/"],
        "headers": [],
        "content": ["Mage.Cookies", "Magento"],
        "version_regex": r'Magento/([0-9.]+)',
        "vuln_check": "magento",
    },
    "PrestaShop": {
        "paths": ["/modules/", "/themes/", "/img/"],
        "headers": [],
        "content": ["PrestaShop", "_prestashop"],
        "version_regex": r'"generator":"PrestaShop v([0-9.]+)',
        "vuln_check": "prestashop",
    },
    "Shopify": {
        "paths": [],
        "headers": [],
        "content": ["cdn.shopify.com", "Shopify.theme"],
        "version_regex": None,
        "vuln_check": None,
    },
    "Laravel": {
        "paths": ["/storage/", "/public/"],
        "headers": ["X-Powered-By"],
        "content": ["laravel", "csrf-token"],
        "version_regex": r'Laravel/([0-9.]+)',
        "vuln_check": None,
    },
    "Django": {
        "paths": ["/admin/", "/static/admin/"],
        "headers": [],
        "content": ["csrfmiddlewaretoken", "__admin_media_prefix__"],
        "version_regex": None,
        "vuln_check": None,
    },
    "Ruby on Rails": {
        "paths": ["/rails/info/", "/assets/application-"],
        "headers": ["X-Powered-By"],
        "content": ["data-remote=\"true\"", "authenticity_token"],
        "version_regex": None,
        "vuln_check": None,
    },
}

# Minimal built-in wordlist (extended with wordlists/directories.txt at runtime)
DEFAULT_WORDLIST = [
    "admin", "login", "wp-admin", "dashboard", "api", "upload",
    "images", "static", "assets", "backup", "backups", "db", "database",
    "config", "configuration", "test", "dev", "staging", "old",
    "tmp", "temp", "cache", "logs", "log", "error", "info",
    "phpinfo.php", "info.php", "index.php", "index.html",
    "robots.txt", "sitemap.xml", ".env", ".git",
    "swagger", "graphql", "api/v1", "api/v2",
    "actuator", "health", "metrics", "status",
    "console", "manager", "panel", "portal", "control",
    "phpmyadmin", "adminer", "cpanel", "webmail",
    "wordpress", "wp-content", "wp-includes",
    "readme", "README", "license", "LICENSE", "CHANGELOG",
    "user", "users", "account", "accounts", "register",
    "search", "ajax", "data", "json", "xml",
    "docs", "documentation", "help", "support",
    "downloads", "files", "media", "uploads",
    "forum", "blog", "shop", "store",
    "contact", "about", "home", "index",
    "404", "403", "500",
]


def scan_web(url: str) -> dict:
    """Full web security scan."""
    print_section("Web Scanner", "🌍")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Normalize URL
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print_error(f"Invalid HTTP(S) URL: {url}")
        return {}
    if parsed.username or parsed.password:
        print_error("URLs containing credentials are not accepted")
        return {}
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    console.print(f"\n[bold]Target:[/] [cyan]{base_url}[/]")
    result = {"url": base_url}

    with console.status("[bold green]Checking security headers..."):
        result["security_headers"] = check_security_headers(base_url)

    with console.status("[bold green]Detecting CMS..."):
        result["cms"] = detect_cms(base_url)

    with console.status("[bold green]Scanning for sensitive files..."):
        result["sensitive_files"] = scan_sensitive_files(base_url)

    console.print("\n[bold]Directory Fuzzing...[/]")
    result["found_paths"] = fuzz_directories(base_url)

    result["risk_score"], result["risk_details"] = _calculate_risk(result)

    _display_results(result)
    log_analysis("web", base_url, result)

    return result


def check_security_headers(url: str) -> dict:
    """Check HTTP security headers."""
    result = {"present": {}, "missing": [], "score": 0}

    try:
        sess = make_session()
        resp = sess.get(url, timeout=15, allow_redirects=True)
        headers = resp.headers

        for header, config in SECURITY_HEADERS.items():
            value = headers.get(header, "")
            if value:
                result["present"][header] = {
                    "value": value,
                    "critical": config["critical"],
                    "description": config["description"],
                }
            else:
                result["missing"].append({
                    "header": header,
                    "critical": config["critical"],
                    "description": config["description"],
                    "recommended": config["recommended"],
                })

        # Score: all present = 100
        total = len(SECURITY_HEADERS)
        present = len(result["present"])
        result["score"] = int((present / total) * 100)

        # Also grab response info
        result["status_code"] = resp.status_code
        result["server"] = headers.get("Server", "")
        result["x_powered_by"] = headers.get("X-Powered-By", "")
        result["cookies"] = []
        for cookie in resp.cookies:
            cookie_info = {
                "name": cookie.name,
                "secure": bool(cookie.secure),
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "samesite": cookie.get_nonstandard_attr("SameSite", ""),
            }
            result["cookies"].append(cookie_info)

    except Exception as e:
        result["error"] = str(e)

    return result


def detect_cms(url: str) -> dict:
    """Detect CMS and version."""
    result = {"detected": None, "version": None, "confidence": 0, "details": {}}

    try:
        sess = make_session()
        resp = sess.get(url, timeout=15, allow_redirects=True)
        html = resp.text[:100000]
        headers = dict(resp.headers)

        for cms, fingerprint in CMS_FINGERPRINTS.items():
            score = 0

            # Content checks
            for sig in fingerprint.get("content", []):
                if sig.lower() in html.lower():
                    score += 2

            # Path checks (quick HEAD requests)
            for path in fingerprint.get("paths", [])[:3]:
                try:
                    r = sess.head(url.rstrip("/") + path, timeout=5, allow_redirects=False)
                    if r.status_code in (200, 301, 302, 403):
                        score += 3
                except Exception:
                    pass

            # Header checks
            for h in fingerprint.get("headers", []):
                if h in headers:
                    score += 2

            if score > 0:
                result["details"][cms] = score
                if score > result["confidence"]:
                    result["confidence"] = score
                    result["detected"] = cms

                    # Version detection
                    version_regex = fingerprint.get("version_regex")
                    if version_regex:
                        match = re.search(version_regex, html)
                        if match:
                            result["version"] = match.group(1)

        # Generator meta tag
        gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)', html, re.I)
        if gen_match and not result["detected"]:
            result["detected"] = gen_match.group(1)

    except Exception as e:
        result["error"] = str(e)

    return result


class NotFoundBaseline:
    """Respuesta del servidor a una ruta inexistente, para descartar "soft 404".

    Muchas webs (SPA, 404 personalizados) devuelven 200 o redirigen a /login para
    cualquier ruta: sin esta referencia, todas las rutas probadas parecerían existir.
    """

    PROBE_PATH = "/cybersword-nonexistent-path-7f3a9c"
    SIZE_TOLERANCE = 64

    def __init__(self, status: int | None, size: int = 0, digest: str = "", location: str = ""):
        self.status = status
        self.size = size
        self.digest = digest
        self.location = location

    @classmethod
    def measure(cls, base_url: str, session) -> "NotFoundBaseline":
        try:
            resp = session.get(base_url.rstrip("/") + cls.PROBE_PATH, timeout=8, allow_redirects=False)
        except Exception:
            return cls(None)
        return cls(
            resp.status_code,
            len(resp.content),
            hashlib.sha256(resp.content[:1000]).hexdigest(),
            resp.headers.get("Location", ""),
        )

    def matches(self, resp, path: str) -> bool:
        """True si `resp` es indistinguible de la respuesta a una ruta inexistente."""
        if self.status is None or resp.status_code != self.status:
            return False
        if resp.status_code in (301, 302, 303, 307, 308):
            # Redirección genérica (p. ej. todo va a /login).
            return resp.headers.get("Location", "") == self.location
        if hashlib.sha256(resp.content[:1000]).hexdigest() == self.digest:
            return True
        # Páginas de error que repiten la ruta pedida: mismo tamaño salvo unos bytes.
        return abs(len(resp.content) - self.size) <= len(path) + self.SIZE_TOLERANCE


def scan_sensitive_files(base_url: str, paths: list = None) -> list:
    """Check for exposed sensitive files."""
    found = []
    check_paths = paths or SENSITIVE_PATHS
    baseline = NotFoundBaseline.measure(base_url, make_session())

    def check_path(path: str):
        url = base_url.rstrip("/") + path
        try:
            resp = _thread_session().get(url, timeout=8, allow_redirects=False)
            if baseline.matches(resp, path):
                return None
            if resp.status_code == 200:
                # Avoid false positives (custom 404 pages returning 200)
                content_length = len(resp.content)
                content_type = resp.headers.get("Content-Type", "")

                # Skip if it looks like a generic error page
                if content_length < 50 and "html" in content_type:
                    return None

                return {
                    "path": path,
                    "url": url,
                    "status": resp.status_code,
                    "size": content_length,
                    "content_type": content_type,
                    "critical": any(x in path for x in [
                        ".env", "config", "password", "secret", "sql",
                        "backup", ".git", "id_rsa", ".htpasswd",
                    ]),
                }
            elif resp.status_code in (301, 302):
                return {
                    "path": path,
                    "url": url,
                    "status": resp.status_code,
                    "size": 0,
                    "content_type": "",
                    "redirect_to": resp.headers.get("Location", ""),
                    "critical": False,
                }
        except Exception:
            pass
        return None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning sensitive files...", total=len(check_paths))
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_path, p): p for p in check_paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                progress.advance(task)

    return sorted(found, key=lambda x: (not x.get("critical"), x["path"]))


def fuzz_directories(base_url: str, custom_wordlist: list = None) -> list:
    """Fuzz directories and endpoints."""
    found = []

    # Lista de rutas: la personalizada si se pasa; si no, la integrada más wordlists/directories.txt.
    wordlist_file = Path(__file__).parent.parent / "wordlists" / "directories.txt"
    if custom_wordlist:
        wordlist = list(dict.fromkeys(custom_wordlist))
    elif wordlist_file.exists():
        with open(wordlist_file, "r", encoding="utf-8", errors="replace") as f:
            file_words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        wordlist = list(dict.fromkeys(DEFAULT_WORDLIST + file_words))
    else:
        wordlist = DEFAULT_WORDLIST

    baseline = NotFoundBaseline.measure(base_url, make_session())

    def check_path(word: str):
        path = "/" + word.lstrip("/")
        url = base_url.rstrip("/") + path
        try:
            resp = _thread_session().get(url, timeout=6, allow_redirects=False)
            status = resp.status_code

            if status in (200, 201, 204, 403, 301, 302, 307, 308):
                if baseline.matches(resp, path):
                    return None

                return {
                    "path": path,
                    "url": url,
                    "status": status,
                    "size": len(resp.content),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "note": {
                        200: "OK - Accessible",
                        403: "Forbidden - Exists but restricted",
                        301: f"Redirect → {resp.headers.get('Location', '')}",
                        302: f"Redirect → {resp.headers.get('Location', '')}",
                    }.get(status, str(status)),
                }
        except Exception:
            pass
        return None

    console.print(f"[dim]Fuzzing {len(wordlist)} paths...[/]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("Fuzzing...", total=len(wordlist))
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(check_path, w): w for w in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                progress.advance(task)

    return sorted(found, key=lambda x: x["status"])


def _calculate_risk(result: dict) -> tuple[int, list]:
    score = 0
    details = []

    # Security headers
    sec = result.get("security_headers", {})
    missing = sec.get("missing", [])
    critical_missing = [m for m in missing if m.get("critical")]
    if critical_missing:
        penalty = len(critical_missing) * 8
        score += min(penalty, 30)
        names = [m["header"] for m in critical_missing]
        details.append(f"Missing critical headers: {', '.join(names)} (+{min(penalty,30)})")

    # Version in server header
    server = sec.get("server", "") or ""
    if any(char.isdigit() for char in server):
        score += 5
        details.append(f"Server version disclosed ({server}) (+5)")

    powered_by = sec.get("x_powered_by", "") or ""
    if powered_by:
        score += 5
        details.append(f"X-Powered-By disclosed ({powered_by}) (+5)")

    # Cookie security
    for cookie in sec.get("cookies", []):
        if not cookie.get("secure"):
            score += 5
            details.append(f"Cookie '{cookie['name']}' missing Secure flag (+5)")
            break
        if not cookie.get("httponly"):
            score += 5
            details.append(f"Cookie '{cookie['name']}' missing HttpOnly flag (+5)")
            break

    # Sensitive files
    sensitive = result.get("sensitive_files", [])
    critical_files = [f for f in sensitive if f.get("critical")]
    if critical_files:
        penalty = len(critical_files) * 15
        score += min(penalty, 40)
        names = [f["path"] for f in critical_files]
        details.append(f"Critical sensitive files exposed: {', '.join(names[:3])} (+{min(penalty,40)})")
    elif sensitive:
        score += len(sensitive) * 3
        details.append(f"{len(sensitive)} files/paths accessible (+{len(sensitive)*3})")

    # Admin panels found
    admin_paths = [f for f in result.get("found_paths", [])
                   if any(a in f["path"] for a in ["/admin", "/phpmyadmin", "/wp-admin", "/manager"])]
    if admin_paths:
        score += 10
        details.append(f"Admin panels found: {[p['path'] for p in admin_paths[:3]]} (+10)")

    return min(score, 100), details


def _display_results(result: dict) -> None:
    # Security headers
    sec = result.get("security_headers", {})
    if sec:
        header_score = sec.get("score", 0)
        score_color = "green" if header_score >= 70 else ("yellow" if header_score >= 40 else "red")
        console.print(f"\n[bold]Security Header Score:[/] [{score_color}]{header_score}/100[/]")
        console.print(f"[bold]Server:[/] {sec.get('server', 'N/A')} | "
                     f"[bold]X-Powered-By:[/] {sec.get('x_powered_by', 'N/A') or 'N/A'}")

        if sec.get("present"):
            present_rows = [
                (h, v.get("value", "")[:60]) for h, v in sec["present"].items()
            ]
            print_result_table("Present Security Headers", present_rows, ["Header", "Value"])

        if sec.get("missing"):
            t = Table(title="Missing Security Headers", box=box.ROUNDED, header_style="bold red")
            t.add_column("Header")
            t.add_column("Critical")
            t.add_column("Recommended")
            for m in sec["missing"]:
                crit = "[red]YES[/]" if m.get("critical") else "No"
                t.add_row(m["header"], crit, m.get("recommended", "")[:50])
            console.print(t)

        # Cookies
        if sec.get("cookies"):
            for cookie in sec["cookies"][:5]:
                flags = []
                if not cookie.get("secure"):
                    flags.append("[red]Missing Secure[/]")
                if not cookie.get("httponly"):
                    flags.append("[red]Missing HttpOnly[/]")
                if flags:
                    console.print(f"  Cookie [cyan]{cookie['name']}[/]: {', '.join(flags)}")

    # CMS
    cms = result.get("cms", {})
    if cms.get("detected"):
        version_str = f" v{cms.get('version')}" if cms.get("version") else ""
        console.print(f"\n[bold]CMS Detected:[/] [cyan]{cms.get('detected')}{version_str}[/] "
                     f"(confidence: {cms.get('confidence', 0)})")

    # Sensitive files
    sensitive = result.get("sensitive_files", [])
    if sensitive:
        t = Table(title=f"Sensitive Files Found ({len(sensitive)})", box=box.ROUNDED,
                  header_style="bold red")
        t.add_column("Path")
        t.add_column("Status")
        t.add_column("Size")
        t.add_column("Critical")
        for f in sensitive:
            crit_color = "red" if f.get("critical") else "yellow"
            t.add_row(
                f["path"],
                str(f["status"]),
                f"{f.get('size', 0):,}b",
                f"[{crit_color}]{'YES' if f.get('critical') else 'No'}[/]",
            )
        console.print(t)

    # Fuzzed paths
    found_paths = result.get("found_paths", [])
    if found_paths:
        t = Table(title=f"Found Paths ({len(found_paths)})", box=box.ROUNDED,
                  header_style="bold green")
        t.add_column("Status", width=6)
        t.add_column("Path")
        t.add_column("Note")
        for p in found_paths[:30]:
            status_color = {200: "green", 403: "yellow", 301: "blue", 302: "blue"}.get(
                p["status"], "white"
            )
            t.add_row(
                f"[{status_color}]{p['status']}[/]",
                p["path"],
                p.get("note", ""),
            )
        console.print(t)
    else:
        print_success("No interesting paths found in fuzzing")

    from utils.output import print_risk_score
    print_risk_score(result.get("risk_score", 0))
    if result.get("risk_details"):
        console.print("[bold]Risk Factors:[/]")
        for d in result.get("risk_details", []):
            console.print(f"  [yellow]•[/] {d}")


def run():
    print_section("Web Scanner", "🌍")
    console.print("\nOptions:")
    console.print("1. Full scan (headers + CMS + sensitive files + fuzzing)")
    console.print("2. Security headers check only")
    console.print("3. Sensitive files scan only")
    console.print("4. Directory fuzzing only")
    choice = console.input("\n[bold]>[/] ").strip()
    if choice not in ("1", "2", "3", "4"):
        print_error("Invalid option")
        return

    url = console.input("[bold]Target URL:[/] ").strip()
    if not url:
        print_error("No URL provided")
        return

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Las opciones 1, 3 y 4 hacen cientos de peticiones al objetivo.
    if choice != "2" and not confirm_authorized("Escaneo web activo", url):
        print_error("Escaneo cancelado: se necesita autorización.")
        return

    result = {}

    if choice == "1":
        result = scan_web(url)
    elif choice == "2":
        result["security_headers"] = check_security_headers(url)
        _display_header_results(result["security_headers"])
    elif choice == "3":
        found = scan_sensitive_files(url)
        result["sensitive_files"] = found
        console.print(f"\n[bold]Found {len(found)} sensitive files[/]")
        for f in found:
            console.print(f"  {'[red]CRITICAL[/]' if f.get('critical') else '[yellow]INFO[/]'} "
                         f"{f['path']} ({f['status']})")
    elif choice == "4":
        found = fuzz_directories(url)
        result["found_paths"] = found
        console.print(f"\n[bold]Found {len(found)} paths[/]")
        for p in found[:20]:
            console.print(f"  [{p['status']}] {p['path']} — {p.get('note', '')}")

    if result:
        export = console.input("\n[bold]Export results? (json/txt/html/all/no):[/] ").strip().lower()
        if export and export != "no":
            formats = ["json", "txt", "html"] if export == "all" else [export]
            saved = save_results("web", url, result, formats)
            for fmt, p in saved.items():
                console.print(f"[green]Saved {fmt.upper()}:[/] {p}")


def _display_header_results(sec: dict) -> None:
    if not sec:
        return
    header_score = sec.get("score", 0)
    score_color = "green" if header_score >= 70 else ("yellow" if header_score >= 40 else "red")
    console.print(f"\n[bold]Security Header Score:[/] [{score_color}]{header_score}/100[/]")
    for h, v in sec.get("present", {}).items():
        console.print(f"  [green]✓[/] {h}: {str(v.get('value', ''))[:60]}")
    for m in sec.get("missing", []):
        crit = "[red](CRITICAL)[/]" if m.get("critical") else ""
        console.print(f"  [red]✗[/] {m['header']} {crit}")
