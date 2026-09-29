"""
CyberSword - OSINT Module
Google Dorks, HaveIBeenPwned, username search, EXIF, reverse image search.
"""

from pathlib import Path
from typing import Optional
from urllib.parse import quote

try:
    import exifread
    EXIFREAD_AVAILABLE = True
except ImportError:
    EXIFREAD_AVAILABLE = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

from rich.console import Console
from rich.table import Table
from rich import box

from utils.helpers import (
    is_valid_email, log_analysis, safe_get, make_session
)
from utils.output import (
    print_section, print_result_table, print_error,
    print_warning, print_success, save_results
)
from utils.api_manager import hibp_check_email

console = Console()

SOCIAL_PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{}", "check": True},
    {"name": "Twitter/X", "url": "https://twitter.com/{}", "check": True},
    {"name": "Instagram", "url": "https://www.instagram.com/{}/", "check": True},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{}", "check": False},
    {"name": "Facebook", "url": "https://www.facebook.com/{}", "check": False},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}", "check": True},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "check": True},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}", "check": True},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}", "check": True},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}", "check": True},
    {"name": "Telegram", "url": "https://t.me/{}", "check": True},
    {"name": "Discord", "url": "https://discord.com/users/{}", "check": False},
    {"name": "Keybase", "url": "https://keybase.io/{}", "check": True},
    {"name": "Pastebin", "url": "https://pastebin.com/u/{}", "check": True},
    {"name": "Gitlab", "url": "https://gitlab.com/{}", "check": True},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "check": True},
    {"name": "Medium", "url": "https://medium.com/@{}", "check": True},
    {"name": "Dev.to", "url": "https://dev.to/{}", "check": True},
    {"name": "DockerHub", "url": "https://hub.docker.com/u/{}", "check": True},
    {"name": "NPM", "url": "https://www.npmjs.com/~{}", "check": True},
    {"name": "PyPI", "url": "https://pypi.org/user/{}", "check": True},
    {"name": "Gravatar", "url": "https://gravatar.com/{}", "check": True},
    {"name": "Fiverr", "url": "https://www.fiverr.com/{}", "check": True},
    {"name": "Upwork", "url": "https://www.upwork.com/freelancers/~{}", "check": False},
]

DORK_TEMPLATES = {
    "email": [
        '"{email}"',
        '"{email}" site:linkedin.com',
        '"{email}" site:github.com',
        '"{email}" filetype:pdf',
        '"{email}" pastebin',
        '"{email}" breach OR leak OR hacked',
        'intext:"{email}"',
    ],
    "name": [
        '"{name}"',
        '"{name}" site:linkedin.com',
        '"{name}" site:facebook.com',
        '"{name}" site:twitter.com',
        '"{name}" resume OR CV',
        '"{name}" contact OR email',
        '"{name}" phone OR tel',
    ],
    "company": [
        'site:{domain}',
        'site:{domain} filetype:pdf',
        'site:{domain} filetype:xls OR filetype:xlsx',
        'site:{domain} inurl:admin',
        'site:{domain} password OR passwd OR pwd',
        'site:{domain} confidential OR internal',
        'site:{domain} "index of /"',
        '"{company}" employees site:linkedin.com',
        '"{company}" leak OR breach',
    ],
    "phone": [
        '"{phone}"',
        '"{phone}" spam OR scam OR complaints',
        '"{phone}" site:truecaller.com',
        '"{phone}" name OR owner',
    ],
}


def osint_email(email: str) -> dict:
    """Full OSINT on an email address."""
    print_section("Email OSINT", "🔍")
    console.print(f"\n[bold]Target:[/] [cyan]{email}[/]")

    if not is_valid_email(email):
        print_error(f"Invalid email format: {email}")
        return {}

    result = {"email": email}

    with console.status("[bold green]Checking HaveIBeenPwned..."):
        result["breaches"] = _check_breaches(email)

    result["dorks"] = _generate_email_dorks(email)
    result["username_hint"] = email.split("@")[0]
    result["domain"] = email.split("@")[1]

    # Gravatar check
    with console.status("[bold green]Checking Gravatar..."):
        result["gravatar"] = _check_gravatar(email)

    _display_email_osint(result)
    log_analysis("osint_email", email, result)
    return result


def osint_username(username: str) -> dict:
    """Search username across social platforms."""
    print_section("Username OSINT", "🔍")
    console.print(f"\n[bold]Searching username:[/] [cyan]{username}[/]")

    result = {"username": username, "found": [], "not_found": [], "error": []}

    with console.status(f"[bold green]Checking {len(SOCIAL_PLATFORMS)} platforms..."):
        sess = make_session()
        for platform in SOCIAL_PLATFORMS:
            if not platform.get("check"):
                result["found"].append({
                    "platform": platform["name"],
                    "url": platform["url"].format(username),
                    "status": "not_checked",
                })
                continue
            url = platform["url"].format(username)
            try:
                resp = sess.get(url, timeout=10, allow_redirects=True)
                if resp.status_code == 200:
                    # Basic heuristic: check if profile page exists
                    if _profile_seems_valid(resp.text, username, platform["name"]):
                        result["found"].append({
                            "platform": platform["name"],
                            "url": url,
                            "status": "found",
                        })
                    else:
                        result["not_found"].append(platform["name"])
                elif resp.status_code == 404:
                    result["not_found"].append(platform["name"])
                else:
                    result["error"].append(platform["name"])
            except Exception:
                result["error"].append(platform["name"])

    result["dorks"] = [
        {"query": f'"{username}" social media profiles', "url": f'https://www.google.com/search?q="{quote(username)}"+social+media'},
        {"query": f'site:github.com "{username}"', "url": f'https://www.google.com/search?q=site:github.com+"{quote(username)}"'},
        {"query": f'"@{username}"', "url": f'https://www.google.com/search?q="%40{quote(username)}"'},
    ]

    _display_username_osint(result)
    log_analysis("osint_username", username, result)
    return result


def osint_person(name: str, extras: dict = None) -> dict:
    """Generate OSINT dorks for a person."""
    print_section("Person OSINT", "🔍")
    console.print(f"\n[bold]Target:[/] [cyan]{name}[/]")

    result = {"name": name, "extras": extras or {}}
    result["dorks"] = _generate_person_dorks(name, extras or {})

    _display_person_osint(result)
    log_analysis("osint_person", name, result)
    return result


def analyze_image_metadata(image_path: str) -> dict:
    """Extract and analyze EXIF metadata from images."""
    print_section("Image Metadata (EXIF)", "🖼")
    console.print(f"\n[bold]Analyzing:[/] [cyan]{image_path}[/]")

    p = Path(image_path)
    if not p.exists():
        print_error(f"File not found: {image_path}")
        return {}

    result = {"file": image_path, "exif": {}, "exif_raw": {}, "gps": {}, "warnings": []}

    # Pillow EXIF
    if PIL_AVAILABLE:
        try:
            img = Image.open(p)
            result["format"] = img.format
            result["mode"] = img.mode
            result["size"] = f"{img.size[0]}x{img.size[1]}"

            exif_data = img._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if tag == "GPSInfo":
                        gps = {}
                        for gps_tag, gps_val in value.items():
                            gps_name = GPSTAGS.get(gps_tag, gps_tag)
                            gps[gps_name] = str(gps_val)
                        result["gps"] = gps
                        # Convert to decimal degrees
                        coords = _gps_to_decimal(value)
                        if coords:
                            result["gps_decimal"] = coords
                            result["google_maps"] = f"https://maps.google.com/?q={coords[0]},{coords[1]}"
                    elif isinstance(value, bytes):
                        continue
                    else:
                        result["exif"][str(tag)] = str(value)[:200]
        except Exception as e:
            result["warnings"].append(f"PIL error: {e}")

    # exifread fallback
    if EXIFREAD_AVAILABLE:
        try:
            with open(p, "rb") as f:
                tags = exifread.process_file(f, details=True)
            for tag, val in tags.items():
                if "GPS" in tag:
                    result["exif_raw"][tag] = str(val)
                elif tag not in result["exif"]:
                    result["exif"][tag] = str(val)[:200]
        except Exception:
            pass

    # Identify sensitive fields
    sensitive_fields = [
        "Make", "Model", "Software", "DateTime", "DateTimeOriginal",
        "Artist", "Copyright", "ImageDescription", "UserComment",
        "XPComment", "XPAuthor", "XPTitle", "XPKeywords",
    ]
    result["sensitive"] = {
        k: v for k, v in result.get("exif", {}).items()
        if any(sf.lower() in k.lower() for sf in sensitive_fields)
    }

    if result.get("gps_decimal"):
        result["warnings"].append("⚠ Image contains GPS coordinates — location is embedded!")

    if result.get("exif"):
        camera = result["exif"].get("Model", result["exif"].get("Make", ""))
        if camera:
            result["warnings"].append(f"Camera model embedded: {camera}")

    result["reverse_search_links"] = {
        "Google Images": "https://images.google.com/searchbyimage (upload manually)",
        "TinEye": "https://www.tineye.com/ (upload manually)",
        "Yandex Images": "https://yandex.com/images/ (upload manually)",
        "Bing Visual Search": "https://www.bing.com/visualsearch (upload manually)",
    }

    _display_exif_results(result)
    log_analysis("osint_image", image_path, result)
    return result


def _check_breaches(email: str) -> dict:
    breaches = hibp_check_email(email)
    result = {"found": False, "count": 0, "breaches": []}

    if breaches is None:
        result["error"] = "Could not reach HaveIBeenPwned (API key required)"
        return result

    if isinstance(breaches, dict) and "error" in breaches:
        result["error"] = breaches["error"]
        return result

    if isinstance(breaches, list) and breaches:
        result["found"] = True
        result["count"] = len(breaches)
        for b in breaches:
            result["breaches"].append({
                "name": b.get("Name", ""),
                "domain": b.get("Domain", ""),
                "breach_date": b.get("BreachDate", ""),
                "pwn_count": b.get("PwnCount", 0),
                "data_classes": b.get("DataClasses", []),
                "is_verified": b.get("IsVerified", False),
                "is_sensitive": b.get("IsSensitive", False),
            })

    return result


def _check_gravatar(email: str) -> dict:
    import hashlib
    # Gravatar's public lookup protocol is keyed by MD5.
    email_hash = hashlib.md5(
        email.lower().encode(), usedforsecurity=False
    ).hexdigest()
    url = f"https://www.gravatar.com/{email_hash}.json"
    try:
        resp = safe_get(url, timeout=10)
        if resp and resp.status_code == 200:
            data = resp.json()
            entry = data.get("entry", [{}])[0]
            return {
                "has_gravatar": True,
                "display_name": entry.get("displayName", ""),
                "username": entry.get("preferredUsername", ""),
                "avatar_url": f"https://www.gravatar.com/avatar/{email_hash}?d=404",
                "profile_url": entry.get("profileUrl", ""),
                "about": entry.get("aboutMe", ""),
                "accounts": [a.get("shortname", "") for a in entry.get("accounts", [])],
            }
    except Exception:
        pass
    return {"has_gravatar": False}


def _generate_email_dorks(email: str) -> list:
    dorks = []
    for template in DORK_TEMPLATES["email"]:
        query = template.format(email=email)
        dorks.append({
            "query": query,
            "url": f"https://www.google.com/search?q={quote(query)}",
        })
    return dorks


def _generate_person_dorks(name: str, extras: dict) -> list:
    dorks = []
    for template in DORK_TEMPLATES["name"]:
        query = template.format(name=name)
        dorks.append({
            "query": query,
            "url": f"https://www.google.com/search?q={quote(query)}",
        })

    if extras.get("company"):
        company = extras["company"]
        domain = extras.get("domain", "")
        for template in DORK_TEMPLATES["company"]:
            query = template.format(company=company, domain=domain or company)
            dorks.append({
                "query": query,
                "url": f"https://www.google.com/search?q={quote(query)}",
            })

    return dorks


def _profile_seems_valid(html: str, username: str, platform: str) -> bool:
    """Heuristic check if profile page actually exists (not a 'user not found' page)."""
    not_found_patterns = [
        "page not found", "user not found", "no user", "doesn't exist",
        "404", "account suspended", "this account doesn't exist",
        "sorry, this page", "user is not found",
    ]
    html_lower = html.lower()[:5000]
    if any(p in html_lower for p in not_found_patterns):
        return False
    if username.lower() in html_lower:
        return True
    return False


def _gps_to_decimal(gps_info: dict) -> Optional[tuple]:
    try:
        from PIL.ExifTags import GPSTAGS
        def _convert(value):
            d = float(value[0])
            m = float(value[1]) / 60
            s = float(value[2]) / 3600
            return d + m + s

        lat_tag = next((k for k, v in GPSTAGS.items() if v == "GPSLatitude"), None)
        lon_tag = next((k for k, v in GPSTAGS.items() if v == "GPSLongitude"), None)
        lat_ref_tag = next((k for k, v in GPSTAGS.items() if v == "GPSLatitudeRef"), None)
        lon_ref_tag = next((k for k, v in GPSTAGS.items() if v == "GPSLongitudeRef"), None)

        if lat_tag and lon_tag and lat_tag in gps_info and lon_tag in gps_info:
            lat = _convert(gps_info[lat_tag])
            lon = _convert(gps_info[lon_tag])
            if gps_info.get(lat_ref_tag, "N") != "N":
                lat = -lat
            if gps_info.get(lon_ref_tag, "E") != "E":
                lon = -lon
            return (round(lat, 6), round(lon, 6))
    except Exception:
        pass
    return None


def _display_email_osint(result: dict) -> None:
    # Breaches
    breaches = result.get("breaches", {})
    if breaches.get("error"):
        print_warning(f"HaveIBeenPwned: {breaches['error']}")
    elif breaches.get("found"):
        console.print(f"\n[bold red]⚠ FOUND IN {breaches['count']} DATA BREACHES![/]")
        for b in breaches.get("breaches", [])[:10]:
            console.print(f"  [red]•[/] [bold]{b['name']}[/] ({b.get('breach_date', '')}) — "
                         f"{b.get('pwn_count', 0):,} accounts — "
                         f"Data: {', '.join(b.get('data_classes', [])[:4])}")
    else:
        print_success("Not found in any known data breaches (HaveIBeenPwned)")

    # Gravatar
    gravatar = result.get("gravatar", {})
    if gravatar.get("has_gravatar"):
        grav_rows = [
            ("Display Name", gravatar.get("display_name", "")),
            ("Username", gravatar.get("username", "")),
            ("Avatar", gravatar.get("avatar_url", "")),
            ("Profile", gravatar.get("profile_url", "")),
            ("About", gravatar.get("about", "")[:100]),
            ("Linked Accounts", ", ".join(gravatar.get("accounts", []))),
        ]
        print_result_table("Gravatar Profile Found", [(r[0], r[1]) for r in grav_rows if r[1]])

    # Dorks
    console.print("\n[bold]Google Dork Links:[/]")
    for d in result.get("dorks", [])[:5]:
        console.print(f"  [blue]•[/] {d['url']}")


def _display_username_osint(result: dict) -> None:
    found = result.get("found", [])
    not_found = result.get("not_found", [])

    if found:
        t = Table(title=f"Profiles Found ({len(found)})", box=box.ROUNDED,
                  header_style="bold green")
        t.add_column("Platform")
        t.add_column("URL")
        t.add_column("Status")
        for f in found:
            status_color = "green" if f.get("status") == "found" else "blue"
            t.add_row(f["platform"], f["url"], f"[{status_color}]{f.get('status', '')}[/]")
        console.print(t)

    if not_found:
        console.print(f"\n[dim]Not found on: {', '.join(not_found)}[/]")

    console.print("\n[bold]Search Dorks:[/]")
    for d in result.get("dorks", []):
        console.print(f"  [blue]•[/] {d['url']}")


def _display_person_osint(result: dict) -> None:
    console.print(f"\n[bold]Dork queries for:[/] [cyan]{result.get('name')}[/]")
    console.print("\n[bold]Google Dork Links:[/]")
    for d in result.get("dorks", [])[:8]:
        console.print(f"  [blue]•[/] [dim]{d['query']}[/]")
        console.print(f"     {d['url']}")


def _display_exif_results(result: dict) -> None:
    console.print(f"\n[bold]File:[/] [cyan]{result.get('file')}[/]")

    if result.get("size"):
        console.print(f"[bold]Size:[/] {result.get('size')} | "
                     f"[bold]Format:[/] {result.get('format')} | "
                     f"[bold]Mode:[/] {result.get('mode')}")

    for w in result.get("warnings", []):
        console.print(f"[bold red]{w}[/]")

    exif = result.get("exif", {})
    if exif:
        rows = [(k, str(v)[:80]) for k, v in list(exif.items())[:30]]
        print_result_table("EXIF Metadata", rows)

    gps = result.get("gps", {})
    if gps:
        gps_rows = [(k, str(v)) for k, v in gps.items()]
        print_result_table("GPS Data", gps_rows)

    if result.get("gps_decimal"):
        lat, lon = result["gps_decimal"]
        console.print(f"\n[bold red]📍 GPS Coordinates:[/] {lat}, {lon}")
        console.print(f"[bold]Google Maps:[/] {result.get('google_maps')}")

    console.print("\n[bold]Reverse Image Search:[/]")
    for name, link in result.get("reverse_search_links", {}).items():
        console.print(f"  [blue]•[/] {name}: {link}")


def run():
    print_section("OSINT", "🔍")
    console.print("\nOSINT Options:")
    console.print("1. Email analysis + breach check")
    console.print("2. Username search (social networks)")
    console.print("3. Person/company dorks")
    console.print("4. Image metadata (EXIF)")
    choice = console.input("\n[bold]>[/] ").strip()

    if choice == "1":
        email = console.input("[bold]Email:[/] ").strip()
        result = osint_email(email)
        if result:
            export = console.input("[bold]Export? (json/html/all/no):[/] ").strip().lower()
            if export and export != "no":
                saved = save_results("osint_email", email, result,
                                    ["json", "txt", "html"] if export == "all" else [export])
                for fmt, path in saved.items():
                    console.print(f"[green]Saved {fmt.upper()}:[/] {path}")

    elif choice == "2":
        username = console.input("[bold]Username:[/] ").strip()
        result = osint_username(username)
        if result:
            export = console.input("[bold]Export? (json/html/all/no):[/] ").strip().lower()
            if export and export != "no":
                saved = save_results("osint_username", username, result,
                                    ["json", "txt", "html"] if export == "all" else [export])
                for fmt, path in saved.items():
                    console.print(f"[green]Saved {fmt.upper()}:[/] {path}")

    elif choice == "3":
        name = console.input("[bold]Full name or company:[/] ").strip()
        company = console.input("[bold]Company domain (optional):[/] ").strip()
        extras = {"company": name, "domain": company} if company else {}
        result = osint_person(name, extras)
        if result:
            export = console.input("[bold]Export? (json/html/all/no):[/] ").strip().lower()
            if export and export != "no":
                saved = save_results("osint_person", name, result,
                                    ["json", "txt", "html"] if export == "all" else [export])
                for fmt, path in saved.items():
                    console.print(f"[green]Saved {fmt.upper()}:[/] {path}")

    elif choice == "4":
        path = console.input("[bold]Image path:[/] ").strip()
        result = analyze_image_metadata(path)
        if result:
            export = console.input("[bold]Export? (json/html/all/no):[/] ").strip().lower()
            if export and export != "no":
                saved = save_results("osint_exif", path, result,
                                    ["json", "txt", "html"] if export == "all" else [export])
                for fmt, path in saved.items():
                    console.print(f"[green]Saved {fmt.upper()}:[/] {path}")
    else:
        print_error("Invalid option")
