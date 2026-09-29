"""
CyberSword - File Analyzer
Hash, VirusTotal, magic bytes, strings, PE headers, IOC extraction.
"""

import re
import hashlib
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

from utils.helpers import (
    extract_urls, extract_ips, extract_emails,
    extract_domains, log_analysis, human_size
)
from utils.output import (
    print_section, print_result_table, print_error,
    print_warning, print_success, save_results
)
from utils.api_manager import vt_file_report, malwarebazaar_hash

console = Console()

MAGIC_SIGNATURES = {
    b"\x4d\x5a": ("PE/EXE", "Windows Executable"),
    b"\x7f\x45\x4c\x46": ("ELF", "Linux/Unix Executable"),
    b"\xca\xfe\xba\xbe": ("Mach-O FAT", "macOS Universal Binary"),
    b"\xfe\xed\xfa\xce": ("Mach-O 32", "macOS 32-bit Executable"),
    b"\xfe\xed\xfa\xcf": ("Mach-O 64", "macOS 64-bit Executable"),
    b"\x50\x4b\x03\x04": ("ZIP", "ZIP Archive"),
    b"\x50\x4b\x05\x06": ("ZIP Empty", "Empty ZIP Archive"),
    b"\x52\x61\x72\x21": ("RAR", "RAR Archive"),
    b"\x37\x7a\xbc\xaf": ("7-Zip", "7-Zip Archive"),
    b"\x1f\x8b": ("GZIP", "GZip Compressed"),
    b"\x42\x5a\x68": ("BZIP2", "BZip2 Compressed"),
    b"\xfd\x37\x7a\x58": ("XZ", "XZ Compressed"),
    b"\x25\x50\x44\x46": ("PDF", "PDF Document"),
    b"\xff\xd8\xff": ("JPEG", "JPEG Image"),
    b"\x89\x50\x4e\x47": ("PNG", "PNG Image"),
    b"\x47\x49\x46\x38": ("GIF", "GIF Image"),
    b"\x42\x4d": ("BMP", "Windows Bitmap"),
    b"\x49\x49\x2a\x00": ("TIFF-LE", "TIFF Image"),
    b"\x4d\x4d\x00\x2a": ("TIFF-BE", "TIFF Image"),
    b"\xd0\xcf\x11\xe0": ("OLE2", "Microsoft Office (DOC/XLS/PPT)"),
    b"\x23\x21": ("Script", "Script (shebang)"),
    b"\x7b\x5c\x72\x74": ("RTF", "Rich Text Format"),
    b"\x3c\x3f\x78\x6d": ("XML", "XML Document"),
    b"\x3c\x68\x74\x6d": ("HTML", "HTML Document"),
    b"\x4d\x54\x68\x64": ("MIDI", "MIDI Audio"),
    b"\x49\x44\x33": ("MP3", "MP3 Audio"),
    b"\x66\x74\x79\x70": ("MP4/MOV", "Video"),
    b"\x52\x49\x46\x46": ("RIFF", "RIFF (WAV/AVI)"),
    b"\x00\x61\x73\x6d": ("WASM", "WebAssembly"),
    b"\xce\xfa\xed\xfe": ("Mach-O", "macOS Mach-O Reverse"),
}

SUSPICIOUS_STRINGS = [
    rb"CreateRemoteThread", rb"VirtualAlloc", rb"WriteProcessMemory",
    rb"NtCreateThread", rb"RtlCreateUserThread", rb"OpenProcess",
    rb"GetProcAddress", rb"LoadLibrary", rb"ShellExecute",
    rb"WScript\.Shell", rb"cmd\.exe", rb"powershell",
    rb"base64", rb"FromBase64String", rb"Invoke-Expression",
    rb"iex\(", rb"bypass", rb"ExecutionPolicy",
    rb"netcat", rb"nc\.exe", rb"meterpreter",
    rb"/bin/sh", rb"/bin/bash", rb"wget\s+http",
    rb"curl\s+http", rb"chmod\s+\+x",
    rb"download.*http", rb"DownloadFile", rb"DownloadString",
    rb"System\.Net\.WebClient", rb"System\.Reflection",
    rb"eval\s*\(", rb"exec\s*\(", rb"system\s*\(",
    rb"passw", rb"password", rb"secret", rb"api_key",
    rb"HKEY_", rb"RegOpenKey", rb"RegSetValue",
    rb"CreateService", rb"StartService",
    rb"SetWindowsHookEx", rb"GetAsyncKeyState",  # Keylogger
    rb"connect\(", rb"socket\(", rb"recv\(", rb"send\(",
    rb"encrypt", rb"decrypt", rb"ransom",
    rb"bitcoin", rb"monero", rb"wallet",
]

OBFUSCATION_INDICATORS = [
    rb"[A-Za-z0-9+/]{200,}={0,2}",  # Long base64
    rb"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){20,}",  # Hex escape sequences
    rb"\%[0-9a-fA-F]{2}(\%[0-9a-fA-F]{2}){20,}",  # URL encoding
    rb"chr\(\d+\)\s*\+\s*chr\(\d+\)",  # Chr concatenation (VBScript)
    rb"String\.fromCharCode\(",  # JS charcode
]


def analyze_file(file_path: str) -> dict:
    """Complete file analysis."""
    print_section("File Analyzer", "📁")

    p = Path(file_path).expanduser()
    if not p.is_file():
        print_error(f"File not found (or not a regular file): {file_path}")
        return {}

    console.print(f"\n[bold]Analyzing:[/] [cyan]{p}[/]")
    result = {"file": str(p), "name": p.name}

    with console.status("[bold green]Hashing..."):
        result["hashes"] = _hash_file(p)

    with console.status("[bold green]Identifying file type..."):
        result["file_type"] = _identify_type(p)

    # El contenido se lee una sola vez y con límite: antes se leía entero cuatro veces.
    data, truncated = _read_for_scan(p)
    if truncated:
        result["scan_truncated"] = f"Only the first {MAX_SCAN_BYTES // (1024 * 1024)} MB were scanned for content"

    with console.status("[bold green]Extracting strings..."):
        result["strings"] = _extract_strings(data)

    with console.status("[bold green]Scanning for IOCs..."):
        result["iocs"] = _extract_iocs(data)

    with console.status("[bold green]Checking for suspicious patterns..."):
        result["suspicious"] = _check_suspicious(data)
        result["obfuscation"] = _check_obfuscation(data)

    # PE analysis if applicable
    if result["file_type"].get("type") == "PE/EXE":
        with console.status("[bold green]Analyzing PE headers..."):
            result["pe"] = _analyze_pe(p)

    # VirusTotal
    sha256 = result["hashes"].get("sha256", "")
    if sha256:
        with console.status("[bold green]Checking VirusTotal..."):
            result["virustotal"] = _check_virustotal(sha256)

        with console.status("[bold green]Checking MalwareBazaar..."):
            result["malwarebazaar"] = _check_malwarebazaar(sha256)

    result["risk_score"], result["risk_details"] = _calculate_risk(result)

    _display_results(result)
    log_analysis("file", file_path, result)

    return result


def _hash_file(p: Path) -> dict:
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    size = 0

    with open(p, "rb") as f:
        while chunk := f.read(65536):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    return {
        "size": size,
        "size_human": human_size(size),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
    }


def _identify_type(p: Path) -> dict:
    result = {"type": "unknown", "description": "", "extension": p.suffix.lower()}

    with open(p, "rb") as f:
        header = f.read(32)

    # Check magic signatures
    for signature, (type_name, desc) in MAGIC_SIGNATURES.items():
        if header[:len(signature)] == signature:
            result["type"] = type_name
            result["description"] = desc
            break

    # Fallback: python-magic
    if MAGIC_AVAILABLE and result["type"] == "unknown":
        try:
            result["magic_lib"] = magic.from_file(str(p))
            result["mime"] = magic.from_file(str(p), mime=True)
        except Exception:
            pass

    # Check extension mismatch
    ext = p.suffix.lower()
    type_ext_map = {
        "PE/EXE": [".exe", ".dll", ".scr", ".com"],
        "ELF": ["", ".elf", ".so", ".bin"],
        "PDF": [".pdf"],
        "JPEG": [".jpg", ".jpeg"],
        "PNG": [".png"],
        "GIF": [".gif"],
        "ZIP": [".zip", ".docx", ".xlsx", ".pptx", ".apk", ".jar"],
        "RAR": [".rar"],
        "GZIP": [".gz", ".tgz"],
        "OLE2": [".doc", ".xls", ".ppt"],
        "Mach-O 64": ["", ".dylib", ".bin"],
        "Mach-O 32": ["", ".dylib"],
    }
    expected_exts = type_ext_map.get(result["type"], [ext])
    result["extension_mismatch"] = ext not in expected_exts and ext != "" and expected_exts != [ext]

    return result


MAX_SCAN_BYTES = 50 * 1024 * 1024


def _read_for_scan(p: Path) -> tuple[bytes, bool]:
    """Contenido para los análisis de texto, limitado a MAX_SCAN_BYTES (los hashes usan el archivo completo)."""
    with open(p, "rb") as f:
        data = f.read(MAX_SCAN_BYTES + 1)
    return data[:MAX_SCAN_BYTES], len(data) > MAX_SCAN_BYTES


def _extract_strings(data: bytes, min_length: int = 6, max_count: int = 200) -> dict:
    """Extract printable ASCII and Unicode strings."""
    ascii_strings = re.findall(rb"[ -~]{%d,}" % min_length, data)
    unicode_strings = re.findall(rb"(?:[ -~]\x00){%d,}" % min_length, data)

    ascii_decoded = [s.decode("ascii", errors="replace") for s in ascii_strings[:max_count]]
    unicode_decoded = [
        s.decode("utf-16-le", errors="replace").rstrip("\x00")
        for s in unicode_strings[:50]
    ]

    return {
        "ascii_count": len(ascii_strings),
        "unicode_count": len(unicode_strings),
        "ascii_sample": ascii_decoded[:50],
        "unicode_sample": unicode_decoded[:20],
    }


def _extract_iocs(data: bytes) -> dict:
    text = data.decode("utf-8", errors="replace")

    return {
        "urls": extract_urls(text)[:20],
        "ips": extract_ips(text)[:20],
        "emails": extract_emails(text)[:20],
        "domains": [d for d in extract_domains(text) if len(d) > 4][:20],
    }


def _check_suspicious(data: bytes) -> list:
    found = []
    for pattern in SUSPICIOUS_STRINGS:
        matches = re.findall(pattern, data, re.IGNORECASE)
        if matches:
            found.append({
                "pattern": pattern.decode("ascii", errors="replace"),
                "count": len(matches),
                "sample": matches[0].decode("ascii", errors="replace")[:60],
            })

    return found


def _check_obfuscation(data: bytes) -> list:
    indicators = []
    for pattern in OBFUSCATION_INDICATORS:
        if re.search(pattern, data):
            indicators.append(pattern.decode("ascii", errors="replace")[:50])

    # Entropy check (high entropy = possible packing/encryption)
    entropy = _calculate_entropy(data[:65536])
    if entropy > 7.5:
        indicators.append(f"High entropy ({entropy:.2f}/8.0) — possible packing or encryption")

    return indicators


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())


def _analyze_pe(p: Path) -> dict:
    if not PEFILE_AVAILABLE:
        return {"error": "pefile not available — pip install pefile"}

    try:
        pe = pefile.PE(str(p))
        result = {}

        # Machine type
        machine_map = {
            0x014c: "x86 (32-bit)",
            0x8664: "x64 (64-bit)",
            0x01c4: "ARM",
            0xaa64: "ARM64",
        }
        result["machine"] = machine_map.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))

        # Timestamps
        import datetime
        ts = pe.FILE_HEADER.TimeDateStamp
        result["compile_time"] = str(datetime.datetime.utcfromtimestamp(ts))

        # Sections
        result["sections"] = []
        for section in pe.sections:
            name = section.Name.decode("ascii", errors="replace").rstrip("\x00")
            entropy = section.get_entropy()
            result["sections"].append({
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "size": section.SizeOfRawData,
                "entropy": round(entropy, 2),
                "suspicious_entropy": entropy > 7.0,
            })

        # Imports
        result["imports"] = {}
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for imp in pe.DIRECTORY_ENTRY_IMPORT[:20]:
                dll = imp.dll.decode("ascii", errors="replace")
                funcs = []
                for func in imp.imports[:20]:
                    if func.name:
                        funcs.append(func.name.decode("ascii", errors="replace"))
                result["imports"][dll] = funcs

        # Exports
        result["exports"] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:20]:
                if exp.name:
                    result["exports"].append(exp.name.decode("ascii", errors="replace"))

        # Characteristics
        result["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        result["is_exe"] = bool(pe.FILE_HEADER.Characteristics & 0x0002)
        result["is_64bit"] = pe.FILE_HEADER.Machine == 0x8664

        # Checksum
        result["checksum_valid"] = pe.verify_checksum()
        result["subsystem"] = pe.OPTIONAL_HEADER.Subsystem

        pe.close()
        return result

    except Exception as e:
        return {"error": str(e)}


def _check_virustotal(sha256: str) -> dict:
    vt = vt_file_report(sha256)
    if not vt:
        return {"info": "No VT response"}
    if "error" in vt:
        return {"info": vt["error"]}

    attrs = vt.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "type_description": attrs.get("type_description", ""),
        "name": attrs.get("meaningful_name", ""),
        "popular_threat_classification": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
    }


def _check_malwarebazaar(sha256: str) -> dict:
    data = malwarebazaar_hash(sha256)
    if not data:
        return {"info": "No response"}
    if "error" in data:
        return {"info": data["error"]}
    status = data.get("query_status", "")
    if status == "no_results":
        return {"found": False}
    if status == "ok":
        info = data.get("data", [{}])[0]
        return {
            "found": True,
            "file_name": info.get("file_name", ""),
            "file_type": info.get("file_type", ""),
            "signature": info.get("signature", ""),
            "tags": info.get("tags", []),
            "first_seen": info.get("first_seen", ""),
            "last_seen": info.get("last_seen", ""),
            "vendor_intel": list(info.get("vendor_intel", {}).keys())[:5],
        }
    return {"status": status}


def _calculate_risk(result: dict) -> tuple[int, list]:
    score = 0
    details = []

    # VirusTotal
    vt = result.get("virustotal", {})
    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    if malicious > 0:
        score += min(malicious * 5, 50)
        details.append(f"VirusTotal: {malicious} malicious detections (+{min(malicious*5,50)})")
    if suspicious > 0:
        score += min(suspicious * 2, 20)
        details.append(f"VirusTotal: {suspicious} suspicious detections (+{min(suspicious*2,20)})")

    # MalwareBazaar
    mb = result.get("malwarebazaar", {})
    if mb.get("found"):
        score += 40
        details.append(f"Found in MalwareBazaar ({mb.get('signature', 'unknown')}) (+40)")

    # File type mismatch
    ft = result.get("file_type", {})
    if ft.get("extension_mismatch"):
        score += 20
        details.append(f"File extension mismatch (detected: {ft.get('type')}) (+20)")

    # Suspicious strings
    suspicious_strings = result.get("suspicious", [])
    if suspicious_strings:
        count = len(suspicious_strings)
        score += min(count * 3, 25)
        details.append(f"{count} suspicious string patterns found (+{min(count*3,25)})")

    # Obfuscation
    obfuscation = result.get("obfuscation", [])
    if obfuscation:
        score += 15
        details.append(f"Obfuscation/packing indicators: {obfuscation[0][:50]} (+15)")

    # PE sections with high entropy
    pe = result.get("pe", {})
    high_entropy_sections = [
        s for s in pe.get("sections", []) if s.get("suspicious_entropy")
    ]
    if high_entropy_sections:
        score += 15
        details.append(f"{len(high_entropy_sections)} PE section(s) with suspicious entropy (+15)")

    # IOCs embedded
    iocs = result.get("iocs", {})
    all_iocs = (len(iocs.get("urls", [])) + len(iocs.get("ips", [])) +
                len(iocs.get("emails", [])))
    if all_iocs > 10:
        score += 10
        details.append(f"{all_iocs} network IOCs embedded in file (+10)")

    return min(score, 100), details


def _display_results(result: dict) -> None:
    hashes = result.get("hashes", {})
    if hashes:
        hash_rows = [
            ("Size", f"{hashes.get('size', 0):,} bytes ({hashes.get('size_human', '')})"),
            ("MD5", hashes.get("md5", "")),
            ("SHA1", hashes.get("sha1", "")),
            ("SHA256", hashes.get("sha256", "")),
            ("SHA512", hashes.get("sha512", "")[:64] + "..."),
        ]
        print_result_table("File Hashes", hash_rows)

    ft = result.get("file_type", {})
    type_color = "red" if ft.get("extension_mismatch") else "white"
    ft_rows = [
        ("Detected Type", f"[{type_color}]{ft.get('type', '')}[/]"),
        ("Description", ft.get("description", "")),
        ("Extension", ft.get("extension", "")),
        ("Extension Mismatch", "[red]YES[/]" if ft.get("extension_mismatch") else "No"),
    ]
    if ft.get("magic_lib"):
        ft_rows.append(("Magic", ft.get("magic_lib", "")))
    print_result_table("File Type", ft_rows)

    # VirusTotal
    vt = result.get("virustotal", {})
    if "malicious" in vt:
        m = vt.get("malicious", 0)
        color = "red" if m > 0 else "green"
        vt_rows = [
            ("Malicious", f"[{color}]{m}[/]"),
            ("Suspicious", str(vt.get("suspicious", 0))),
            ("Harmless", str(vt.get("harmless", 0))),
            ("Type", vt.get("type_description", "")),
            ("Threat", vt.get("popular_threat_classification", "")),
        ]
        print_result_table("VirusTotal", [(r[0], r[1]) for r in vt_rows if r[1]])
    elif vt.get("info"):
        print_warning(f"VirusTotal: {vt['info']}")

    # MalwareBazaar
    mb = result.get("malwarebazaar", {})
    if mb.get("found"):
        console.print("\n[bold red]⚠ FOUND IN MALWAREBAZAAR![/]")
        mb_rows = [
            ("Name", mb.get("file_name", "")),
            ("Type", mb.get("file_type", "")),
            ("Signature", mb.get("signature", "")),
            ("Tags", ", ".join(mb.get("tags", []))),
            ("First Seen", mb.get("first_seen", "")),
        ]
        print_result_table("MalwareBazaar", [(r[0], r[1]) for r in mb_rows if r[1]])
    elif mb.get("found") is False:
        print_success("Not found in MalwareBazaar")

    # Suspicious strings
    suspicious = result.get("suspicious", [])
    if suspicious:
        console.print(f"\n[bold red]⚠ {len(suspicious)} suspicious patterns found![/]")
        t = Table(box=box.SIMPLE, header_style="bold red")
        t.add_column("Pattern")
        t.add_column("Count")
        t.add_column("Sample")
        for s in suspicious[:15]:
            t.add_row(s.get("pattern", "")[:40], str(s.get("count")), s.get("sample", "")[:50])
        console.print(t)

    # Obfuscation
    obfuscation = result.get("obfuscation", [])
    if obfuscation:
        console.print("\n[bold yellow]⚠ Obfuscation/packing indicators:[/]")
        for ind in obfuscation:
            console.print(f"  [yellow]•[/] {ind}")

    # PE info
    pe = result.get("pe", {})
    if pe and "error" not in pe:
        pe_rows = [
            ("Architecture", pe.get("machine", "")),
            ("Compile Time", pe.get("compile_time", "")),
            ("Is DLL", "[yellow]Yes[/]" if pe.get("is_dll") else "No"),
            ("Checksum Valid", "[green]Yes[/]" if pe.get("checksum_valid") else "[red]No[/]"),
            ("Sections", str(len(pe.get("sections", [])))),
        ]
        print_result_table("PE Header", pe_rows)

        high_ent = [s for s in pe.get("sections", []) if s.get("suspicious_entropy")]
        if high_ent:
            for s in high_ent:
                console.print(f"  [red]Section {s['name']}: entropy {s['entropy']} (packed?)[/]")

    # IOCs
    iocs = result.get("iocs", {})
    has_iocs = any(iocs.values())
    if has_iocs:
        console.print("\n[bold]Embedded IOCs:[/]")
        for ioc_type, values in iocs.items():
            if values:
                console.print(f"  [cyan]{ioc_type}:[/] {len(values)} found")
                for v in values[:5]:
                    console.print(f"    [dim]•[/] {v}")

    from utils.output import print_risk_score
    print_risk_score(result.get("risk_score", 0))
    if result.get("risk_details"):
        console.print("[bold]Risk Factors:[/]")
        for d in result.get("risk_details", []):
            console.print(f"  [yellow]•[/] {d}")


def run():
    print_section("File Analyzer", "📁")
    path = console.input("\n[bold]File path to analyze:[/] ").strip()
    if not path:
        print_error("No path provided")
        return

    result = analyze_file(path)
    if result:
        export = console.input("\n[bold]Export results? (json/txt/html/all/no):[/] ").strip().lower()
        if export and export != "no":
            formats = ["json", "txt", "html"] if export == "all" else [export]
            saved = save_results("file", Path(path).name, result, formats)
            for fmt, p in saved.items():
                console.print(f"[green]Saved {fmt.upper()}:[/] {p}")
