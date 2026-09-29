"""
CyberSword - Output formatting: rich tables, JSON, TXT, HTML export.
"""

import html as html_lib
import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from utils.helpers import PROJECT_ROOT, load_config, risk_color, risk_label

console = Console()


# ---------------------------------------------------------------------------
# Rich display helpers
# ---------------------------------------------------------------------------

def print_banner():
    banner = """
  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝"""
    console.print(f"[bold cyan]{banner}[/]")
    console.print("[bold white]         Personal Cybersecurity Swiss Army Knife — v1.0[/]")
    console.print("[dim]         Defensive OSINT & Analysis Platform[/]\n")


def print_section(title: str, icon: str = ""):
    console.print(Panel(f"{icon} [bold]{title}[/]", style="cyan", box=box.HEAVY_HEAD))


def print_result_table(title: str, rows: list[tuple], headers: list[str] = ("Field", "Value"),
                       style: str = "cyan") -> None:
    t = Table(title=title, box=box.ROUNDED, header_style=f"bold {style}", show_lines=True)
    for h in headers:
        t.add_column(h, style="white")
    for row in rows:
        t.add_row(*[str(c) for c in row])
    console.print(t)


def print_risk_score(score: int, label_override: str = None) -> None:
    color = risk_color(score)
    label = label_override or risk_label(score)
    bar = "█" * int(score / 5) + "░" * (20 - int(score / 5))
    console.print(f"\n[bold]Risk Score:[/] [{color}]{score}/100[/]  [{color}]{bar}[/]  [{color}][{label}][/]")


def print_ioc_table(iocs: dict) -> None:
    t = Table(title="Extracted IOCs", box=box.ROUNDED, header_style="bold magenta")
    t.add_column("Type")
    t.add_column("Value")
    for ioc_type, values in iocs.items():
        for v in values:
            t.add_row(ioc_type, str(v))
    console.print(t)


def print_error(msg: str) -> None:
    console.print(f"[bold red][ERROR][/] {msg}")


def print_warning(msg: str) -> None:
    console.print(f"[bold yellow][WARN][/] {msg}")


def print_success(msg: str) -> None:
    console.print(f"[bold green][OK][/] {msg}")


def print_info(msg: str) -> None:
    console.print(f"[bold blue][INFO][/] {msg}")


# ---------------------------------------------------------------------------
# Export functions
# ---------------------------------------------------------------------------

def export_txt(data: dict, filepath: Path) -> None:
    def _flatten(obj, prefix=""):
        lines = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                lines.extend(_flatten(v, f"{prefix}{k}: "))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                lines.extend(_flatten(item, f"{prefix}[{i}] "))
        else:
            lines.append(f"{prefix}{obj}")
        return lines

    lines = [
        "CyberSword Analysis Report",
        f"Generated: {datetime.now().isoformat()}",
        "=" * 60,
        "",
    ]
    lines.extend(_flatten(data))
    filepath.write_text("\n".join(lines), encoding="utf-8")


def export_json(data: dict, filepath: Path) -> None:
    filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def export_html(data: dict, title: str, filepath: Path) -> None:
    def _render(obj, depth=0):
        if isinstance(obj, dict):
            rows = "".join(
                f"<tr><td class='key'>{html_lib.escape(str(k))}</td><td>{_render(v, depth+1)}</td></tr>"
                for k, v in obj.items()
            )
            return f"<table class='inner'>{rows}</table>"
        elif isinstance(obj, list):
            items = "".join(f"<li>{_render(i, depth+1)}</li>" for i in obj)
            return f"<ul>{items}</ul>" if items else "<em>empty</em>"
        else:
            s = str(obj)
            escaped = html_lib.escape(s)
            if s.startswith(("http://", "https://")):
                href = html_lib.escape(s, quote=True)
                return f"<a href='{href}' target='_blank' rel='noopener noreferrer'>{escaped}</a>"
            return escaped

    body = _render(data)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberSword - {html_lib.escape(title)}</title>
<style>
  body {{font-family: 'Courier New', monospace; background:#0d1117; color:#c9d1d9; padding:20px;}}
  h1 {{color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:10px;}}
  h2 {{color:#79c0ff; margin-top:30px;}}
  .meta {{color:#8b949e; font-size:0.85em; margin-bottom:20px;}}
  table {{border-collapse:collapse; width:100%; margin:10px 0;}}
  table.inner {{background:#161b22; border-radius:6px; margin:4px 0;}}
  td {{padding:8px 12px; border-bottom:1px solid #21262d; vertical-align:top;}}
  td.key {{color:#79c0ff; font-weight:bold; white-space:nowrap; width:200px;}}
  ul {{margin:4px 0; padding-left:20px;}}
  a {{color:#58a6ff;}}
  .badge-high {{background:#da3633; color:white; padding:2px 8px; border-radius:4px;}}
  .badge-med {{background:#d29922; color:black; padding:2px 8px; border-radius:4px;}}
  .badge-low {{background:#1a7f37; color:white; padding:2px 8px; border-radius:4px;}}
</style>
</head>
<body>
<h1>&#x1F5E1; CyberSword — {html_lib.escape(title)}</h1>
<p class="meta">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
<div class="content">{body}</div>
</body>
</html>"""
    filepath.write_text(html, encoding="utf-8")


def save_results(module: str, target: str, data: dict,
                 formats: list = None) -> dict[str, Path]:
    cfg = load_config()
    report_dir = Path(cfg.get("output", {}).get("report_dir", "reports"))
    if not report_dir.is_absolute():
        report_dir = PROJECT_ROOT / report_dir
    report_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = "".join(c for c in target if c.isalnum() or c in "._-")[:50]
    stem = f"{module}_{safe_target}_{ts}"
    saved = {}

    if formats is None:
        formats = ["json", "txt", "html"]

    if "json" in formats:
        p = report_dir / f"{stem}.json"
        export_json(data, p)
        saved["json"] = p

    if "txt" in formats:
        p = report_dir / f"{stem}.txt"
        export_txt(data, p)
        saved["txt"] = p

    if "html" in formats:
        p = report_dir / f"{stem}.html"
        export_html(data, f"{module}: {target}", p)
        saved["html"] = p

    return saved


def confirm_authorized(action: str, target: str) -> bool:
    """Pide confirmación explícita antes de una acción activa contra un objetivo (escaneo de puertos o rutas)."""
    from rich.prompt import Confirm

    console.print(
        f"\n[bold yellow]⚠ {action} contra {target}[/]\n"
        "[yellow]Solo debes hacerlo en sistemas propios o con autorización expresa. "
        "Escanear sistemas ajenos puede estar prohibido por ley o por el proveedor.[/]"
    )
    return Confirm.ask("¿Confirmas que tienes autorización?", default=False)
