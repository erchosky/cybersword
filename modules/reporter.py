"""
CyberSword - Reporter & Dashboard
Session summary, HTML report with charts, timeline, stats.
"""

import json
import html as html_lib
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from utils.helpers import PROJECT_ROOT, get_session_log, get_session_start, load_config, risk_color
from utils.output import print_section, print_result_table

console = Console()


def show_dashboard() -> None:
    """Display session analysis dashboard."""
    print_section("Session Dashboard", "📊")

    log = get_session_log()
    start = get_session_start()
    duration = datetime.now() - start

    if not log:
        console.print("[yellow]No analyses performed in this session.[/]")
        return

    # Session info
    console.print(Panel(
        f"[bold]Session Start:[/] {start.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"[bold]Duration:[/] {str(duration).split('.')[0]}\n"
        f"[bold]Total Analyses:[/] {len(log)}",
        title="[bold]Session Summary[/]",
        style="blue",
    ))

    # Module usage stats
    module_counts = {}
    for entry in log:
        mod = entry.get("module", "unknown")
        module_counts[mod] = module_counts.get(mod, 0) + 1

    stats_rows = [(mod, str(count)) for mod, count in sorted(
        module_counts.items(), key=lambda x: x[1], reverse=True
    )]
    print_result_table("Module Usage", stats_rows, ["Module", "Count"])

    # Timeline
    t = Table(title="Analysis Timeline", box=box.ROUNDED, header_style="bold cyan")
    t.add_column("Time")
    t.add_column("Module")
    t.add_column("Target")
    t.add_column("Risk Score")

    for entry in log:
        ts = entry.get("timestamp", "")[:19].replace("T", " ")
        mod = entry.get("module", "")
        target = str(entry.get("target", ""))[:50]
        risk = entry.get("result", {}).get("risk_score", "")
        risk_str = ""
        if isinstance(risk, int):
            color = risk_color(risk)
            risk_str = f"[{color}]{risk}[/]"

        t.add_row(ts, mod, target, risk_str)

    console.print(t)

    # High risk findings
    high_risk = [e for e in log if isinstance(e.get("result", {}).get("risk_score"), int)
                 and e["result"]["risk_score"] >= 50]
    if high_risk:
        console.print(f"\n[bold red]⚠ HIGH RISK FINDINGS ({len(high_risk)}):[/]")
        for entry in high_risk:
            score = entry["result"]["risk_score"]
            console.print(f"  [red]•[/] [{entry['module']}] {entry['target'][:60]} — Risk: {score}/100")


def export_session_report() -> Optional[Path]:
    """Export full session as HTML report with all findings."""
    log = get_session_log()
    start = get_session_start()

    if not log:
        console.print("[yellow]No analyses to export.[/]")
        return None

    cfg = load_config()
    report_dir = Path(cfg.get("output", {}).get("report_dir", "reports"))
    if not report_dir.is_absolute():
        report_dir = PROJECT_ROOT / report_dir
    report_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"session_report_{ts}.html"

    # Build HTML
    module_counts = {}
    risk_scores = []
    for entry in log:
        mod = entry.get("module", "unknown")
        module_counts[mod] = module_counts.get(mod, 0) + 1
        score = entry.get("result", {}).get("risk_score")
        if isinstance(score, int):
            risk_scores.append(score)

    high_risk_count = sum(1 for s in risk_scores if s >= 70)
    medium_risk_count = sum(1 for s in risk_scores if 40 <= s < 70)
    low_risk_count = sum(1 for s in risk_scores if s < 40)

    # Timeline rows
    timeline_rows = ""
    for index, entry in enumerate(log):
        ts_str = entry.get("timestamp", "")[:19].replace("T", " ")
        mod = entry.get("module", "")
        target = str(entry.get("target", ""))[:80]
        score = entry.get("result", {}).get("risk_score", "N/A")
        risk_html = ""
        if isinstance(score, int):
            color = "#da3633" if score >= 70 else ("#d29922" if score >= 40 else "#1a7f37")
            risk_html = f'<span style="background:{color};color:white;padding:2px 6px;border-radius:4px;">{score}</span>'
        else:
            risk_html = "N/A"

        details = json.dumps(entry.get("result", {}), indent=2, ensure_ascii=False, default=str)
        row_id = f"entry_{index}"
        timeline_rows += f"""
        <tr>
            <td>{html_lib.escape(ts_str)}</td>
            <td><span class="badge">{html_lib.escape(mod)}</span></td>
            <td>{html_lib.escape(target)}</td>
            <td>{risk_html}</td>
            <td><button onclick="toggleDetails('{row_id}')">View</button></td>
        </tr>
        <tr id="details_{row_id}" style="display:none">
            <td colspan="5"><pre class="details">{html_lib.escape(details[:3000])}</pre></td>
        </tr>
        """

    # Module chart data
    chart_labels = json.dumps(list(module_counts.keys()))
    chart_data = json.dumps(list(module_counts.values()))
    risk_chart_data = json.dumps([high_risk_count, medium_risk_count, low_risk_count])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberSword Session Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', 'Courier New', monospace; background: #0d1117; color: #c9d1d9; }}
  .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    padding: 30px; border-bottom: 2px solid #58a6ff; }}
  .header h1 {{ color: #58a6ff; font-size: 2.2em; letter-spacing: 2px; }}
  .header .meta {{ color: #8b949e; margin-top: 8px; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0; }}
  .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 20px; text-align: center; }}
  .stat-card .value {{ font-size: 2.5em; font-weight: bold; }}
  .stat-card .label {{ color: #8b949e; margin-top: 4px; font-size: 0.85em; }}
  .red {{ color: #da3633; }} .yellow {{ color: #d29922; }}
  .green {{ color: #1a7f37; }} .blue {{ color: #58a6ff; }}
  .charts-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin: 24px 0; }}
  .chart-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }}
  .chart-card h3 {{ color: #79c0ff; margin-bottom: 16px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  th {{ background: #21262d; padding: 12px; text-align: left; color: #79c0ff; font-weight: 600; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; vertical-align: middle; }}
  tr:hover td {{ background: #161b22; }}
  .badge {{ background: #1f6feb; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
  button {{ background: #21262d; color: #58a6ff; border: 1px solid #30363d;
    padding: 4px 12px; border-radius: 4px; cursor: pointer; font-size: 0.8em; }}
  button:hover {{ background: #30363d; }}
  pre.details {{ background: #0d1117; padding: 16px; border-radius: 4px; overflow-x: auto;
    font-size: 0.8em; color: #8b949e; max-height: 400px; overflow-y: auto; }}
  .section-title {{ color: #58a6ff; font-size: 1.3em; margin: 24px 0 12px; border-bottom: 1px solid #21262d; padding-bottom: 8px; }}
  @media (max-width: 768px) {{ .stats-grid {{ grid-template-columns: 1fr 1fr; }} .charts-grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="header">
  <div class="container">
    <h1>&#x1F5E1; CyberSword Session Report</h1>
    <div class="meta">
      Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |
      Session: {start.strftime("%Y-%m-%d %H:%M:%S")} → {datetime.now().strftime("%H:%M:%S")}
    </div>
  </div>
</div>
<div class="container">

  <div class="stats-grid">
    <div class="stat-card">
      <div class="value blue">{len(log)}</div>
      <div class="label">Total Analyses</div>
    </div>
    <div class="stat-card">
      <div class="value red">{high_risk_count}</div>
      <div class="label">High Risk</div>
    </div>
    <div class="stat-card">
      <div class="value yellow">{medium_risk_count}</div>
      <div class="label">Medium Risk</div>
    </div>
    <div class="stat-card">
      <div class="value green">{low_risk_count}</div>
      <div class="label">Low/Clean</div>
    </div>
  </div>

  <div class="charts-grid">
    <div class="chart-card">
      <h3>Module Usage</h3>
      <canvas id="moduleChart" height="200"></canvas>
    </div>
    <div class="chart-card">
      <h3>Risk Distribution</h3>
      <canvas id="riskChart" height="200"></canvas>
    </div>
  </div>

  <h2 class="section-title">Analysis Timeline</h2>
  <table>
    <thead>
      <tr>
        <th>Timestamp</th>
        <th>Module</th>
        <th>Target</th>
        <th>Risk Score</th>
        <th>Details</th>
      </tr>
    </thead>
    <tbody>
      {timeline_rows}
    </tbody>
  </table>

</div>
<script>
function toggleDetails(id) {{
  var row = document.getElementById('details_' + id);
  row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
}}
new Chart(document.getElementById('moduleChart'), {{
  type: 'bar',
  data: {{
    labels: {chart_labels},
    datasets: [{{
      label: 'Analyses',
      data: {chart_data},
      backgroundColor: '#1f6feb',
      borderRadius: 4,
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ grid: {{ color: '#21262d' }}, ticks: {{ color: '#8b949e' }} }},
      y: {{ grid: {{ color: '#21262d' }}, ticks: {{ color: '#8b949e' }} }},
    }}
  }}
}});
new Chart(document.getElementById('riskChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['High Risk', 'Medium Risk', 'Low/Clean'],
    datasets: [{{
      data: {risk_chart_data},
      backgroundColor: ['#da3633', '#d29922', '#1a7f37'],
      borderWidth: 0,
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ labels: {{ color: '#c9d1d9' }} }}
    }}
  }}
}});
</script>
</body>
</html>"""

    report_path.write_text(html, encoding="utf-8")
    return report_path


def run():
    print_section("Dashboard & Reports", "📊")
    console.print("\n1. Show session dashboard")
    console.print("2. Export full session report (HTML)")
    choice = console.input("\n[bold]>[/] ").strip()

    if choice == "1":
        show_dashboard()
    elif choice == "2":
        path = export_session_report()
        if path:
            console.print(f"\n[bold green]Report saved:[/] {path}")
    else:
        from utils.output import print_error
        print_error("Invalid option")
