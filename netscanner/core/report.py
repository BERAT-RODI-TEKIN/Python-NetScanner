"""
NetScanner v1.3 — HTML Report Generator
Güzel, standalone HTML raporu üretir.
"""
from datetime import datetime
from typing import List
from netscanner.core.scanner import ScanResult, PortState, VERSION, BUILD, GITHUB


def _ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


_SEVERITY_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "INFO":     "#4488ff",
}

_STATE_COLOR = {
    "open":          "#00ff88",
    "closed":        "#ff4444",
    "filtered":      "#ffcc00",
    "open|filtered": "#00ccff",
}


def to_html(results: List[ScanResult]) -> str:
    total_open  = sum(len(r.open_ports) for r in results)
    total_crit  = sum(len(r.critical_cves) for r in results)
    up_count    = sum(1 for r in results if r.is_up)
    scan_ts     = _ts()

    hosts_html  = ""
    for r in results:
        if r.error:
            hosts_html += f"""
            <div class="host-card error-card">
              <div class="host-header">
                <span class="host-ip">{r.target}</span>
                <span class="badge badge-down">ERROR</span>
              </div>
              <p class="error-msg">{r.error}</p>
            </div>"""
            continue

        status_badge = '<span class="badge badge-up">UP</span>' \
                       if r.is_up else '<span class="badge badge-down">DOWN</span>'

        # CVE alerts
        cve_html = ""
        for p in r.open_ports:
            for cve_id, desc, sev in p.cve_hints:
                col = _SEVERITY_COLOR.get(sev, "#888")
                cve_html += f"""
                <div class="cve-item" style="border-left-color:{col}">
                  <span class="cve-sev" style="color:{col}">{sev}</span>
                  <span class="cve-id">{cve_id}</span>
                  <span class="cve-port">Port {p.port}</span>
                  <span class="cve-desc">{desc}</span>
                </div>"""

        # Port rows
        port_rows = ""
        for p in r.ports:
            sc  = _STATE_COLOR.get(p.state.value, "#888")
            danger = p.port in (21,23,445,3389,4444,6379,11211,27017,2375)
            danger_badge = '<span class="danger-tag">⚠ DANGER</span>' if danger else ""
            cve_count = len(p.cve_hints)
            cve_badge = f'<span class="cve-tag">{cve_count} CVE</span>' if cve_count else ""
            info = p.version or p.banner or ""
            port_rows += f"""
            <tr>
              <td><span class="port-num">{p.port}</span>{danger_badge}{cve_badge}</td>
              <td><span class="proto">{p.protocol}</span></td>
              <td><span class="state" style="color:{sc}">{p.state.value}</span></td>
              <td class="service-cell">{p.service}</td>
              <td class="info-cell">{info[:80]}</td>
              <td class="extra-cell">{p.extra[:40]}</td>
            </tr>"""

        hosts_html += f"""
        <div class="host-card">
          <div class="host-header">
            <div class="host-title">
              <span class="host-ip">{r.ip or r.target}</span>
              {f'<span class="host-name">{r.hostname}</span>' if r.hostname and r.hostname != r.target else ""}
            </div>
            <div class="host-badges">
              {status_badge}
              <span class="badge badge-open">{len(r.open_ports)} open</span>
              {f'<span class="badge badge-crit">{len(r.critical_cves)} critical</span>' if r.critical_cves else ""}
            </div>
          </div>

          <div class="host-meta">
            {f'<span>🖥 OS: {r.os_hint}</span>' if r.os_hint else ""}
            {f'<span>TTL: {r.ttl}</span>' if r.ttl else ""}
            <span>🕐 {r.duration}s</span>
            <span>📊 {r.total_scanned} ports scanned</span>
            {f'<span>🔗 {r.scan_type.value}</span>'}
          </div>

          {f'<div class="cve-section"><h3>⚠ Vulnerability Hints</h3>{cve_html}</div>' if cve_html else ""}

          <table class="port-table">
            <thead>
              <tr>
                <th>PORT</th><th>PROTO</th><th>STATE</th>
                <th>SERVICE</th><th>VERSION / BANNER</th><th>EXTRA</th>
              </tr>
            </thead>
            <tbody>{port_rows if port_rows else '<tr><td colspan="6" class="no-ports">No open ports found</td></tr>'}</tbody>
          </table>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetScanner {VERSION} — Report</title>
<style>
  :root {{
    --bg:      #0d1117;
    --bg2:     #161b22;
    --bg3:     #1c2128;
    --border:  #30363d;
    --text:    #e6edf3;
    --text2:   #8b949e;
    --green:   #00ff88;
    --red:     #ff4444;
    --yellow:  #ffcc00;
    --cyan:    #00ccff;
    --purple:  #a371f7;
    --font:    'Segoe UI', system-ui, sans-serif;
    --mono:    'Cascadia Code', 'Fira Code', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: var(--font);
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 2rem 1rem;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; }}

  /* Header */
  .report-header {{
    text-align: center;
    padding: 2.5rem 0 2rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
  }}
  .logo {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--cyan);
    white-space: pre;
    line-height: 1.2;
    margin-bottom: 1rem;
  }}
  .report-title {{
    font-size: 1.4rem;
    color: var(--text);
    margin-bottom: 0.4rem;
  }}
  .report-meta {{ font-size: 0.85rem; color: var(--text2); }}
  .github-link {{ color: var(--cyan); text-decoration: none; }}
  .github-link:hover {{ text-decoration: underline; }}

  /* Summary cards */
  .summary {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .stat-card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem;
    text-align: center;
  }}
  .stat-num {{
    font-size: 2rem;
    font-weight: 600;
    font-family: var(--mono);
  }}
  .stat-label {{ font-size: 0.8rem; color: var(--text2); margin-top: 0.3rem; }}
  .stat-green {{ color: var(--green); }}
  .stat-red   {{ color: var(--red); }}
  .stat-cyan  {{ color: var(--cyan); }}
  .stat-yellow{{ color: var(--yellow); }}

  /* Host cards */
  .host-card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 1.5rem;
    overflow: hidden;
  }}
  .host-card.error-card {{ border-color: var(--red); opacity: 0.7; }}
  .host-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.5rem;
    background: var(--bg3);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
    gap: 0.5rem;
  }}
  .host-title {{ display: flex; align-items: center; gap: 0.8rem; flex-wrap: wrap; }}
  .host-ip {{
    font-family: var(--mono);
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--cyan);
  }}
  .host-name {{ font-size: 0.85rem; color: var(--text2); }}
  .host-badges {{ display: flex; gap: 0.4rem; flex-wrap: wrap; }}
  .host-meta {{
    padding: 0.6rem 1.5rem;
    font-size: 0.8rem;
    color: var(--text2);
    display: flex;
    gap: 1.2rem;
    flex-wrap: wrap;
    border-bottom: 1px solid var(--border);
  }}
  .error-msg {{ padding: 1rem 1.5rem; color: var(--red); font-size: 0.9rem; }}

  /* Badges */
  .badge {{
    font-size: 0.72rem;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .badge-up   {{ background: rgba(0,255,136,.15); color: var(--green); border: 1px solid rgba(0,255,136,.3); }}
  .badge-down {{ background: rgba(255,68,68,.15);  color: var(--red);   border: 1px solid rgba(255,68,68,.3); }}
  .badge-open {{ background: rgba(0,204,255,.15);  color: var(--cyan);  border: 1px solid rgba(0,204,255,.3); }}
  .badge-crit {{ background: rgba(255,68,68,.2);   color: var(--red);   border: 1px solid rgba(255,68,68,.4); }}

  /* CVE section */
  .cve-section {{ padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); }}
  .cve-section h3 {{
    font-size: 0.85rem;
    color: var(--yellow);
    margin-bottom: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }}
  .cve-item {{
    display: flex;
    gap: 0.8rem;
    align-items: baseline;
    padding: 0.4rem 0.8rem;
    border-left: 3px solid;
    background: rgba(255,255,255,.03);
    border-radius: 0 4px 4px 0;
    margin-bottom: 0.4rem;
    flex-wrap: wrap;
    font-size: 0.82rem;
  }}
  .cve-sev  {{ font-weight: 700; font-size: 0.72rem; text-transform: uppercase; min-width: 60px; }}
  .cve-id   {{ font-family: var(--mono); color: var(--text2); min-width: 110px; }}
  .cve-port {{ color: var(--text2); font-size: 0.75rem; min-width: 55px; }}
  .cve-desc {{ color: var(--text); flex: 1; }}

  /* Port table */
  .port-table {{ width: 100%; border-collapse: collapse; font-size: 0.84rem; }}
  .port-table th {{
    background: var(--bg3);
    color: var(--text2);
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 0.6rem 1rem;
    text-align: left;
    font-weight: 500;
  }}
  .port-table td {{
    padding: 0.6rem 1rem;
    border-top: 1px solid var(--border);
    vertical-align: top;
  }}
  .port-table tr:hover td {{ background: rgba(255,255,255,.03); }}
  .port-num  {{ font-family: var(--mono); font-weight: 600; color: var(--text); }}
  .proto     {{ font-family: var(--mono); font-size: 0.78rem; color: var(--text2); }}
  .state     {{ font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: .04em; }}
  .service-cell {{ color: var(--purple); font-family: var(--mono); font-size: 0.8rem; }}
  .info-cell {{ color: var(--text2); font-size: 0.8rem; word-break: break-all; }}
  .extra-cell {{ color: var(--text2); font-size: 0.75rem; word-break: break-all; }}
  .no-ports {{ text-align: center; color: var(--text2); padding: 1.5rem; font-style: italic; }}
  .danger-tag {{
    font-size: 0.65rem; color: var(--red);
    border: 1px solid rgba(255,68,68,.4);
    border-radius: 3px; padding: 1px 4px;
    margin-left: 6px; vertical-align: middle;
  }}
  .cve-tag {{
    font-size: 0.65rem; color: var(--yellow);
    border: 1px solid rgba(255,204,0,.4);
    border-radius: 3px; padding: 1px 4px;
    margin-left: 4px; vertical-align: middle;
  }}

  /* Footer */
  .report-footer {{
    text-align: center;
    padding: 2rem 0;
    font-size: 0.8rem;
    color: var(--text2);
    border-top: 1px solid var(--border);
    margin-top: 2rem;
  }}

  @media (max-width: 640px) {{
    .host-header {{ flex-direction: column; align-items: flex-start; }}
    .port-table th:nth-child(5), .port-table td:nth-child(5),
    .port-table th:nth-child(6), .port-table td:nth-child(6) {{ display: none; }}
  }}
</style>
</head>
<body>
<div class="container">

  <div class="report-header">
    <div class="logo">███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝</div>
    <h1 class="report-title">NetScanner {VERSION} — Scan Report</h1>
    <p class="report-meta">
      Generated: {scan_ts} &nbsp;|&nbsp;
      Build: {BUILD} &nbsp;|&nbsp;
      <a class="github-link" href="{GITHUB}" target="_blank">{GITHUB}</a>
    </p>
  </div>

  <div class="summary">
    <div class="stat-card">
      <div class="stat-num stat-cyan">{len(results)}</div>
      <div class="stat-label">Hosts Scanned</div>
    </div>
    <div class="stat-card">
      <div class="stat-num stat-green">{up_count}</div>
      <div class="stat-label">Hosts Up</div>
    </div>
    <div class="stat-card">
      <div class="stat-num stat-cyan">{total_open}</div>
      <div class="stat-label">Open Ports</div>
    </div>
    <div class="stat-card">
      <div class="stat-num stat-red">{total_crit}</div>
      <div class="stat-label">Critical CVEs</div>
    </div>
  </div>

  {hosts_html}

  <div class="report-footer">
    NetScanner {VERSION} (build {BUILD}) &mdash;
    <a class="github-link" href="{GITHUB}" target="_blank">GitHub</a>
    &mdash; For authorized security testing only.
  </div>

</div>
</body>
</html>"""
