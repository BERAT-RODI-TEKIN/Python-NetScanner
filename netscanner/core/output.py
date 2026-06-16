"""
NetScanner v1.3 — Output Engine
Terminal, JSON, XML, Grepable, HTML
"""
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List
from netscanner.core.scanner import (
    ScanResult, PortState, VERSION, BUILD, GITHUB, YEAR
)
from netscanner.core.report import to_html

def _supports_unicode() -> bool:
    """Check if terminal supports UTF-8 box-drawing chars."""
    try:
        enc = getattr(sys.stdout, "encoding", "") or ""
        return enc.lower().replace("-","") in ("utf8","utf16","utf32")
    except Exception:
        return False

_UNICODE = _supports_unicode()
_H2 = "═" if _UNICODE else "="
_H1 = "─" if _UNICODE else "-"



def _ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── ANSI renk temizleyici (dosya kaydetme için) ──────────────
_ANSI_STRIP = re.compile(r'\x1b\[[0-9;]*[mGKHFABCDSTJRsu]')

def strip_ansi(text: str) -> str:
    return _ANSI_STRIP.sub('', text)


class C:
    R    = "\033[0m";  BOLD = "\033[1m";  DIM  = "\033[2m"
    GRN  = "\033[92m"; YLW  = "\033[93m"; RED  = "\033[91m"
    CYN  = "\033[96m"; BLU  = "\033[94m"; MAG  = "\033[95m"
    WHT  = "\033[97m"; GRY  = "\033[90m"; ORG  = "\033[33m"

    @staticmethod
    def disable():
        for a in ["R","BOLD","DIM","GRN","YLW","RED",
                  "CYN","BLU","MAG","WHT","GRY","ORG"]:
            setattr(C, a, "")


BANNER_ART = (
    f"{C.CYN}{C.BOLD}\n"
    "  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗\n"
    "  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗\n"
    "  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝\n"
    "  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗\n"
    "  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║\n"
    "  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝\n"
    f"{C.R}\n"
    f"  {C.GRN}NetScanner — {VERSION}{C.R}  {C.GRY}|{C.R}  "
    f"{C.WHT}Professional Port Scanner{C.R}  {C.GRY}|{C.R}  {C.CYN}{GITHUB}{C.R}\n"
)


def print_banner():
    print(BANNER_ART)


def _state_color(state: PortState) -> str:
    return {
        PortState.OPEN:          C.GRN,
        PortState.CLOSED:        C.RED,
        PortState.FILTERED:      C.YLW,
        PortState.OPEN_FILTERED: C.CYN,
    }.get(state, C.R)


_SEV_COLOR = {
    "CRITICAL": C.RED,
    "HIGH":     C.ORG,
    "MEDIUM":   C.YLW,
    "INFO":     C.BLU,
}


def format_result(result: ScanResult, verbose: bool = False) -> str:
    L = []
    _h2 = '═' if _supports_unicode() else '='
    L.append(f"\n{C.CYN}{_h2*72}{C.R}")
    L.append(f"  {C.BOLD}{C.WHT}Scan Report — {result.target}{C.R}")
    L.append(f"{C.CYN}{_H1*72}{C.R}")

    rows = [("Target", result.target)]
    if result.ip and result.ip != result.target:
        rows.append(("IP Address", result.ip))
    if result.resolved_from:
        rows.append(("Resolved From", result.resolved_from))
    if result.hostname and result.hostname != result.target:
        rows.append(("Hostname", result.hostname))
    rows.append(("Status",
                 f"{C.GRN}UP{C.R}" if result.is_up else f"{C.RED}DOWN{C.R}"))
    if result.os_hint:
        rows.append(("OS Hint", f"{C.MAG}{result.os_hint}{C.R}"))
    if result.ttl:
        rows.append(("TTL", str(result.ttl)))
    rows.append(("Scan Type", result.scan_type.value))
    rows.append(("Started",   _ts()))

    for k, v in rows:
        L.append(f"  {C.CYN}{k:<22}{C.R} {v}")

    if result.error:
        L.append(f"\n  {C.RED}[ERROR] {result.error}{C.R}")
        L.append(f"{C.CYN}{_H2*72}{C.R}")
        return "\n".join(L)

    # ── Port tablosu ──────────────────────────────────────────
    L.append(f"\n  {C.BOLD}"
             f"{'PORT':<10}{'PROTO':<7}{'STATE':<14}"
             f"{'SERVICE':<20}{'VERSION / BANNER'}"
             f"{C.R}")
    L.append(f"  {_H1*70}")

    if not result.ports:
        L.append(f"\n  {C.YLW}No open ports found.{C.R}")
        L.append(f"  {C.GRY}({result.total_scanned} ports scanned){C.R}")
        L.append(f"  {C.GRY}Tip: use --closed to show closed ports too{C.R}")
    else:
        for pr in result.ports:
            col    = _state_color(pr.state)
            port_s = f"{pr.port}/{pr.protocol}"
            info   = pr.version or pr.banner or ""
            extra  = f"  {C.GRY}({pr.extra}){C.R}" if pr.extra else ""
            cve_badge = ""
            if pr.cve_hints:
                worst = pr.cve_hints[0][2]
                wc    = _SEV_COLOR.get(worst, C.R)
                cve_badge = f"  {wc}[{worst}]{C.R}"

            L.append(
                f"  {col}{port_s:<10}{C.R}"
                f"{C.GRY}{pr.protocol:<7}{C.R}"
                f"{col}{pr.state.value:<14}{C.R}"
                f"{C.CYN}{pr.service:<20}{C.R}"
                f"{C.WHT}{info}{C.R}{extra}{cve_badge}"
            )
            if verbose and pr.banner and pr.banner != info:
                L.append(f"  {C.GRY}{'':51}↳ {pr.banner[:55]}{C.R}")

    # ── CVE uyarı bölümü ──────────────────────────────────────
    all_cves = []
    for pr in result.open_ports:
        for cve_id, desc, sev in pr.cve_hints:
            all_cves.append((pr.port, pr.service, cve_id, desc, sev))

    if all_cves:
        # Dinamik sütun genişlikleri
        max_port = max(len(f"{port}/{svc}") for port, svc, *_ in all_cves)
        max_cve  = max(len(cve_id) for _, __, cve_id, *_ in all_cves)
        max_port = max(max_port, 8)
        max_cve  = max(max_cve, 18)
        sep_w    = 10 + max_port + 2 + max_cve + 2 + 44

        L.append(f"\n  {C.RED}{C.BOLD}⚠  VULNERABILITY HINTS  —  {len(all_cves)} finding(s){C.R}")
        L.append(f"  {C.GRY}{'─' * sep_w}{C.R}")
        L.append(
            f"  {C.BOLD}"
            f"{'SEV':<10}"
            f"{'PORT/SERVICE':<{max_port + 2}}"
            f"{'CVE ID':<{max_cve + 2}}"
            f"DESCRIPTION"
            f"{C.R}"
        )
        L.append(f"  {'─' * sep_w}")
        indent = " " * (2 + 10 + max_port + 2 + max_cve + 2)
        for port, svc, cve_id, desc, sev in all_cves:
            sc       = _SEV_COLOR.get(sev, C.R)
            port_str = f"{port}/{svc}"
            # İlk satır
            L.append(
                f"  {sc}{C.BOLD}{sev:<10}{C.R}"
                f"{C.CYN}{port_str:<{max_port + 2}}{C.R}"
                f"{C.YLW}{cve_id:<{max_cve + 2}}{C.R}"
                f"{C.WHT}{desc}{C.R}"
            )
        L.append(f"  {C.GRY}{'─' * sep_w}{C.R}")
        L.append(f"  {C.GRY}⚠ CVE hints are informational. Always verify with a dedicated scanner.{C.R}")

    # ── Özet satır ────────────────────────────────────────────
    oc  = len(result.open_ports)
    fc  = len(result.filtered_ports)
    cc  = len(result.closed_ports)
    hidden = result.total_scanned - len(result.ports)

    L.append(f"\n{C.CYN}{_H1*72}{C.R}")
    if hidden > 0:
        L.append(
            f"  {C.GRY}Note: {hidden} closed/filtered ports hidden "
            f"(use --closed to display){C.R}"
        )
    L.append(
        f"  {C.GRN}{C.BOLD}{oc} open{C.R}  │  "
        f"{C.YLW}{fc} filtered{C.R}  │  "
        f"{C.RED}{cc} closed{C.R}  │  "
        f"{C.GRY}Total scanned: {result.total_scanned}{C.R}"
    )
    if all_cves:
        crit = sum(1 for *_, s in all_cves if s == "CRITICAL")
        L.append(
            f"  {C.RED}{C.BOLD}⚠  {crit} CRITICAL  "
            f"{sum(1 for *_,s in all_cves if s=='HIGH')} HIGH  "
            f"{sum(1 for *_,s in all_cves if s=='MEDIUM')} MEDIUM  "
            f"CVE hints{C.R}"
        )
    L.append(f"  {C.GRY}Duration: {C.BOLD}{C.WHT}{result.duration}s{C.R}")
    L.append(f"{C.CYN}{_H2*72}{C.R}")
    return "\n".join(L)


def format_summary(results: List[ScanResult]) -> str:
    L = []
    _h2 = '═' if _supports_unicode() else '='
    L.append(f"\n{C.CYN}{_h2*72}{C.R}")
    L.append(f"  {C.BOLD}{C.WHT}SCAN SUMMARY — {len(results)} host(s){C.R}")
    L.append(f"  {_H1*70}")
    L.append(
        f"  {C.BOLD}"
        f"{'HOST':<22}{'IP':<18}{'STATUS':<10}"
        f"{'OPEN':<8}{'CVEs':<8}{'DURATION'}"
        f"{C.R}"
    )
    L.append(f"  {_H1*70}")
    total_open = 0
    total_cves = 0
    for r in results:
        oc  = len(r.open_ports)
        cvec = sum(len(p.cve_hints) for p in r.open_ports)
        total_open += oc
        total_cves += cvec
        col = C.GRN if r.is_up else C.RED
        cvc = C.RED if cvec > 0 else C.GRY
        L.append(
            f"  {C.CYN}{r.target:<22}{C.R}"
            f"{C.GRY}{r.ip:<18}{C.R}"
            f"{col}{'up' if r.is_up else 'down':<10}{C.R}"
            f"{(C.GRN if oc>0 else C.GRY)}{oc:<8}{C.R}"
            f"{cvc}{cvec:<8}{C.R}"
            f"{C.GRY}{r.duration}s{C.R}"
        )
    L.append(f"  {_H1*70}")
    L.append(
        f"  {C.BOLD}Total: {total_open} open port(s), "
        f"{total_cves} CVE hint(s) across {len(results)} host(s){C.R}"
    )
    L.append(f"{C.CYN}{_H2*72}{C.R}\n")
    return "\n".join(L)


# ── File output formats ───────────────────────────────────────
def to_json(results: List[ScanResult], indent=2) -> str:
    data = {
        "scanner":   "NetScanner",
        "version":   BUILD,
        "release":   VERSION,
        "generated": _ts(),
        "github":    GITHUB,
        "hosts": [{
            "target":        r.target,
            "ip":            r.ip,
            "hostname":      r.hostname,
            "resolved_from": r.resolved_from,
            "is_up":         r.is_up,
            "os_hint":       r.os_hint,
            "ttl":           r.ttl,
            "scan_type":     r.scan_type.value,
            "duration_sec":  r.duration,
            "total_scanned": r.total_scanned,
            "open_count":    len(r.open_ports),
            "error":         r.error,
            "ports": [{
                "port":      p.port,
                "protocol":  p.protocol,
                "state":     p.state.value,
                "service":   p.service,
                "version":   p.version,
                "banner":    p.banner,
                "extra":     p.extra,
                "reason":    p.reason,
                "cve_hints": [
                    {"id": c[0], "description": c[1], "severity": c[2]}
                    for c in p.cve_hints
                ],
            } for p in r.ports],
        } for r in results],
    }
    return json.dumps(data, indent=indent, ensure_ascii=False)


def to_xml(results: List[ScanResult]) -> str:
    root = ET.Element("NetScannerRun",
                      version=BUILD, release=VERSION,
                      generated=_ts(), github=GITHUB)
    for r in results:
        h = ET.SubElement(root, "host")
        ET.SubElement(h, "address", addr=r.ip, type="ipv4")
        if r.hostname:
            ET.SubElement(h, "hostname").text = r.hostname
        ET.SubElement(h, "status", state="up" if r.is_up else "down")
        if r.os_hint:
            ET.SubElement(h, "os", ttl=str(r.ttl)).text = r.os_hint
        ps = ET.SubElement(h, "ports",
                            total_scanned=str(r.total_scanned),
                            open=str(len(r.open_ports)))
        for p in r.ports:
            pe = ET.SubElement(ps, "port",
                               id=str(p.port), protocol=p.protocol)
            ET.SubElement(pe, "state", value=p.state.value, reason=p.reason)
            svc = ET.SubElement(pe, "service", name=p.service)
            if p.version:
                svc.set("version", p.version)
            if p.banner:
                ET.SubElement(pe, "banner").text = p.banner
            if p.extra:
                ET.SubElement(pe, "extra").text = p.extra
            if p.cve_hints:
                cves_el = ET.SubElement(pe, "cve_hints")
                for cve_id, desc, sev in p.cve_hints:
                    ET.SubElement(cves_el, "cve",
                                  id=cve_id, severity=sev).text = desc
        ET.SubElement(h, "timing", duration=str(r.duration))
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def to_grepable(results: List[ScanResult]) -> str:
    lines = [
        f"# NetScanner {VERSION} — {_ts()}",
        f"# {GITHUB}",
        "# Format: Host: IP (hostname)\tStatus: state\tPorts: port/proto/state/service",
    ]
    for r in results:
        ports_str = ",".join(
            f"{p.port}/{p.protocol}/{p.state.value}/{p.service}"
            for p in r.ports
        )
        lines.append(
            f"Host: {r.ip} ({r.hostname})\t"
            f"Status: {'Up' if r.is_up else 'Down'}\t"
            f"Ports: {ports_str}"
        )
    return "\n".join(lines)


def to_txt(results: List[ScanResult], verbose: bool = False) -> str:
    """Plain text — no ANSI codes, suitable for file saving."""
    C.disable()
    parts = [strip_ansi(format_result(r, verbose)) for r in results]
    if len(results) > 1:
        parts.append(strip_ansi(format_summary(results)))
    return "\n".join(parts)


def save(results: List[ScanResult], path: str,
         fmt: str = "json", verbose: bool = False) -> str:
    """Save results to file. fmt: json | xml | grepable | gnmap | txt | html"""
    fmt_map = {
        "json":     lambda: to_json(results),
        "xml":      lambda: to_xml(results),
        "grepable": lambda: to_grepable(results),
        "gnmap":    lambda: to_grepable(results),
        "txt":      lambda: to_txt(results, verbose),
        "html":     lambda: to_html(results),
    }
    content = fmt_map.get(fmt, lambda: to_txt(results, verbose))()
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# Legacy aliases
def save_results(results, path, fmt="json"):
    return save(results, path, fmt)

def format_json(results):
    return to_json(results)
