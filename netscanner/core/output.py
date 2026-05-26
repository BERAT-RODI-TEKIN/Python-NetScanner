"""
NetScanner — Output Engine
Formats: terminal text, JSON, XML, grepable
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List
from netscanner.core.scanner import ScanResult, PortState, VERSION, BUILD, GITHUB, YEAR


def _ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class C:
    R = "\033[0m";  BOLD = "\033[1m";  DIM = "\033[2m"
    GRN = "\033[92m"; YLW = "\033[93m"; RED = "\033[91m"
    CYN = "\033[96m"; BLU = "\033[94m"; MAG = "\033[95m"
    WHT = "\033[97m"; GRY = "\033[90m"; ORG = "\033[33m"

    @staticmethod
    def disable():
        for a in ["R","BOLD","DIM","GRN","YLW","RED",
                  "CYN","BLU","MAG","WHT","GRY","ORG"]:
            setattr(C, a, "")


BANNER_ART = f"""{C.CYN}{C.BOLD}
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{C.R}
  {C.GRN}NetScanner — {VERSION}{C.R}  {C.GRY}|{C.R}  {C.WHT}Professional Port Scanner{C.R}  {C.GRY}|{C.R}  {C.CYN}{GITHUB}{C.R}
"""


def print_banner():
    print(BANNER_ART)


def _state_color(state: PortState) -> str:
    return {
        PortState.OPEN:          C.GRN,
        PortState.CLOSED:        C.RED,
        PortState.FILTERED:      C.YLW,
        PortState.OPEN_FILTERED: C.CYN,
    }.get(state, C.R)


def format_result(result: ScanResult, verbose: bool = False) -> str:
    L = []

    L.append(f"\n{C.CYN}{'═'*72}{C.R}")
    L.append(f"  {C.BOLD}{C.WHT}Scan Report — {result.target}{C.R}")
    L.append(f"{C.CYN}{'─'*72}{C.R}")

    # Host info block
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
    rows.append(("Scan Type",  result.scan_type.value))
    rows.append(("Started",    _ts()))

    for k, v in rows:
        L.append(f"  {C.CYN}{k:<22}{C.R} {v}")

    if result.error:
        L.append(f"\n  {C.RED}[ERROR] {result.error}{C.R}")
        L.append(f"{C.CYN}{'═'*72}{C.R}")
        return "\n".join(L)

    # Port table
    L.append(f"\n  {C.BOLD}"
             f"{'PORT':<10}{'PROTO':<7}{'STATE':<14}"
             f"{'SERVICE':<20}{'VERSION / BANNER'}"
             f"{C.R}")
    L.append(f"  {'─'*70}")

    if not result.ports:
        not_shown = result.total_scanned
        L.append(f"\n  {C.YLW}No open ports found.{C.R}")
        L.append(f"  {C.GRY}({not_shown} ports scanned — all closed or filtered){C.R}")
        L.append(f"  {C.GRY}Tip: use --closed to show closed ports too{C.R}")
    else:
        for pr in result.ports:
            col     = _state_color(pr.state)
            port_s  = f"{pr.port}/{pr.protocol}"
            state_s = pr.state.value
            info    = pr.version or pr.banner or ""
            if pr.extra:
                info += f"  {C.GRY}({pr.extra}){C.R}"

            L.append(
                f"  {col}{port_s:<10}{C.R}"
                f"{C.GRY}{pr.protocol:<7}{C.R}"
                f"{col}{state_s:<14}{C.R}"
                f"{C.CYN}{pr.service:<20}{C.R}"
                f"{C.WHT}{info}{C.R}"
            )
            if verbose and pr.banner and pr.banner != pr.version:
                L.append(
                    f"  {C.GRY}{'':10}{'':7}{'':14}{'':20}"
                    f"↳ {pr.banner[:55]}{C.R}"
                )

    # Summary
    oc = len(result.open_ports)
    fc = len(result.filtered_ports)
    cc = len(result.closed_ports)
    not_shown = result.total_scanned - len(result.ports)

    L.append(f"\n{C.CYN}{'─'*72}{C.R}")
    if not_shown > 0:
        L.append(
            f"  {C.GRY}Note: {not_shown} closed/filtered ports hidden "
            f"(use --closed to display){C.R}"
        )
    L.append(
        f"  {C.GRN}{C.BOLD}{oc} open{C.R}  │  "
        f"{C.YLW}{fc} filtered{C.R}  │  "
        f"{C.RED}{cc} closed{C.R}  │  "
        f"{C.GRY}Total scanned: {result.total_scanned}{C.R}"
    )
    L.append(
        f"  {C.GRY}Duration: {C.BOLD}{C.WHT}{result.duration}s{C.R}"
    )
    L.append(f"{C.CYN}{'═'*72}{C.R}")
    return "\n".join(L)


def format_summary(results: List[ScanResult]) -> str:
    L = []
    L.append(f"\n{C.CYN}{'═'*72}{C.R}")
    L.append(f"  {C.BOLD}{C.WHT}SCAN SUMMARY — {len(results)} host(s){C.R}")
    L.append(f"  {'─'*70}")
    L.append(
        f"  {C.BOLD}"
        f"{'HOST':<22}{'IP':<18}{'STATUS':<10}"
        f"{'OPEN':<10}{'DURATION'}"
        f"{C.R}"
    )
    L.append(f"  {'─'*70}")
    total_open = 0
    for r in results:
        oc = len(r.open_ports)
        total_open += oc
        col = C.GRN if r.is_up else C.RED
        L.append(
            f"  {C.CYN}{r.target:<22}{C.R}"
            f"{C.GRY}{r.ip:<18}{C.R}"
            f"{col}{'up' if r.is_up else 'down':<10}{C.R}"
            f"{(C.GRN if oc>0 else C.GRY)}{oc:<10}{C.R}"
            f"{C.GRY}{r.duration}s{C.R}"
        )
    L.append(f"  {'─'*70}")
    L.append(f"  {C.BOLD}Total: {total_open} open port(s) across {len(results)} host(s){C.R}")
    L.append(f"{C.CYN}{'═'*72}{C.R}\n")
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
                "port":     p.port,
                "protocol": p.protocol,
                "state":    p.state.value,
                "service":  p.service,
                "version":  p.version,
                "banner":   p.banner,
                "extra":    p.extra,
                "reason":   p.reason,
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
        if r.resolved_from:
            ET.SubElement(h, "resolved_from").text = r.resolved_from
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


def save(results: List[ScanResult], path: str, fmt: str = "json") -> str:
    content = {
        "json":     lambda: to_json(results),
        "xml":      lambda: to_xml(results),
        "grepable": lambda: to_grepable(results),
        "gnmap":    lambda: to_grepable(results),
    }.get(fmt, lambda: "\n\n".join(format_result(r) for r in results))()
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# Legacy alias used by old GUI
def save_results(results, path, fmt="json"):
    return save(results, path, fmt)


def format_json(results):
    return to_json(results)
