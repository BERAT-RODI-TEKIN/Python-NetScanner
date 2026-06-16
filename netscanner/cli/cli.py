"""
NetScanner — CLI Interface
nmap-style argument parsing, colored output, progress bar
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import argparse
import time
import threading

from netscanner.core.scanner import (
    NetScanner, ScanType, PortState,
    parse_targets, parse_ports, PORT_PROFILES,
    VERSION, BUILD, GITHUB, resolve_domain_info, _LARGE_CIDR_THRESHOLD,
    DANGEROUS_PORTS,
)
from netscanner.core.output import (
    C, print_banner, format_result, format_summary, save,
)

TIMING = {
    1: (3.0,  50,  "Sneaky    — slow, IDS-friendly"),
    2: (2.0, 100,  "Polite    — moderate speed"),
    3: (1.0, 300,  "Normal    — default"),
    4: (0.5, 500,  "Aggressive — fast"),
    5: (0.2, 800,  "Insane    — maximum speed"),
}

EXAMPLES = f"""
{C.BOLD}EXAMPLES:{C.R}
  {C.GRN}netscanner 192.168.1.1{C.R}
  {C.GRN}netscanner google.com -p 80,443{C.R}               # domain → IP auto-resolve
  {C.GRN}netscanner 192.168.1.1 -p 1-65535 -T4{C.R}        # full port scan
  {C.GRN}netscanner 192.168.1.0/24 -p top-100{C.R}         # subnet
  {C.GRN}netscanner 10.0.0.1-20 -p web{C.R}                # IP range + profile
  {C.GRN}netscanner host.com -sU -p 53,161{C.R}            # UDP scan
  {C.GRN}netscanner target.com -A -p top-1000{C.R}         # aggressive (banner+OS)
  {C.GRN}netscanner target.com --resolve{C.R}               # DNS lookup only
  {C.GRN}netscanner 10.0.0.1 -p top-100 -oJ out.json{C.R}  # save as JSON
  {C.GRN}netscanner 10.0.0.1 -p top-100 -oA results{C.R}   # all formats

{C.BOLD}PORT PROFILES:{C.R}
  {C.CYN}top-100{C.R}    100 common ports
  {C.CYN}top-1000{C.R}   ports 1-1000
  {C.CYN}web{C.R}        HTTP/HTTPS ports
  {C.CYN}db{C.R}         database ports
  {C.CYN}mail{C.R}       mail server ports
  {C.CYN}remote{C.R}     remote access ports
  {C.CYN}vuln{C.R}       common vulnerability ports
  {C.CYN}all{C.R}        all 65535 ports

{C.BOLD}TIMING:{C.R}
  {C.YLW}1{C.R} Sneaky     3.0s timeout,  50 threads
  {C.YLW}2{C.R} Polite     2.0s timeout, 100 threads
  {C.YLW}3{C.R} Normal     1.0s timeout, 300 threads  ← default
  {C.YLW}4{C.R} Aggressive 0.5s timeout, 500 threads
  {C.YLW}5{C.R} Insane     0.2s timeout, 800 threads
"""


class ProgressBar:
    def __init__(self, width: int = 45):
        self.width  = width
        self._lock  = threading.Lock()
        self._start = time.time()

    def update(self, done: int, total: int):
        with self._lock:
            pct    = done / total if total else 0
            filled = int(self.width * pct)
            bar    = "█" * filled + "░" * (self.width - filled)
            ela    = time.time() - self._start
            rate   = done / ela if ela > 0 else 0
            eta    = (total - done) / rate if rate > 0 else 0
            sys.stdout.write(
                f"\r  {C.CYN}[{bar}]{C.R} "
                f"{C.BOLD}{done}/{total}{C.R} "
                f"{C.GRY}({rate:.0f}/s  ETA:{eta:.0f}s){C.R}   "
            )
            sys.stdout.flush()

    def clear(self):
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscanner",
        description=f"NetScanner — {VERSION}  |  Professional Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
    )

    p.add_argument("target", nargs="?",
                   help="Target: IP, hostname, domain, CIDR, range, comma-separated")

    # Scan type
    st = p.add_argument_group("Scan Type")
    stx = st.add_mutually_exclusive_group()
    stx.add_argument("-sT", action="store_true", help="TCP Connect scan (default)")
    stx.add_argument("-sU", action="store_true", help="UDP scan")

    # Ports
    pg = p.add_argument_group("Port Selection")
    pg.add_argument("-p","--ports", default="top-100", metavar="PORTS",
                    help="Ports: 22,80 | 1-1024 | top-100 | web | all ...")
    pg.add_argument("--top-ports", type=int, metavar="N",
                    help="Scan first N ports")

    # Discovery
    dg = p.add_argument_group("Host Discovery")
    dg.add_argument("-Pn", action="store_true",
                    help="Skip host discovery (treat all hosts as up)")

    # Timing
    tg = p.add_argument_group("Timing & Performance")
    tg.add_argument("-T","--timing", type=int, choices=range(1,6),
                    default=3, metavar="1-5",
                    help="Timing template (1=Sneaky … 5=Insane, default=3)")
    tg.add_argument("--timeout", type=float, metavar="SEC",
                    help="Override socket timeout in seconds")
    tg.add_argument("--threads", type=int, metavar="N",
                    help="Override thread count")

    # Detection
    det = p.add_argument_group("Detection")
    det.add_argument("-b","--banner", action="store_true",
                     help="Enable banner / version detection")
    det.add_argument("-O","--os", action="store_true",
                     help="OS detection (TTL-based)")
    det.add_argument("-A","--aggressive", action="store_true",
                     help="Aggressive mode: enable -b + -O")

    # DNS
    dns = p.add_argument_group("DNS / Resolution")
    dns.add_argument("--resolve", action="store_true",
                     help="DNS lookup only — show IPs for domain, no scan")

    # Output
    og = p.add_argument_group("Output")
    og.add_argument("-v","--verbose", action="store_true",
                    help="Verbose: show banner on separate line")
    og.add_argument("--no-color", action="store_true",
                    help="Disable ANSI colors")
    og.add_argument("--closed", action="store_true",
                    help="Also show closed ports (hidden by default)")
    og.add_argument("-oN", metavar="FILE", help="Save normal text")
    og.add_argument("-oJ", metavar="FILE", help="Save JSON")
    og.add_argument("-oX", metavar="FILE", help="Save XML")
    og.add_argument("-oG", metavar="FILE", help="Save grepable format")
    og.add_argument("-oA", metavar="NAME",
                    help="Save all formats (NAME.txt/.json/.xml/.gnmap)")

    # Misc
    misc = p.add_argument_group("Misc")
    misc.add_argument("--gui",           action="store_true",
                      help="Launch GUI mode")
    misc.add_argument("--list-profiles", action="store_true",
                      help="List available port profiles")
    og.add_argument("-oH", metavar="FILE", help="Save HTML report")
    misc.add_argument("--no-cve",         action="store_true",
                      help="Disable CVE hint lookup for open ports")
    misc.add_argument("--rate-limit",     type=float, default=0.0, metavar="SEC",
                      help="Delay (seconds) between port probes (e.g. 0.05)")
    misc.add_argument("--parallel-hosts", type=int, default=1, metavar="N",
                      help="Scan N hosts in parallel (v1.3, default=1)")
    misc.add_argument("--force-large-scan", action="store_true",
                      help="Allow scanning CIDR blocks with >65536 hosts (use with caution)")
    misc.add_argument("--version",       action="version",
                      version=f"NetScanner {VERSION} (build {BUILD})")
    return p


def run_cli(argv=None):
    parser = build_parser()
    args   = parser.parse_args(argv)

    if args.gui:
        from netscanner.gui.app import launch_gui
        launch_gui()
        return

    if args.list_profiles:
        print(f"\n{C.BOLD}Available port profiles:{C.R}\n")
        for name, ports in PORT_PROFILES.items():
            n  = len(ports)
            ex = str(sorted(ports)[:5])[:-1] + ", ...]" if n > 5 else str(sorted(ports))
            print(f"  {C.CYN}{name:<12}{C.R} {C.BOLD}{n:>6} ports{C.R}  {C.GRY}{ex}{C.R}")
        print()
        return

    if not args.target:
        print_banner()
        parser.print_usage()
        print(f"\n{C.YLW}Example: netscanner 192.168.1.1 -p top-100{C.R}")
        print(f"{C.YLW}Help:    netscanner --help{C.R}\n")
        sys.exit(0)

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    print_banner()

    # DNS lookup only mode
    if args.resolve:
        target = args.target
        print(f"  {C.CYN}[*] Resolving: {C.BOLD}{target}{C.R}\n")
        info = resolve_domain_info(target)
        print(f"  {C.BOLD}Domain  :{C.R} {info.get('domain', target)}")
        ips = info.get("ips", [])
        for i, ip in enumerate(ips):
            print(f"  {C.BOLD}IP [{i+1}]  :{C.R} {C.GRN}{ip}{C.R}")
        if info.get("hostname"):
            print(f"  {C.BOLD}Hostname:{C.R} {info['hostname']}")
        if not ips:
            print(f"  {C.RED}Could not resolve {target}{C.R}")
        print()
        return

    # Timing
    t_out, t_thr, t_desc = TIMING[args.timing]
    timeout = args.timeout or t_out
    threads = args.threads or t_thr

    scan_type = ScanType.UDP if args.sU else ScanType.TCP_CONNECT
    do_banner = args.banner or args.aggressive
    do_os     = args.os     or args.aggressive

    if args.top_ports:
        ports = list(range(1, min(args.top_ports + 1, 65536)))
    else:
        ports = parse_ports(args.ports)

    try:
        targets = parse_targets(args.target, confirm_large=getattr(args, "force_large_scan", False))
    except ValueError as e:
        print(f"\n  {C.RED}[!] {e}{C.R}")
        print(f"  {C.YLW}Add --force-large-scan to override.{C.R}\n")
        sys.exit(1)
    if not targets:
        print(f"{C.RED}[!] No valid targets found.{C.R}")
        sys.exit(1)

    print(f"  {C.BOLD}Target  :{C.R}  {len(targets)} host(s)   "
          f"{C.BOLD}Ports   :{C.R}  {len(ports)}   "
          f"{C.BOLD}Type    :{C.R}  {scan_type.value}")
    print(f"  {C.BOLD}Timing  :{C.R}  T{args.timing} ({t_desc})")
    print(f"  {C.BOLD}Timeout :{C.R}  {timeout}s   "
          f"{C.BOLD}Threads :{C.R}  {threads}   "
          f"{C.BOLD}Banner  :{C.R}  {'yes' if do_banner else 'no'}   "
          f"{C.BOLD}OS      :{C.R}  {'yes' if do_os else 'no'}   "
          f"{C.BOLD}Closed  :{C.R}  {'show' if args.closed else 'hidden'}")
    print()

    progress = ProgressBar()
    verbose  = args.verbose

    # BUG FIX: Separate the found_cb to avoid lambda tuple/None ambiguity
    if verbose:
        def _found_cb(pr):
            danger = pr.port in DANGEROUS_PORTS
            col = C.RED if danger else C.GRN
            tag = f" {C.YLW}[!DANGER]{C.R}" if danger else ""
            progress.clear()
            print(
                f"  {col}[+] {pr.port:<6}/{pr.protocol:<4} OPEN  "
                f"{pr.service:<20}  {pr.version or pr.banner or ''}{C.R}{tag}"
            )
    else:
        _found_cb = None

    scanner  = NetScanner(
        scan_type   = scan_type,
        timeout     = timeout,
        threads     = threads,
        do_banner   = do_banner,
        do_cve      = not getattr(args, "no_cve", False),
        skip_ping   = args.Pn,
        os_detect   = do_os,
        show_closed = args.closed,
        rate_limit  = getattr(args, "rate_limit", 0.0),
        progress_cb = progress.update,
        found_cb    = _found_cb,
    )

    all_results = []
    parallel = getattr(args, "parallel_hosts", 1)
    if parallel > 1 and len(targets) > 1:
        print(f"  {C.CYN}[*] Parallel mode: {parallel} hosts simultaneously{C.R}\n")
        for result in scanner.scan_many(targets, ports, max_parallel_hosts=parallel):
            progress.clear()
            print(format_result(result, verbose=verbose))
            all_results.append(result)
    else:
        for target in targets:
            print(f"  {C.CYN}[*] Scanning: {C.BOLD}{target}{C.R}  "
                  f"{C.GRY}({len(ports)} ports){C.R}")
            result = scanner.scan(target, ports)
            progress.clear()
            print(format_result(result, verbose=verbose))
            all_results.append(result)

    if len(all_results) > 1:
        print(format_summary(all_results))

    def _save(fmt, path):
        try:
            save(all_results, path, fmt)
            print(f"  {C.GRN}[✓] {fmt.upper()} saved → {os.path.abspath(path)}{C.R}")
        except Exception as e:
            print(f"  {C.RED}[!] Save error {path}: {e}{C.R}")

    if getattr(args, "oH", None): _save("html", args.oH)
    if args.oN:            _save("txt",      args.oN)
    if args.oJ: _save("json",     args.oJ)
    if args.oX: _save("xml",      args.oX)
    if args.oG: _save("grepable", args.oG)
    if args.oA:
        _save("txt",      args.oA + ".txt")
        _save("json",     args.oA + ".json")
        _save("xml",      args.oA + ".xml")
        _save("grepable", args.oA + ".gnmap")
        _save("html",     args.oA + ".html")

    print()
