#!/usr/bin/env python3
"""
NetScanner — Full Release
Entry point: interactive menu, CLI, or GUI

  python main.py            → interactive menu
  python main.py 192.168.1.1 → direct CLI scan
  python main.py --gui       → open GUI directly
  python main.py --help      → show all options
"""

import sys
import os
import platform

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.chdir(ROOT)   # always run from project root

from netscanner.core.scanner import VERSION, BUILD, GITHUB

# ── Color support ─────────────────────────────────────────────
def _colors():
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return sys.stdout.isatty()

_USE_COLOR = _colors()
def _c(code): return code if _USE_COLOR else ""

CYN = _c("\033[96m"); GRN = _c("\033[92m"); YLW = _c("\033[93m")
RED = _c("\033[91m"); WHT = _c("\033[97m"); BLD = _c("\033[1m")
DIM = _c("\033[2m");  MAG = _c("\033[95m"); RST = _c("\033[0m")

# ── Banner ────────────────────────────────────────────────────
BANNER = f"""
{CYN}{BLD}  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{RST}

  {GRN}NetScanner — {VERSION}{RST}  {DIM}|{RST}  {WHT}Professional Port Scanner{RST}  {DIM}|{RST}  {CYN}{GITHUB}{RST}
"""

MENU = f"""
  {BLD}{WHT}What would you like to do?{RST}

  {GRN}[1]{RST}  {WHT}Launch GUI{RST}               {DIM}— NetScanner Visual Interface{RST}
  {GRN}[2]{RST}  {WHT}Interactive CLI Scan{RST}      {DIM}— Step-by-step terminal scan{RST}
  {GRN}[3]{RST}  {WHT}Quick Scan{RST}                {DIM}— Enter IP, scan top-100 instantly{RST}
  {GRN}[4]{RST}  {WHT}DNS Lookup{RST}                {DIM}— Resolve domain → IP address(es){RST}
  {GRN}[5]{RST}  {WHT}List Port Profiles{RST}        {DIM}— Show available scan profiles{RST}
  {GRN}[6]{RST}  {WHT}Help / All Options{RST}        {DIM}— Full CLI reference{RST}
  {RED}[0]{RST}  {WHT}Exit{RST}

  {CYN}Choice:{RST} """


def main():
    args = sys.argv[1:]

    # No args → interactive menu
    if not args:
        _interactive_menu()
        return

    # --gui flag
    if "--gui" in args:
        _launch_gui()
        return

    # Everything else → direct CLI
    from netscanner.cli.cli import run_cli
    run_cli()


# ── Interactive menu ──────────────────────────────────────────
def _interactive_menu():
    print(BANNER)
    while True:
        try:
            choice = input(MENU).strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {YLW}Exiting...{RST}\n")
            sys.exit(0)

        print()
        if   choice == "1": _launch_gui();       print()
        elif choice == "2": _cli_interactive()
        elif choice == "3": _quick_scan()
        elif choice == "4": _dns_lookup()
        elif choice == "5": _list_profiles()
        elif choice == "6": _show_help()
        elif choice == "0":
            print(f"  {YLW}Exiting...{RST}\n"); sys.exit(0)
        else:
            print(f"  {RED}[!] Invalid choice. Enter 0-6.{RST}\n")


# ── [1] Launch GUI ────────────────────────────────────────────
def _launch_gui():
    print(f"  {GRN}[*] Starting NetScanner Visual Interface...{RST}\n")
    try:
        import tkinter  # noqa: F401 – check availability first
    except ImportError:
        print(f"  {RED}[!] tkinter not found.{RST}")
        print(f"  {YLW}    Linux fix:  sudo apt install python3-tk{RST}")
        print(f"  {YLW}    Windows:    reinstall Python and tick 'tcl/tk' option{RST}")
        input(f"\n  Press Enter to return to menu...")
        return

    try:
        from netscanner.gui.app import launch_gui
        launch_gui()   # blocks until window is closed
    except Exception as e:
        print(f"  {RED}[!] GUI error: {e}{RST}")
        input(f"\n  Press Enter to return to menu...")


# ── [2] Interactive CLI scan ──────────────────────────────────
def _cli_interactive():
    print(f"  {CYN}{'─'*58}{RST}")
    print(f"  {BLD}{WHT}Interactive CLI Scan{RST}")
    print(f"  {CYN}{'─'*58}{RST}")
    print(f"  {DIM}Leave blank + Enter to cancel{RST}\n")

    try:
        target = input(f"  {CYN}Target IP / hostname / domain:{RST} ").strip()
        if not target:
            return

        print(f"\n  {BLD}Port profile:{RST}")
        print(f"  {GRN}[1]{RST} top-100    {DIM}(100 common ports — fast){RST}")
        print(f"  {GRN}[2]{RST} top-1000   {DIM}(1000 ports — thorough){RST}")
        print(f"  {GRN}[3]{RST} web        {DIM}(HTTP/HTTPS ports){RST}")
        print(f"  {GRN}[4]{RST} 1-65535    {DIM}(all ports — slow){RST}")
        print(f"  {GRN}[5]{RST} Custom     {DIM}(enter manually, e.g. 22,80,443){RST}")

        pc = input(f"\n  {CYN}Selection [1-5, Enter=1]:{RST} ").strip()
        pmap = {"1":"top-100","2":"top-1000","3":"web","4":"1-65535","":"top-100"}
        if pc == "5":
            ports = input(f"  {CYN}Ports (22,80 or 1-1024):{RST} ").strip() or "top-100"
        else:
            ports = pmap.get(pc, "top-100")

        timing = input(f"  {CYN}Speed [1=Slow … 5=Fast, Enter=3]:{RST} ").strip()
        if timing not in ("1","2","3","4","5"):
            timing = "3"

        print(f"\n  {BLD}Detection options:{RST}")
        bn_raw = input(f"  {CYN}Banner / version detection? [Y/n]:{RST} ").strip().lower()
        os_raw = input(f"  {CYN}OS detection? [Y/n]:{RST} ").strip().lower()
        cl_raw = input(f"  {CYN}Show closed ports? [y/N]:{RST} ").strip().lower()

        # Fix: 'n' / 'no' means off; anything else (including blank) = yes
        do_banner = bn_raw not in ("n", "no")
        do_os     = os_raw not in ("n", "no")
        do_closed = cl_raw in ("y", "yes")

        argv = [target, "-p", ports, f"-T{timing}"]
        if do_banner:   argv.append("-b")
        if do_os:       argv.append("-O")
        if do_closed:   argv.append("--closed")
        argv.append("-v")   # verbose in interactive mode

        print(f"\n  {GRN}[*] Running: netscanner {' '.join(argv)}{RST}")
        print(f"  {CYN}{'─'*58}{RST}\n")

        from netscanner.cli.cli import run_cli
        run_cli(argv)

    except KeyboardInterrupt:
        print(f"\n\n  {YLW}Scan cancelled.{RST}\n")

    input(f"\n  Press Enter to return to menu...")


# ── [3] Quick scan ────────────────────────────────────────────
def _quick_scan():
    print(f"  {CYN}{'─'*58}{RST}")
    print(f"  {BLD}{WHT}Quick Scan  (top-100, banner+OS){RST}")
    print(f"  {CYN}{'─'*58}{RST}\n")
    try:
        target = input(f"  {CYN}Target IP or hostname:{RST} ").strip()
        if not target:
            return
        print()
        from netscanner.cli.cli import run_cli
        run_cli([target, "-p", "top-100", "-T4", "-b", "-O", "-v"])
    except KeyboardInterrupt:
        print(f"\n\n  {YLW}Cancelled.{RST}\n")
    input(f"\n  Press Enter to return to menu...")


# ── [4] DNS lookup ────────────────────────────────────────────
def _dns_lookup():
    print(f"  {CYN}{'─'*58}{RST}")
    print(f"  {BLD}{WHT}DNS Lookup — Domain → IP Resolution{RST}")
    print(f"  {CYN}{'─'*58}{RST}\n")
    try:
        domain = input(f"  {CYN}Domain / hostname:{RST} ").strip()
        if not domain:
            return
        print()

        from netscanner.core.scanner import resolve_domain_info
        info = resolve_domain_info(domain)

        print(f"  {BLD}Domain  :{RST} {info.get('domain', domain)}")
        ips = info.get("ips", [])
        if ips:
            for i, ip in enumerate(ips):
                print(f"  {BLD}IP [{i+1}]  :{RST} {GRN}{ip}{RST}")
        else:
            print(f"  {RED}Could not resolve {domain}{RST}")
        if info.get("hostname"):
            print(f"  {BLD}Hostname:{RST} {info['hostname']}")
        if info.get("error"):
            print(f"  {RED}Error: {info['error']}{RST}")

        if ips:
            scan = input(f"\n  {CYN}Scan {ips[0]}? [Y/n]:{RST} ").strip().lower()
            if scan not in ("n","no"):
                from netscanner.cli.cli import run_cli
                run_cli([ips[0], "-p", "top-100", "-T4", "-b"])

    except KeyboardInterrupt:
        print(f"\n\n  {YLW}Cancelled.{RST}\n")
    input(f"\n  Press Enter to return to menu...")


# ── [5] List profiles ─────────────────────────────────────────
def _list_profiles():
    from netscanner.core.scanner import PORT_PROFILES
    print(f"  {CYN}{'─'*58}{RST}")
    print(f"  {BLD}{WHT}Available Port Profiles{RST}")
    print(f"  {CYN}{'─'*58}{RST}")
    print(f"  {BLD}{'PROFILE':<14}{'PORTS':<10}SAMPLE{RST}")
    print(f"  {'─'*56}")
    for name, ports in PORT_PROFILES.items():
        s  = sorted(ports)
        ex = str(s[:4])[:-1] + ", ...]" if len(s) > 4 else str(s)
        print(f"  {GRN}{name:<14}{RST}{len(ports):<10}{DIM}{ex}{RST}")
    print(f"  {CYN}{'─'*58}{RST}\n")
    input(f"  Press Enter to return to menu...")


# ── [6] Help ─────────────────────────────────────────────────
def _show_help():
    from netscanner.cli.cli import build_parser
    print()
    build_parser().print_help()
    print()
    input(f"\n  Press Enter to return to menu...")


if __name__ == "__main__":
    main()
