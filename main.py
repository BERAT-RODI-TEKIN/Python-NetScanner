#!/usr/bin/env python3
"""
NetScanner v1.4
Entry point: interactive menu, CLI, or GUI

  python main.py              → interactive menu
  python main.py 192.168.1.1  → direct CLI scan
  python main.py --gui        → open GUI directly
  python main.py --help       → show all options
"""

import sys
import os
import platform

# v1.4: Force UTF-8 stdout (fixes broken chars in EXE on Linux)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
else:
    import codecs
    try:
        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, errors="replace")
        sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, errors="replace")
    except Exception:
        pass

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from netscanner.core.scanner import VERSION, BUILD, GITHUB

# ── ASCII Art Banner (pure ASCII, works in every terminal) ───
_NETSCANNER_ART = r"""
  _   _ _____ _____ ____   ____    _    _   _ _   _ _____ ____  
 | \ | | ____|_   _/ ___| / ___|  / \  | \ | | \ | | ____|  _ \ 
 |  \| |  _|   | | \___ \| |     / _ \ |  \| |  \| |  _| | |_) |
 | |\  | |___  | |  ___) | |___ / ___ \| |\  | |\  | |___|  _ < 
 |_| \_|_____| |_| |____/ \____/_/   \_\_| \_|_| \_|_____|_| \_\
"""



# v1.4: Detect if terminal supports unicode box-drawing chars
def _supports_unicode() -> bool:
    try:
        enc = getattr(sys.stdout, "encoding", "") or ""
        if enc.lower().replace("-", "") in ("utf8", "utf16", "utf32"):
            return True
        # EXE on Linux pipe check
        "\u2550".encode(enc)
        return True
    except Exception:
        return False

_UNICODE = _supports_unicode()

# Box chars with ASCII fallback
def _box(char: str, fallback: str) -> str:
    return char if _UNICODE else fallback

H2  = _box("═", "=")
H1  = _box("─", "-")
VT  = _box("│", "|")

# ── Color support ─────────────────────────────────────────────
def _colors() -> bool:
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


# ── Entry point ───────────────────────────────────────────────
def main():
    args = sys.argv[1:]

    # Direct CLI (has target or flags)
    if args and not args[0].startswith("--gui"):
        from netscanner.cli.cli import run_cli
        run_cli(args)
        return

    # GUI flag
    if args and args[0] == "--gui":
        try:
            from netscanner.gui.app import launch_gui
            launch_gui()
        except ImportError:
            print(f"{RED}[!] GUI requires tkinter: sudo apt install python3-tk{RST}")
        return

    # Interactive menu
    _interactive_menu()


# ── Interactive menu ──────────────────────────────────────────
def _interactive_menu():
    while True:
        os.system("cls" if platform.system() == "Windows" else "clear")
        print(f"{CYN}{BLD}{_NETSCANNER_ART}{RST}")
        print(f"  {CYN}{BLD}{VERSION}  |  Professional Port Scanner  |  {GITHUB}{RST}")
        print(f"  {CYN}{'-'*70}{RST}")
        print(f"""

  {GRN}[1]{RST}  Launch GUI               {DIM}{H1} NetScanner Visual Interface{RST}
  {GRN}[2]{RST}  Interactive CLI Scan     {DIM}{H1} Step-by-step terminal scan{RST}
  {GRN}[3]{RST}  Quick Scan               {DIM}{H1} Enter IP, scan top-100 instantly{RST}
  {GRN}[4]{RST}  Subnet Scan              {DIM}{H1} Scan entire network range{RST}
  {GRN}[5]{RST}  DNS Lookup               {DIM}{H1} Resolve domain to IP address(es){RST}
  {GRN}[6]{RST}  List Port Profiles       {DIM}{H1} Show available scan profiles{RST}
  {GRN}[7]{RST}  Help / All Options       {DIM}{H1} Full CLI reference{RST}
  {RED}[0]{RST}  Exit
""")
        choice = input(f"  {CYN}Select [{H1}]:{RST} ").strip()
        if   choice == "1": _launch_gui()
        elif choice == "2": _cli_interactive()
        elif choice == "3": _quick_scan()
        elif choice == "4": _subnet_scan()
        elif choice == "5": _dns_lookup()
        elif choice == "6": _list_profiles()
        elif choice == "7": _show_help()
        elif choice == "0": print(f"\n  {GRN}Goodbye!{RST}\n"); sys.exit(0)


def _launch_gui():
    try:
        from netscanner.gui.app import launch_gui
        launch_gui()
    except ImportError:
        print(f"\n  {RED}[!] GUI requires tkinter.{RST}")
        print(f"  {YLW}Install: sudo apt install python3-tk{RST}\n")
        input("  Press Enter to return...")


# ── [2] Interactive CLI scan ──────────────────────────────────
def _cli_interactive():
    os.system("cls" if platform.system() == "Windows" else "clear")
    print(f"  {CYN}{H2*52}{RST}")
    print(f"  {BLD}{WHT}Interactive CLI Scan{RST}")
    print(f"  {CYN}{H2*52}{RST}\n")
    try:
        target = input(f"  {CYN}Target (IP / domain / CIDR):{RST} ").strip()
        if not target:
            return

        print(f"\n  {BLD}Port Profile:{RST}")
        print(f"  {GRN}[1]{RST} top-100   {DIM}(default, fast){RST}")
        print(f"  {GRN}[2]{RST} top-1000")
        print(f"  {GRN}[3]{RST} web       {DIM}(80,443,8080...){RST}")
        print(f"  {GRN}[4]{RST} db        {DIM}(mysql,postgres...){RST}")
        print(f"  {GRN}[5]{RST} vuln      {DIM}(common exploit ports){RST}")
        print(f"  {GRN}[6]{RST} Custom    {DIM}(e.g. 22,80,443 or 1-1000){RST}")
        pc = input(f"\n  {CYN}Profile [1-6, Enter=1]:{RST} ").strip()
        ports = {
            "1": "top-100", "2": "top-1000",
            "3": "web", "4": "db", "5": "vuln",
        }.get(pc, "top-100")
        if pc == "6":
            ports = input(f"  {CYN}Custom ports:{RST} ").strip() or "top-100"

        print(f"\n  {BLD}Timing:{RST}")
        print(f"  {GRN}[1]{RST} T1 Sneaky  {GRN}[2]{RST} T2 Polite  {GRN}[3]{RST} T3 Normal  "
              f"{GRN}[4]{RST} T4 Fast  {GRN}[5]{RST} T5 Insane")
        tc = input(f"  {CYN}Timing [1-5, Enter=3]:{RST} ").strip()
        timing = tc if tc in ("1","2","3","4","5") else "3"

        do_banner = input(f"\n  {CYN}Banner detection? [Y/n]:{RST} ").strip().lower() != "n"
        do_os     = input(f"  {CYN}OS detection? [Y/n]:{RST} ").strip().lower() != "n"
        do_cve    = input(f"  {CYN}CVE hints? [Y/n]:{RST} ").strip().lower() != "n"
        do_closed = input(f"  {CYN}Show closed ports? [y/N]:{RST} ").strip().lower() == "y"

        # v1.4: Kayıt konumu seçimi
        print(f"\n  {BLD}Output / Save:{RST}")
        print(f"  {GRN}[1]{RST} Sadece ekran")
        print(f"  {GRN}[2]{RST} TXT dosyası")
        print(f"  {GRN}[3]{RST} HTML raporu     {DIM}(tarayıcıda aç){RST}")
        print(f"  {GRN}[4]{RST} Hepsi           {DIM}(txt + html + json + xml){RST}")

        sc = input(f"\n  {CYN}Kaydetme [1-4, Enter=1]:{RST} ").strip()
        save_path = ""
        if sc in ("2","3","4"):
            default_name = f"scan_{target.replace('.','_').replace('/','_')}"
            # v1.4: Kayıt konumu seçimi
            print(f"\n  {BLD}Kayıt konumu:{RST}")
            print(f"  {GRN}[1]{RST} Mevcut klasör    {DIM}({os.getcwd()}){RST}")
            print(f"  {GRN}[2]{RST} Masaüstü")
            print(f"  {GRN}[3]{RST} Özel klasör")
            lc = input(f"  {CYN}Konum [1-3, Enter=1]:{RST} ").strip()

            if lc == "2":
                if platform.system() == "Windows":
                    save_dir = os.path.join(os.environ.get("USERPROFILE",""), "Desktop")
                else:
                    save_dir = os.path.join(os.path.expanduser("~"), "Desktop")
            elif lc == "3":
                save_dir = input(f"  {CYN}Klasör yolu:{RST} ").strip()
                if not os.path.isdir(save_dir):
                    print(f"  {YLW}Klasör bulunamadı, mevcut klasör kullanılıyor.{RST}")
                    save_dir = os.getcwd()
            else:
                save_dir = os.getcwd()

            fname = input(f"  {CYN}Dosya adı [Enter={default_name}]:{RST} ").strip() or default_name
            save_path = os.path.join(save_dir, fname)

            if sc == "2":
                print(f"  {YLW}Kaydedilecek: {save_path}.txt{RST}")
            elif sc == "3":
                print(f"  {YLW}Kaydedilecek: {save_path}.html{RST}")
            elif sc == "4":
                print(f"  {YLW}Kaydedilecek: {save_path}.txt / .html / .json / .xml{RST}")

        argv = [target, "-p", ports, f"-T{timing}"]
        if do_banner: argv.append("-b")
        if do_os:     argv.append("-O")
        if do_closed: argv.append("--closed")
        if not do_cve: argv.append("--no-cve")
        argv.append("-v")

        if sc == "2" and save_path: argv += ["-oN", f"{save_path}.txt"]
        elif sc == "3" and save_path: argv += ["-oH", f"{save_path}.html"]
        elif sc == "4" and save_path: argv += ["-oA", save_path]

        print(f"\n  {GRN}[*] netscanner {' '.join(argv)}{RST}")
        print(f"  {CYN}{H1*58}{RST}\n")

        from netscanner.cli.cli import run_cli
        run_cli(argv)

    except KeyboardInterrupt:
        print(f"\n\n  {YLW}Cancelled.{RST}\n")

    input(f"\n  Press Enter to return to menu...")


# ── [3] Quick scan ────────────────────────────────────────────
def _quick_scan():
    os.system("cls" if platform.system() == "Windows" else "clear")
    print(f"  {CYN}{H2*52}{RST}")
    print(f"  {BLD}{WHT}Quick Scan  (top-100, T4, banner+OS+CVE){RST}")
    print(f"  {CYN}{H2*52}{RST}\n")
    try:
        target = input(f"  {CYN}Target:{RST} ").strip()
        if not target:
            return

        # v1.4: Kayıt seçimi
        print(f"\n  {BLD}Kaydet?{RST}")
        print(f"  {GRN}[1]{RST} Sadece ekran  {GRN}[2]{RST} TXT  {GRN}[3]{RST} HTML  {GRN}[4]{RST} Hepsi")
        sq = input(f"  {CYN}[1-4, Enter=1]:{RST} ").strip()

        qargs = [target, "-p", "top-100", "-T4", "-b", "-O", "-v"]
        if sq in ("2","3","4"):
            default_name = f"scan_{target.replace('.','_').replace('/','_')}"

            print(f"\n  {BLD}Kayıt konumu:{RST}")
            print(f"  {GRN}[1]{RST} Mevcut klasör  {GRN}[2]{RST} Masaüstü  {GRN}[3]{RST} Özel klasör")
            lc = input(f"  {CYN}[1-3, Enter=1]:{RST} ").strip()

            if lc == "2":
                if platform.system() == "Windows":
                    save_dir = os.path.join(os.environ.get("USERPROFILE",""), "Desktop")
                else:
                    save_dir = os.path.join(os.path.expanduser("~"), "Desktop")
            elif lc == "3":
                save_dir = input(f"  {CYN}Klasör:{RST} ").strip()
                if not os.path.isdir(save_dir):
                    save_dir = os.getcwd()
            else:
                save_dir = os.getcwd()

            qname = input(f"  {CYN}Dosya adı [Enter={default_name}]:{RST} ").strip() or default_name
            qpath = os.path.join(save_dir, qname)

            if sq == "2":
                print(f"  {YLW}→ {qpath}.txt{RST}")
                qargs += ["-oN", f"{qpath}.txt"]
            elif sq == "3":
                print(f"  {YLW}→ {qpath}.html{RST}")
                qargs += ["-oH", f"{qpath}.html"]
            elif sq == "4":
                print(f"  {YLW}→ {qpath}.txt / .html / .json / .xml{RST}")
                qargs += ["-oA", qpath]

        print(f"\n  {GRN}[*] Scanning...{RST}\n")
        from netscanner.cli.cli import run_cli
        run_cli(qargs)

    except KeyboardInterrupt:
        print(f"\n\n  {YLW}Cancelled.{RST}\n")
    input(f"\n  Press Enter to return to menu...")


# ── [4] Subnet scan ───────────────────────────────────────────
def _subnet_scan():
    os.system("cls" if platform.system() == "Windows" else "clear")
    print(f"  {CYN}{H2*52}{RST}")
    print(f"  {BLD}{WHT}Subnet / Network Scan{RST}")
    print(f"  {CYN}{H2*52}{RST}\n")
    try:
        target = input(f"  {CYN}Target (CIDR or range, e.g. 192.168.1.0/24):{RST} ").strip()
        if not target:
            return

        print(f"\n  {BLD}Port Profile:{RST}")
        print(f"  {GRN}[1]{RST} top-100  {GRN}[2]{RST} web  {GRN}[3]{RST} remote  {GRN}[4]{RST} vuln  {GRN}[5]{RST} Custom")
        pc  = input(f"  {CYN}[1-5, Enter=1]:{RST} ").strip()
        ports = {"1":"top-100","2":"web","3":"remote","4":"vuln"}.get(pc,"top-100")
        if pc == "5":
            ports = input(f"  {CYN}Custom ports:{RST} ").strip() or "top-100"

        ph  = input(f"\n  {CYN}Parallel hosts [1-20, Enter=5]:{RST} ").strip()
        parallel = ph if ph.isdigit() and 1 <= int(ph) <= 20 else "5"

        # Kayıt seçimi
        print(f"\n  {BLD}Kaydet?{RST}")
        print(f"  {GRN}[1]{RST} Sadece ekran  {GRN}[2]{RST} TXT  {GRN}[3]{RST} HTML  {GRN}[4]{RST} Hepsi")
        sq = input(f"  {CYN}[1-4, Enter=1]:{RST} ").strip()

        sargs = [target, "-p", ports, "-T4", "-Pn", f"--parallel-hosts={parallel}", "-v"]

        if sq in ("2","3","4"):
            default_name = f"subnet_{target.replace('.','_').replace('/','_')}"
            print(f"\n  {BLD}Kayıt konumu:{RST}")
            print(f"  {GRN}[1]{RST} Mevcut klasör  {GRN}[2]{RST} Masaüstü  {GRN}[3]{RST} Özel")
            lc = input(f"  {CYN}[1-3, Enter=1]:{RST} ").strip()
            if lc == "2":
                save_dir = os.path.join(
                    os.environ.get("USERPROFILE", os.path.expanduser("~")), "Desktop")
            elif lc == "3":
                save_dir = input(f"  {CYN}Klasör:{RST} ").strip()
                if not os.path.isdir(save_dir):
                    save_dir = os.getcwd()
            else:
                save_dir = os.getcwd()
            qname = input(f"  {CYN}Dosya adı [Enter={default_name}]:{RST} ").strip() or default_name
            qpath = os.path.join(save_dir, qname)
            if sq == "2":   sargs += ["-oN", f"{qpath}.txt"]
            elif sq == "3": sargs += ["-oH", f"{qpath}.html"]
            elif sq == "4": sargs += ["-oA", qpath]

        print(f"\n  {GRN}[*] Scanning subnet (parallel={parallel})...{RST}\n")
        from netscanner.cli.cli import run_cli
        run_cli(sargs)

    except KeyboardInterrupt:
        print(f"\n\n  {YLW}Cancelled.{RST}\n")
    input(f"\n  Press Enter to return to menu...")


# ── [5] DNS lookup ────────────────────────────────────────────
def _dns_lookup():
    os.system("cls" if platform.system() == "Windows" else "clear")
    print(f"  {CYN}{H2*52}{RST}")
    print(f"  {BLD}{WHT}DNS Lookup{RST}")
    print(f"  {CYN}{H2*52}{RST}\n")
    try:
        from netscanner.cli.cli import run_cli
        target = input(f"  {CYN}Domain:{RST} ").strip()
        if target:
            run_cli([target, "--resolve"])
    except KeyboardInterrupt:
        pass
    input(f"\n  Press Enter to return to menu...")


# ── [6] List profiles ─────────────────────────────────────────
def _list_profiles():
    from netscanner.cli.cli import run_cli
    run_cli(["--list-profiles"])
    input(f"\n  Press Enter to return to menu...")


# ── [7] Help ─────────────────────────────────────────────────
def _show_help():
    from netscanner.cli.cli import run_cli
    try:
        run_cli(["--help"])
    except SystemExit:
        pass
    input(f"\n  Press Enter to return to menu...")


if __name__ == "__main__":
    main()
