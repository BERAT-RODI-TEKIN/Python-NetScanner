# ⬡ NetScanner — Full Release

```
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

  Professional Port Scanner  |  Full Release
  github.com/BERAT-RODI-TEKIN/Python-NetScanner
```

> **Professional cross-platform port scanner — CLI + Visual Interface**
> TCP/UDP scanning, banner grabbing, OS detection, DNS resolution.
> Zero external dependencies — pure Python stdlib.
> Works on **Kali Linux**, **Ubuntu/Debian**, **Windows**.

---

## 🚀 Installation

### 🐧 Linux / Kali — One command install

```bash
git clone https://github.com/BERAT-RODI-TEKIN/Python-NetScanner.git
cd Python-NetScanner
sudo bash install.sh
```

Then just type `netscanner` anywhere:
```bash
netscanner                    # interactive menu + GUI
netscanner 192.168.1.1        # direct CLI scan
netscanner --gui              # open visual interface
```

### 🪟 Windows — Installer

```
1. git clone https://github.com/BERAT-RODI-TEKIN/Python-NetScanner.git
2. Right-click install.bat → "Run as Administrator"
3. Open a new CMD / PowerShell
4. Type: netscanner
```

### 📦 pip install (any platform)

```bash
git clone https://github.com/BERAT-RODI-TEKIN/Python-NetScanner.git
cd Python-NetScanner
pip install -e .
netscanner 192.168.1.1
```

---

## 💻 Running Without Install

```bash
cd Python-NetScanner

# Interactive menu (launches GUI or CLI)
python main.py
python3 main.py

# Direct CLI scan
python main.py 192.168.1.1
python main.py 192.168.1.1 -p top-100 -A

# Open GUI
python main.py --gui
```

---

## 📟 CLI Reference

```
positional arguments:
  target                IP, hostname, domain, CIDR, range, comma-separated

Scan Type:
  -sT                   TCP Connect scan (default)
  -sU                   UDP scan

Port Selection:
  -p PORTS              22,80 | 1-1024 | top-100 | web | db | all ...
  --top-ports N         Scan first N ports

Host Discovery:
  -Pn                   Skip host discovery (treat all as up)

Timing & Performance:
  -T 1-5                1=Sneaky  2=Polite  3=Normal  4=Aggressive  5=Insane
  --timeout SEC         Override socket timeout
  --threads N           Override thread count

Detection:
  -b, --banner          Enable banner / version detection
  -O, --os              OS detection (TTL-based)
  -A, --aggressive      Aggressive: enable -b + -O

DNS / Resolution:
  --resolve             DNS lookup only — domain → IP, no scan

Output:
  -v, --verbose         Show banner on separate line
  --no-color            Disable ANSI colors
  --closed              Also show closed ports (hidden by default)
  -oN FILE              Save normal text
  -oJ FILE              Save JSON
  -oX FILE              Save XML
  -oG FILE              Save grepable format
  -oA NAME              Save all formats (NAME.txt/.json/.xml/.gnmap)

Misc:
  --gui                 Launch Visual Interface
  --list-profiles       List available port profiles
  --version             Show version
```

---

## 🖥️ Usage Examples

```bash
# Basic scan
netscanner 192.168.1.1

# Specific ports
netscanner 192.168.1.1 -p 22,80,443,8080

# Port range
netscanner 192.168.1.1 -p 1-1024

# Named profile
netscanner 192.168.1.1 -p top-1000

# Full port scan (fast)
netscanner 192.168.1.1 -p 1-65535 -T4

# Subnet scan
netscanner 192.168.1.0/24 -p top-100 -T4

# IP range
netscanner 192.168.1.1-20 -p web

# Aggressive: banner + OS detection
netscanner 192.168.1.1 -A -p top-1000

# Domain → IP (DNS lookup only)
netscanner google.com --resolve

# Scan a domain (auto-resolves IP)
netscanner google.com -p 80,443

# UDP scan
netscanner 192.168.1.1 -sU -p 53,161,500

# Save results
netscanner 192.168.1.1 -p top-100 -oJ results.json
netscanner 192.168.1.1 -p top-100 -oA scan_output

# Show closed ports too
netscanner 192.168.1.1 -p top-100 --closed

# Open Visual Interface
netscanner --gui
```

---

## 🗂️ Port Profiles

| Profile    | Ports | Description               |
|------------|-------|---------------------------|
| `top-100`  | 100   | 100 most common ports     |
| `top-1000` | 1000  | Ports 1–1000              |
| `web`      | 12    | HTTP/HTTPS ports          |
| `db`       | 11    | Database ports            |
| `mail`     | 7     | Mail server ports         |
| `remote`   | 9     | RDP, SSH, VNC, WinRM      |
| `vuln`     | 15    | Common vulnerability ports|
| `all`      | 65535 | All ports                 |

---

## 📁 Project Structure

```
Python-NetScanner/
├── main.py                    ← Entry point (menu / CLI / GUI)
├── install.sh                 ← Linux/Kali installer
├── install.bat                ← Windows installer
├── setup.py                   ← pip install support
├── README.md
├── LICENSE
├── netscanner/
│   ├── core/
│   │   ├── scanner.py         ← Scan engine + DNS resolver
│   │   └── output.py          ← Terminal output + JSON/XML/Grepable
│   ├── cli/
│   │   └── cli.py             ← CLI interface (nmap-style)
│   └── gui/
│       └── app.py             ← Visual Interface (dark theme)
└── output/                    ← Scan results saved here
```

---

## ❓ FAQ

**Why does my IP only show 5 open ports?**
That is the correct result. For example, 192.168.1.1 (your router) only
exposes those ports. Open ports ≠ all ports — most are closed or filtered.
Use `--closed` to see all scanned ports.

**"Closed — hidden" means what?**
By default, only OPEN ports are displayed. Closed/filtered ports are hidden
to keep output clean. Add `--closed` to show every port.

**Can I scan a website domain?**
Yes! NetScanner auto-resolves domain names:
```bash
netscanner github.com -p 80,443
netscanner github.com --resolve    # DNS lookup only
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing and research only**.
Scanning systems without explicit permission may violate laws.
The authors accept no liability for misuse.

---

## 📜 License

MIT License — Copyright © 2026 Berat Rodi Tekin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE.
