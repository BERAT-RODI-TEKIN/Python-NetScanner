# ⬡ NetScanner v1.3

```
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

  Professional Port Scanner  |  v1.3
  github.com/BERAT-RODI-TEKIN/Python-NetScanner
```

> **Professional cross-platform port scanner — CLI + Visual Interface**  
> TCP/UDP scanning · Banner grabbing · OS detection · CVE hints · HTML reports · Parallel host scanning  
> Zero external dependencies — pure Python stdlib.  
> Works on **Kali Linux**, **Ubuntu/Debian**, **Windows**.

---

## 🆕 What's New in v1.3

| Feature | Description |
|---|---|
| 🔴 **CVE Hint Database** | 24+ ports mapped to known CVEs — BlueKeep, EternalBlue, Heartbleed, Log4Shell and more |
| 🌐 **HTML Report** | Beautiful standalone dark-theme report (`-oH report.html`) with CVE highlighting |
| ⚡ **Parallel Host Scanning** | Scan multiple hosts simultaneously (`--parallel-hosts N`) |
| 🔍 **Service Fingerprinting** | Regex-based accurate version extraction (OpenSSH, nginx, Apache, Dovecot…) |
| 🐢 **Rate Limiting** | `--rate-limit 0.05` — IDS-friendly slow scan mode |
| 🔐 **SSL/TLS cert info** | Real TLS handshake: protocol version, cipher, CN, expiry date |

---

## 🚀 Installation

### 🐧 Linux / Kali — One command

```bash
git clone https://github.com/BERAT-RODI-TEKIN/Python-NetScanner.git
cd Python-NetScanner
sudo bash install.sh
```

### 🪟 Windows

```bat
git clone https://github.com/BERAT-RODI-TEKIN/Python-NetScanner.git
cd Python-NetScanner
install.bat
```

### Manual

```bash
git clone https://github.com/BERAT-RODI-TEKIN/Python-NetScanner.git
cd Python-NetScanner/NS4
python main.py
```

**Requirements:** Python 3.8+ — no pip installs needed.

---

## 📖 Usage

### Interactive menu

```bash
python main.py
```

### CLI — Quick examples

```bash
# Basic scan
python main.py 192.168.1.1

# Scan with banner detection + OS fingerprint
python main.py 192.168.1.1 -p top-100 -b -O

# Aggressive scan — all detection + CVE hints
python main.py 192.168.1.1 -p top-1000 -A

# Full port scan, save HTML report
python main.py 192.168.1.1 -p 1-65535 -T4 -oH report.html

# Subnet scan — parallel hosts (v1.3)
python main.py 192.168.1.0/24 -p top-100 -T4 --parallel-hosts 10

# Save all formats at once
python main.py target.com -p top-100 -A -oA results
# → results.txt, results.json, results.xml, results.gnmap, results.html

# UDP scan
python main.py 192.168.1.1 -sU -p 53,161,123

# Rate-limited scan (IDS-friendly)
python main.py target.com -p top-100 --rate-limit 0.1

# Disable CVE hints
python main.py 192.168.1.1 -p top-100 --no-cve

# DNS lookup only
python main.py google.com --resolve

# Launch GUI
python main.py --gui
```

---

## 🎯 Port Profiles

| Profile | Ports | Use case |
|---|---|---|
| `top-100` | 100 common ports | Fast everyday scan |
| `top-1000` | 1–1000 | Thorough scan |
| `web` | 80,443,8080,8443… | Web server audit |
| `db` | 3306,5432,27017… | Database exposure check |
| `mail` | 25,110,143,465… | Mail server scan |
| `remote` | 22,23,3389,5900… | Remote access audit |
| `vuln` | Common exploit ports | Quick vuln sweep |
| `all` | 1–65535 | Full scan |

---

## ⏱ Timing Templates

| Level | Timeout | Threads | Description |
|---|---|---|---|
| `-T1` | 3.0s | 50 | Sneaky — very slow, IDS-friendly |
| `-T2` | 2.0s | 100 | Polite — moderate |
| `-T3` | 1.0s | 300 | Normal *(default)* |
| `-T4` | 0.5s | 500 | Aggressive — fast |
| `-T5` | 0.2s | 800 | Insane — maximum speed |

---

## 📤 Output Formats

| Flag | Format | Description |
|---|---|---|
| `-oH file.html` | HTML | **NEW v1.3** — Beautiful dark-theme visual report |
| `-oJ file.json` | JSON | Machine-readable, all fields |
| `-oX file.xml` | XML | Structured, importable |
| `-oN file.txt` | Text | Plain terminal output |
| `-oG file.gnmap` | Grepable | Grep-friendly one-liner |
| `-oA basename` | All | Saves all 5 formats at once |

---

## 🔴 CVE Hint Database (v1.3)

NetScanner automatically checks open ports against a built-in CVE database:

| Port | Notable CVEs |
|---|---|
| 22 (SSH) | CVE-2023-38408 (OpenSSH agent RCE), CVE-2018-15473 (user enum) |
| 80/443 (HTTP/S) | CVE-2021-41773 (Apache path traversal), Heartbleed |
| 139/445 (SMB) | EternalBlue (WannaCry), SMBGhost, PetitPotam |
| 3389 (RDP) | BlueKeep, DejaBlue — pre-auth RCE, no credentials needed |
| 6379 (Redis) | CVE-2022-0543 Lua sandbox escape, unauthenticated access |
| 2375 (Docker) | Container escape, daemon without TLS |
| 9200 (Elasticsearch) | Unauthenticated data access, script eval RCE |
| 27017 (MongoDB) | Unauthenticated database access |

> ⚠ CVE hints are informational. Always verify with a proper vulnerability scanner.

---

## 📂 Project Structure

```
NS4/
├── main.py                      # Entry point — menu, CLI, GUI router
├── netscanner/
│   ├── core/
│   │   ├── scanner.py           # Scan engine, CVE DB, fingerprinting
│   │   ├── output.py            # Terminal, JSON, XML, grepable output
│   │   └── report.py            # HTML report generator (v1.3)
│   ├── cli/
│   │   └── cli.py               # CLI argument parser, progress bar
│   └── gui/
│       └── app.py               # Tkinter dark-theme GUI
├── tests/
│   └── test_netscanner.py       # 80 unit tests (v1.3)
├── install.sh                   # Linux installer
├── install.bat                  # Windows installer
└── README.md
```

---

## 🧪 Running Tests

```bash
cd NS4
PYTHONPATH=. python tests/test_netscanner.py
```

Expected: **80 tests, 0 failures** (1 skipped in restricted environments).

---

## 📋 Full Changelog

### v1.3 (current)
- **NEW** CVE hint database (24 ports, 40+ CVE entries)
- **NEW** HTML report generator (`-oH`, included in `-oA`)
- **NEW** Parallel multi-host scanning (`scan_many()`, `--parallel-hosts`)
- **NEW** Service fingerprinting with regex patterns
- **NEW** Rate limiting (`--rate-limit SEC`)
- **NEW** `--no-cve` flag to disable CVE hints
- **NEW** SSL/TLS: real cert CN + expiry in banner
- **NEW** `critical_cves` property on `ScanResult`
- **IMPROVED** `-oA` now includes HTML output

### v1.2
- **FIX** `is_host_up()` correctly returns `False` for unreachable hosts
- **FIX** UDP uses protocol-specific payloads (DNS, NTP, SNMP, IKE…)
- **FIX** SSL/TLS ports do real TLS handshake (cert info, cipher, protocol)
- **FIX** `detect_os()` uses `subprocess.run()` — no `CalledProcessError` leak
- **FIX** Large CIDR guard: `/8` requires `--force-large-scan`
- **PERF** DNS resolution cache (avoids repeat lookups on subnet scans)
- **PERF** Adaptive thread cap: `min(threads, len(ports))`

### v1.1
- Thread cap (`_MAX_THREADS = 1000`)
- Terminal injection protection (ANSI sanitization)
- DNS reverse timeout with daemon thread
- IPv6 bracket stripping
- Cross-platform ECONNREFUSED codes (Windows/macOS/BSD/Linux)
- ZeroDivisionError fix in `parse_ports()`
- Cisco/Solaris TTL≤255 OS detection

### v1.0
- Initial release: TCP/UDP scanning, banner grabbing, OS detection
- CLI (argparse, nmap-style) + GUI (Tkinter dark theme)
- 8 port profiles, 5 timing templates
- JSON/XML/grepable/text output formats

---

## ⚖️ Legal

**For authorized security testing only.**  
Only scan systems you own or have explicit written permission to test.  
Unauthorized port scanning may be illegal in your jurisdiction.

---

*Made by [BERAT-RODI-TEKIN](https://github.com/BERAT-RODI-TEKIN)*  
*NetScanner v1.3 — 2026*
