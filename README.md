# ⬡ NetScanner v1.4

```
  _   _ _____ _____ ____   ____    _    _   _ _   _ _____ ____  
 | \ | | ____|_   _/ ___| / ___|  / \  | \ | | \ | | ____|  _ \ 
 |  \| |  _|   | | \___ \| |     / _ \ |  \| |  \| |  _| | |_) |
 | |\  | |___  | |  ___) | |___ / ___ \| |\  | |\  | |___|  _ < 
 |_| \_|_____| |_| |____/ \____/_/   \_\_| \_|_| \_|_____|_| \_\
```

> **Professional cross-platform port scanner — CLI + GUI**
> TCP/UDP · Banner · OS detect · CVE hints · HTML reports · Parallel scanning
> Zero external dependencies — pure Python stdlib.
> **Windows · Linux · Kali · macOS**

---

## 🆕 What's New in v1.4

| # | Feature | Description |
|---|---|---|
| 🔧 | **EXE Linux fix** | Box-drawing chars no longer corrupt on Linux terminals |
| 📁 | **Save location picker** | Choose Desktop, current folder, or custom path when saving |
| 🌐 | **Subnet Scan menu** | New `[4]` menu option — subnet/range scan with parallel hosts |
| ⚙️ | **GitHub Actions** | Auto test + EXE build on every push/tag |
| 🧹 | **Clean repo** | `.gitignore`, removed AI comment clutter from shell scripts |
| 🐛 | **CVE table fix** | Full descriptions no longer truncated in terminal |
| 🐛 | **Fingerprint fix** | OpenSSH version now correctly parsed (`8.9p1` not `2.0`) |

## 📋 Full Changelog

### v1.4 (current)
- **FIX** EXE on Linux — UTF-8 stdout forced, box-drawing chars have ASCII fallback
- **FIX** CVE description truncation — full text now shown
- **FIX** Fingerprint regex — OpenSSH/nginx/Apache versions correctly extracted
- **NEW** Save location picker — Desktop / current folder / custom path
- **NEW** Subnet Scan option in interactive menu (`[4]`)
- **NEW** GitHub Actions — CI tests + Windows/Linux EXE build on tag push
- **NEW** `.gitignore` — clean repo, no pyc/exe/output files committed

### v1.3
- CVE hint database (24 ports, 40+ CVE entries)
- HTML report generator (`-oH`, included in `-oA`)
- Parallel multi-host scanning (`scan_many()`, `--parallel-hosts`)
- Service fingerprinting with regex patterns
- Rate limiting (`--rate-limit SEC`)
- SSL/TLS real cert handshake (CN, expiry, cipher)
- `--no-cve` flag

### v1.2
- `is_host_up()` correctly returns `False` for unreachable hosts
- UDP protocol-specific payloads (DNS, NTP, SNMP…)
- SSL/TLS real TLS handshake
- `detect_os()` uses `subprocess.run()`
- Large CIDR guard (`--force-large-scan`)
- DNS resolution cache
- Adaptive thread cap

### v1.1
- Thread cap (`_MAX_THREADS = 1000`)
- Terminal injection protection (ANSI sanitization)
- DNS reverse timeout
- IPv6 bracket stripping
- Cross-platform ECONNREFUSED codes

### v1.0
- Initial release: TCP/UDP scanning, banner, OS detection
- CLI (argparse, nmap-style) + GUI (Tkinter dark theme)
- 8 port profiles, 5 timing templates
- JSON/XML/grepable/text output

---

## 🚀 Installation

### 🐧 Linux / Kali
```bash
git clone https://github.com/BERAT-RODI-TEKIN/Python-NetScanner.git
cd Python-NetScanner
sudo bash install.sh
netscanner --help
```

### 🪟 Windows
```
Sağ tıkla install.bat → Yönetici olarak çalıştır
Yeni terminal: netscanner --help
```

### Manual (no install)
```bash
git clone https://github.com/BERAT-RODI-TEKIN/Python-NetScanner.git
cd Python-NetScanner
python main.py
```

---

## 📖 Usage

### Interactive menu
```bash
netscanner          # or: python main.py
```

```
[1] Launch GUI
[2] Interactive CLI Scan    ← adım adım, kayıt konumu seçimi
[3] Quick Scan
[4] Subnet Scan             ← v1.4 NEW — parallel host scanning
[5] DNS Lookup
[6] List Port Profiles
[7] Help / All Options
```

### Terminal — Direct commands
```bash
# Temel tarama
netscanner 192.168.1.1

# Agresif — banner + OS + CVE
netscanner 192.168.1.1 -A

# Subnet — 10 host aynı anda
netscanner 192.168.1.0/24 -p top-100 -T4 --parallel-hosts 10

# HTML rapor kaydet
netscanner 192.168.1.1 -A -oH rapor.html

# Hepsini kaydet
netscanner 192.168.1.1 -A -oA sonuclar
# → sonuclar.txt  sonuclar.html  sonuclar.json  sonuclar.xml  sonuclar.gnmap

# Yavaş tarama (IDS-friendly)
netscanner 192.168.1.1 -p top-100 --rate-limit 0.1

# CVE ipuçlarını kapat
netscanner 192.168.1.1 -p top-100 --no-cve
```

---

## 🎯 Port Profiles

| Profile | Ports | Use case |
|---|---|---|
| `top-100` | 100 common | Fast everyday scan |
| `top-1000` | 1–1000 | Thorough scan |
| `web` | 80,443,8080… | Web server audit |
| `db` | 3306,5432,27017… | Database exposure |
| `mail` | 25,110,143… | Mail server scan |
| `remote` | 22,23,3389,5900… | Remote access audit |
| `vuln` | Common exploit ports | Quick vuln sweep |
| `all` | 1–65535 | Full scan |

---

## ⏱ Timing Templates

| Flag | Timeout | Threads | |
|---|---|---|---|
| `-T1` | 3.0s | 50 | Sneaky |
| `-T2` | 2.0s | 100 | Polite |
| `-T3` | 1.0s | 300 | Normal *(default)* |
| `-T4` | 0.5s | 500 | Fast |
| `-T5` | 0.2s | 800 | Insane |

---

## 📤 Output Formats

| Flag | Format | |
|---|---|---|
| `-oH file.html` | HTML | Dark-theme visual report + CVE highlighting |
| `-oN file.txt` | Text | Clean plain text, no ANSI |
| `-oJ file.json` | JSON | Machine-readable |
| `-oX file.xml` | XML | Structured |
| `-oG file.gnmap` | Grepable | grep-friendly |
| `-oA basename` | All | All 5 formats at once |

---

## 🔴 CVE Hint Database

```
CRITICAL  445/smb   CVE-2017-0144  EternalBlue — SMBv1 RCE (WannaCry/NotPetya)
CRITICAL  3389/rdp  CVE-2019-0708  BlueKeep — RDP pre-auth RCE (no credentials)
CRITICAL  6379/redis CVE-2022-0543 Lua sandbox escape — arbitrary code exec
```

> ⚠ CVE hints are informational. Always verify with a dedicated scanner.

---

## 📂 Project Structure

```
├── main.py                        # Entry point, interactive menu
├── netscanner/
│   ├── core/
│   │   ├── scanner.py             # Scan engine, CVE DB, fingerprinting
│   │   ├── output.py              # Terminal, JSON, XML, grepable, txt
│   │   └── report.py              # HTML report generator
│   ├── cli/cli.py                 # CLI argument parser
│   └── gui/app.py                 # Tkinter dark-theme GUI
├── tests/test_netscanner.py       # 80 unit tests
├── .github/workflows/
│   ├── test.yml                   # CI — auto test on push
│   └── build.yml                  # Build EXE on tag push
├── .gitignore
├── install.sh                     # Linux installer
├── install.bat                    # Windows installer
└── README.md
```

---

## 🧪 Tests
```bash
cd NS4
PYTHONPATH=. python tests/test_netscanner.py
# Expected: 80 tests, 0 failures
```

---

## ⚖️ Legal
For authorized security testing only. Only scan systems you own or have explicit written permission to test.

*Made by [BERAT-RODI-TEKIN](https://github.com/BERAT-RODI-TEKIN) — NetScanner v1.4 — 2026*
