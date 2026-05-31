"""
NetScanner v1.3
Core scanning engine

CHANGELOG v1.3:
  [NEW] Parallel multi-host scanning (scan_many) — all hosts concurrently
  [NEW] CVE hint database — known vulnerabilities per port/version
  [NEW] Service fingerprinting — regex-based accurate version detection
  [NEW] Rate limiting support — configurable delay between port scans
  [NEW] scan_many() returns results as they complete (generator)
  [FIX] All v1.2 bug fixes preserved
  [FIX] is_host_up correctly returns False for unreachable hosts
  [FIX] UDP uses protocol-specific payloads
  [FIX] SSL/TLS does real handshake for cert/version info
  [FIX] detect_os uses subprocess.run (no CalledProcessError)
  [FIX] Large CIDR guard (>65536 hosts requires --force-large-scan)
  [PERF] DNS cache, adaptive thread cap
"""

import socket
import ssl
import threading
import time
import ipaddress
import re
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Callable, Tuple, Iterator
from enum import Enum

VERSION = "v1.3"
BUILD   = "1.3.0"
GITHUB  = "https://github.com/BERAT-RODI-TEKIN/Python-NetScanner"
YEAR    = "2026"

_MAX_THREADS            = 1000
_LARGE_CIDR_THRESHOLD   = 65536

_dns_cache: Dict[str, Tuple[str, str, str]] = {}
_dns_cache_lock = threading.Lock()

_ANSI_RE = re.compile(
    r'\x1b\[[0-9;]*[mGKHFABCDSTJRsu]'
    r'|[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]'
)

def _sanitize(text: str, maxlen: int = 200) -> str:
    return _ANSI_RE.sub('', text)[:maxlen]


# ─────────────────────────────────────────────
# CVE HINT DATABASE
# port → list of (cve_id, description, severity)
# severity: CRITICAL / HIGH / MEDIUM / INFO
# ─────────────────────────────────────────────
CVE_HINTS: Dict[int, List[Tuple[str, str, str]]] = {
    21:  [("CVE-2011-2523", "vsftpd 2.3.4 backdoor (smiley face exploit)", "CRITICAL"),
          ("CVE-2015-3306", "ProFTPD mod_copy unauthenticated file copy", "CRITICAL")],
    22:  [("CVE-2023-38408", "OpenSSH ssh-agent remote code exec (< 9.3p2)", "CRITICAL"),
          ("CVE-2016-6515",  "OpenSSH 7.x DoS via long password auth loop", "HIGH"),
          ("CVE-2018-15473", "OpenSSH username enumeration (< 7.7)", "MEDIUM")],
    23:  [("CVE-GENERIC",    "Telnet transmits credentials in plaintext", "HIGH")],
    25:  [("CVE-2014-3566",  "SMTP POODLE — SSLv3 downgrade attack", "HIGH"),
          ("CVE-2020-7247",  "OpenSMTPD RCE via malformed FROM address", "CRITICAL")],
    80:  [("CVE-2021-41773", "Apache 2.4.49 path traversal + RCE", "CRITICAL"),
          ("CVE-2022-22965", "Spring4Shell — Spring Framework RCE", "CRITICAL")],
    110: [("CVE-2014-3566",  "POP3 POODLE — SSLv3 padding oracle", "HIGH")],
    135: [("CVE-2003-0352",  "MS03-026 DCOM RPC buffer overflow (Blaster worm)", "CRITICAL")],
    139: [("CVE-2017-0144",  "EternalBlue — SMBv1 RCE (WannaCry/NotPetya)", "CRITICAL")],
    143: [("CVE-2021-30807", "IMAP memory corruption — macOS/iOS", "CRITICAL")],
    443: [("CVE-2014-0160",  "Heartbleed — OpenSSL TLS heartbeat info leak", "CRITICAL"),
          ("CVE-2022-0778",  "OpenSSL BN_mod_sqrt infinite loop DoS", "HIGH"),
          ("CVE-2021-3449",  "OpenSSL 1.1.1 NULL deref DoS via renegotiation", "HIGH")],
    445: [("CVE-2017-0144",  "EternalBlue — SMBv1 RCE (WannaCry/NotPetya)", "CRITICAL"),
          ("CVE-2020-0796",  "SMBGhost — SMBv3 compression buffer overflow", "CRITICAL"),
          ("CVE-2021-36942", "PetitPotam — NTLM relay via MS-EFSRPC", "HIGH")],
    1433:[("CVE-2020-0618",  "SQL Server Reporting Services RCE", "CRITICAL"),
          ("CVE-2019-1068",  "SQL Server Full-Text Search RCE", "HIGH")],
    2375:[("CVE-2019-5736",  "Docker runc container escape (< 18.09.2)", "CRITICAL"),
          ("CVE-GENERIC",    "Docker daemon exposed without TLS — full control", "CRITICAL")],
    3306:[("CVE-2021-2307",  "MySQL InnoDB Cluster privilege escalation", "HIGH"),
          ("CVE-2020-14878", "MySQL Server DoS via crafted request", "MEDIUM")],
    3389:[("CVE-2019-0708",  "BlueKeep — RDP pre-auth RCE (no credentials)", "CRITICAL"),
          ("CVE-2020-0609",  "DejaBlue — RDP heap overflow RCE", "CRITICAL"),
          ("CVE-2019-1181",  "DejaBlue variant — same impact as BlueKeep", "CRITICAL")],
    4444:[("CVE-GENERIC",    "Default Metasploit listener port — active backdoor?", "CRITICAL")],
    5432:[("CVE-2019-9193",  "PostgreSQL COPY TO/FROM PROGRAM arbitrary code exec", "HIGH")],
    5900:[("CVE-2015-5239",  "VNC integer overflow via RFB protocol", "HIGH"),
          ("CVE-2019-15681", "LibVNCServer memory leak via unauthenticated conn", "HIGH")],
    6379:[("CVE-2022-0543",  "Redis Lua sandbox escape — arbitrary code exec", "CRITICAL"),
          ("CVE-GENERIC",    "Redis exposed without auth — full DB access", "CRITICAL")],
    8080:[("CVE-2021-41773", "Apache 2.4.49 path traversal if on alt port", "HIGH")],
    8443:[("CVE-2014-0160",  "Heartbleed applies to HTTPS on alt ports too", "CRITICAL")],
    9200:[("CVE-2014-3120",  "Elasticsearch RCE via dynamic script eval (< 1.4.3)", "CRITICAL"),
          ("CVE-GENERIC",    "Elasticsearch exposed without auth — full data access", "HIGH")],
    11211:[("CVE-2018-1000115","Memcached UDP amplification DDoS reflection", "HIGH"),
           ("CVE-GENERIC",    "Memcached exposed without auth — full cache read/write", "HIGH")],
    27017:[("CVE-2019-2386",  "MongoDB user re-login after logout race condition", "MEDIUM"),
           ("CVE-GENERIC",    "MongoDB exposed without auth — full DB access", "CRITICAL")],
}

def get_cve_hints(port: int, version: str = "") -> List[Tuple[str, str, str]]:
    """Return CVE hints for a port. Filters by version string if provided."""
    hints = CVE_HINTS.get(port, [])
    if not hints:
        return []
    # If we have version info, try to refine (basic keyword match)
    if version:
        v_lower = version.lower()
        relevant = [h for h in hints if any(
            kw in v_lower for kw in
            ["apache", "openssl", "openssh", "vsftpd", "smb", "rdp",
             "mysql", "postgres", "mongo", "redis", "elastic", "docker"]
        )]
        return relevant if relevant else hints
    return hints


# ─────────────────────────────────────────────
# SERVICE FINGERPRINTING
# Regex patterns for accurate version extraction
# ─────────────────────────────────────────────
_FINGERPRINTS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"SSH-([\d.]+)-OpenSSH_([\d.p]+)", re.I),
     "ssh", "OpenSSH {2}"),
    (re.compile(r"SSH-([\d.]+)-dropbear_([\d.]+)", re.I),
     "ssh", "Dropbear SSH {2}"),
    (re.compile(r"220.*(FileZilla Server) ([\d.]+)", re.I),
     "ftp", "FileZilla {2}"),
    (re.compile(r"220.*(ProFTPD) ([\d.]+)", re.I),
     "ftp", "ProFTPD {2}"),
    (re.compile(r"220.*(vsftpd) ([\d.]+)", re.I),
     "ftp", "vsftpd {2}"),
    (re.compile(r"Server: (nginx)/([\d.]+)", re.I),
     "http", "nginx {2}"),
    (re.compile(r"Server: Apache/([\d.]+)", re.I),
     "http", "Apache {1}"),
    (re.compile(r"Server: (Microsoft-IIS)/([\d.]+)", re.I),
     "http", "IIS {2}"),
    (re.compile(r"Server: (lighttpd)/([\d.]+)", re.I),
     "http", "lighttpd {2}"),
    (re.compile(r"220.*(Postfix)", re.I),
     "smtp", "Postfix"),
    (re.compile(r"220.*(Exim) ([\d.]+)", re.I),
     "smtp", "Exim {2}"),
    (re.compile(r"5\.[\d.]+ (MySQL)", re.I),
     "mysql", "MySQL 5.x"),
    (re.compile(r"(MariaDB)-([\d.]+)", re.I),
     "mysql", "MariaDB {2}"),
    (re.compile(r"\+OK.*dovecot", re.I),
     "pop3", "Dovecot POP3"),
    (re.compile(r"\* OK.*dovecot", re.I),
     "imap", "Dovecot IMAP"),
    (re.compile(r"redis_version:([\d.]+)", re.I),
     "redis", "Redis {1}"),
    (re.compile(r"ElasticSearch.*version.*\"([\d.]+)\"", re.I),
     "elasticsearch", "Elasticsearch {1}"),
]

def fingerprint_version(raw_banner: str, service: str = "") -> str:
    """Extract precise version string from raw banner using regex fingerprints."""
    if not raw_banner:
        return ""
    for pat, svc_hint, tmpl in _FINGERPRINTS:
        m = pat.search(raw_banner)
        if m:
            version = tmpl
            for i, g in enumerate(m.groups(), 1):
                version = version.replace(f"{{{i}}}", g or "")
            return _sanitize(version.strip()[:60])
    return ""


class ScanType(Enum):
    TCP_CONNECT = "TCP Connect"
    UDP         = "UDP"


class PortState(Enum):
    OPEN          = "open"
    CLOSED        = "closed"
    FILTERED      = "filtered"
    OPEN_FILTERED = "open|filtered"


@dataclass
class PortResult:
    port:      int
    state:     PortState
    service:   str = "unknown"
    banner:    str = ""
    version:   str = ""
    protocol:  str = "tcp"
    reason:    str = ""
    extra:     str = ""
    cve_hints: List[Tuple[str, str, str]] = field(default_factory=list)


@dataclass
class ScanResult:
    target:        str
    ip:            str       = ""
    hostname:      str       = ""
    resolved_from: str       = ""
    scan_type:     ScanType  = ScanType.TCP_CONNECT
    ports:         List[PortResult] = field(default_factory=list)
    start_time:    float     = 0.0
    end_time:      float     = 0.0
    os_hint:       str       = ""
    ttl:           int       = 0
    is_up:         bool      = True
    error:         str       = ""
    total_scanned: int       = 0

    @property
    def duration(self) -> float:
        return round(self.end_time - self.start_time, 2)

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == PortState.OPEN]

    @property
    def filtered_ports(self) -> List[PortResult]:
        return [p for p in self.ports
                if p.state in (PortState.FILTERED, PortState.OPEN_FILTERED)]

    @property
    def closed_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == PortState.CLOSED]

    @property
    def critical_cves(self) -> List[Tuple[int, str, str, str]]:
        """Return (port, cve_id, desc, severity) for CRITICAL findings."""
        out = []
        for p in self.open_ports:
            for cve in p.cve_hints:
                if cve[2] == "CRITICAL":
                    out.append((p.port, *cve))
        return out


SERVICE_DB: Dict[int, str] = {
    7:"echo",9:"discard",13:"daytime",19:"chargen",
    20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",
    25:"smtp",37:"time",43:"whois",53:"dns",
    67:"dhcp-s",68:"dhcp-c",69:"tftp",79:"finger",
    80:"http",88:"kerberos",110:"pop3",111:"rpcbind",
    113:"ident",119:"nntp",123:"ntp",135:"msrpc",
    137:"netbios-ns",138:"netbios-dgm",139:"netbios-ssn",
    143:"imap",161:"snmp",162:"snmptrap",179:"bgp",
    194:"irc",389:"ldap",443:"https",445:"smb",
    465:"smtps",500:"isakmp",512:"rexec",513:"rlogin",
    514:"rsh",515:"lpd",587:"smtp-sub",631:"ipp",
    636:"ldaps",873:"rsync",902:"vmware",990:"ftps",
    993:"imaps",995:"pop3s",1080:"socks5",1194:"openvpn",
    1433:"mssql",1521:"oracle",1723:"pptp",1883:"mqtt",
    2049:"nfs",2082:"cpanel",2083:"cpanel-ssl",
    2181:"zookeeper",2222:"ssh-alt",2375:"docker",
    2376:"docker-ssl",3000:"http-dev",3306:"mysql",
    3389:"rdp",3690:"svn",4444:"metasploit",
    4848:"glassfish",5000:"upnp",5432:"postgresql",
    5601:"kibana",5672:"amqp",5900:"vnc",
    5985:"winrm-http",5986:"winrm-https",
    6379:"redis",6443:"kubernetes",6667:"irc",
    7001:"weblogic",7474:"neo4j",8000:"http-alt",
    8080:"http-proxy",8081:"http-alt2",8443:"https-alt",
    8888:"jupyter",9000:"sonarqube",9090:"prometheus",
    9092:"kafka",9200:"elasticsearch",9300:"elasticsearch-tcp",
    10000:"webmin",11211:"memcached",15672:"rabbitmq",
    27017:"mongodb",27018:"mongodb-shard",
}

PORT_PROFILES: Dict[str, List[int]] = {
    "top-100": sorted([
        21,22,23,25,53,80,88,110,111,119,135,137,138,139,143,
        161,194,389,443,445,465,500,512,513,514,515,587,631,636,
        873,902,990,993,995,1080,1433,1521,1723,2049,2082,2083,
        2222,2375,3000,3306,3389,3690,4444,4848,5000,5432,5900,
        5985,5986,6379,6443,6667,7001,8000,8080,8081,8443,8888,
        9000,9090,9200,9300,10000,27017,
    ]),
    "top-1000": list(range(1, 1001)),
    "web":    [80,443,8000,8080,8081,8443,8888,3000,4000,5000,9000,9090],
    "db":     [1433,1521,3306,5432,6379,27017,9200,9300,5601,7474,11211],
    "mail":   [25,110,143,465,587,993,995],
    "remote": [22,23,135,139,445,3389,5900,5985,5986,2222],
    "vuln":   [21,22,23,25,80,110,135,139,143,443,445,1433,3306,3389,5900],
    "all":    list(range(1, 65536)),
}

DANGEROUS_PORTS = frozenset([
    21,23,69,135,137,138,139,445,512,513,514,
    1080,1433,2375,3389,4444,5900,6379,11211,27017,
])

UDP_PROBES: Dict[int, bytes] = {
    53:  (b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
          b"\x07version\x04bind\x00\x00\x10\x00\x03"),
    123: b"\x1b" + b"\x00" * 47,
    161: (b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19"
          b"\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00"
          b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"),
    500: b"\x00" * 28 + b"\x01\x10\x02\x00" + b"\x00" * 4,
    1194:b"\x38" + b"\x00" * 7,
    5353:(b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
          b"\x05local\x00\x00\xff\x00\x01"),
}
_UDP_DEFAULT_PROBE = b"\x00" * 8


def _reverse_dns(ip: str, timeout: float = 2.0) -> str:
    result: List[str] = [""]
    def _lookup():
        try:
            result[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            result[0] = ""
    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(timeout)
    return result[0]


def resolve_target(target: str) -> Tuple[str, str, str]:
    with _dns_cache_lock:
        if target in _dns_cache:
            return _dns_cache[target]
    stripped = target.strip("[]")
    try:
        ipaddress.ip_address(stripped)
        hostname = _reverse_dns(stripped, timeout=2.0)
        result = stripped, hostname, ""
    except ValueError:
        try:
            ip = socket.gethostbyname(target)
            hostname = _reverse_dns(ip, timeout=2.0) or target
            result = ip, hostname, target
        except socket.gaierror as e:
            result = "", "", f"DNS error: {e}"
    with _dns_cache_lock:
        _dns_cache[target] = result
    return result


def resolve_domain_info(domain: str) -> Dict[str, object]:
    info: Dict[str, object] = {"domain": domain, "ips": [], "hostname": ""}
    try:
        results = socket.getaddrinfo(domain, None)
        ips = list(dict.fromkeys(r[4][0] for r in results))
        info["ips"] = ips
        if ips:
            info["hostname"] = _reverse_dns(ips[0], timeout=2.0) or domain
    except Exception as e:
        info["error"] = str(e)
    return info


HTTP_PROBE = (
    b"HEAD / HTTP/1.0\r\n"
    b"Host: target\r\n"
    b"User-Agent: NetScanner/1.3\r\n"
    b"Accept: */*\r\n\r\n"
)

def _grab_ssl_info(ip: str, port: int, timeout: float) -> Tuple[str, str, str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                proto      = s.version() or "TLS"
                cipher     = s.cipher()
                cert       = s.getpeercert()
                cn, expiry = "", ""
                if cert:
                    for fl in cert.get("subject", []):
                        for k, v in fl:
                            if k == "commonName":
                                cn = v
                    expiry = cert.get("notAfter", "")
                cipher_name = cipher[0] if cipher else ""
                banner  = f"SSL/TLS ({proto})"
                version = _sanitize(f"{proto} / {cipher_name}"[:60])
                extra_parts = []
                if cn:
                    extra_parts.append(f"CN={cn[:30]}")
                if expiry:
                    extra_parts.append(f"exp:{expiry[:12]}")
                extra = "  ".join(extra_parts)
                return banner, version, _sanitize(extra[:60])
    except ssl.SSLError as e:
        return "SSL/TLS", f"SSL error: {_sanitize(str(e)[:40])}", ""
    except Exception:
        return "SSL/TLS", "HTTPS (encrypted)", ""


def grab_banner(ip: str, port: int, timeout: float = 2.5) -> Tuple[str, str, str]:
    svc = SERVICE_DB.get(port, "")
    try:
        ssl_ports = {443,8443,990,993,995,465,636}
        ssl_svcs  = {"https","https-alt","imaps","pop3s","smtps","ldaps","ftps"}
        if port in ssl_ports or svc in ssl_svcs:
            return _grab_ssl_info(ip, port, timeout)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if svc in ("http","http-alt","http-alt2","http-proxy","http-dev") \
               or port in (80,8080,8000,8081,3000,9000,8888):
                s.send(HTTP_PROBE)
            else:
                time.sleep(0.3)
                try:
                    s.send(b"\r\n")
                except Exception:
                    pass
            try:
                raw = s.recv(2048).decode("utf-8", errors="replace")
            except socket.timeout:
                return "", "", ""
            if not raw.strip():
                return "", "", ""

            lines  = [l.strip() for l in raw.split("\n") if l.strip()]
            first  = lines[0][:100] if lines else ""

            # Try fingerprint first for best version string
            fp_version = fingerprint_version(raw, svc)

            if raw.startswith("HTTP/"):
                banner, extra_parts = _sanitize(first[:80]), []
                srv_hdr = ""
                for line in lines:
                    low = line.lower()
                    if low.startswith("server:"):
                        srv_hdr = _sanitize(line[7:].strip()[:60])
                    elif low.startswith("x-powered-by:"):
                        extra_parts.append(_sanitize(line[13:].strip()[:30]))
                    elif low.startswith("location:"):
                        extra_parts.append("→ " + _sanitize(line[9:].strip()[:30]))
                version = fp_version or srv_hdr
                return banner, version, "  ".join(extra_parts[:2])

            return _sanitize(first[:80]), fp_version or _sanitize(first[:60]), ""

    except (ConnectionRefusedError, OSError):
        return "", "", ""
    except Exception:
        return "", "", ""


_ECONNREFUSED = frozenset([10061, 111, 61, 146])

def tcp_connect(ip: str, port: int, timeout: float = 1.0,
                do_banner: bool = True,
                do_cve: bool = True) -> PortResult:
    svc = SERVICE_DB.get(port, "unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            err = s.connect_ex((ip, port))

        if err == 0:
            banner, version, extra = "", "", ""
            if do_banner:
                banner, version, extra = grab_banner(
                    ip, port, min(timeout * 2.5, 4.0))
            cves = get_cve_hints(port, version) if do_cve else []
            return PortResult(port, PortState.OPEN, svc,
                              banner, version, "tcp", "syn-ack", extra, cves)
        if err in _ECONNREFUSED:
            return PortResult(port, PortState.CLOSED, svc,
                              "", "", "tcp", "conn-refused")
        return PortResult(port, PortState.FILTERED, svc,
                          "", "", "tcp", f"err({err})")
    except socket.timeout:
        return PortResult(port, PortState.FILTERED, svc,
                          "", "", "tcp", "timeout")
    except ConnectionRefusedError:
        return PortResult(port, PortState.CLOSED, svc,
                          "", "", "tcp", "refused")
    except OSError:
        return PortResult(port, PortState.FILTERED, svc,
                          "", "", "tcp", "os-error")


def udp_scan_port(ip: str, port: int, timeout: float = 2.0) -> PortResult:
    svc   = SERVICE_DB.get(port, "unknown")
    probe = UDP_PROBES.get(port, _UDP_DEFAULT_PROBE)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(probe, (ip, port))
            try:
                data, _ = s.recvfrom(1024)
                return PortResult(port, PortState.OPEN, svc,
                                  _sanitize(data[:30].hex()), "", "udp", "response")
            except socket.timeout:
                return PortResult(port, PortState.OPEN_FILTERED, svc,
                                  "", "", "udp", "no-response")
    except PermissionError:
        return PortResult(port, PortState.FILTERED, svc,
                          "", "", "udp", "need-root")
    except Exception as e:
        return PortResult(port, PortState.FILTERED, svc,
                          "", "", "udp", str(e)[:20])


def is_host_up(ip: str, timeout: float = 2.0) -> bool:
    ping_result = [False]
    def _ping():
        try:
            flags = ["-n","1","-w","1000"] if platform.system() == "Windows" \
                    else ["-c","1","-W","1"]
            r = subprocess.run(["ping"] + flags + [ip],
                               capture_output=True, timeout=3)
            ping_result[0] = (r.returncode == 0)
        except Exception:
            ping_result[0] = False
    pt = threading.Thread(target=_ping, daemon=True)
    pt.start()
    pt.join(3.5)
    if ping_result[0]:
        return True
    for p in (80, 443, 22, 445, 8080, 135):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(min(timeout, 1.0))
                if s.connect_ex((ip, p)) == 0:
                    return True
        except Exception:
            pass
    return False


def detect_os(ip: str) -> Tuple[str, int]:
    try:
        flags = ["-n","1"] if platform.system() == "Windows" else ["-c","1"]
        r = subprocess.run(["ping"] + flags + [ip],
                           capture_output=True, timeout=4)
        out = r.stdout.decode("utf-8", errors="replace")
        m = re.search(r"TTL[=\s]+(\d+)", out, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            if ttl <= 64:
                return f"Linux / Unix  (TTL={ttl})", ttl
            elif ttl <= 128:
                return f"Windows       (TTL={ttl})", ttl
            else:
                return f"Cisco / Solaris (TTL={ttl})", ttl
    except Exception:
        pass
    return "Unknown", 0


def parse_targets(raw: str, confirm_large: bool = False) -> List[str]:
    targets = []
    for part in raw.replace(" ", "").split(","):
        if not part:
            continue
        try:
            net   = ipaddress.ip_network(part, strict=False)
            hosts = list(net.hosts())
            count = len(hosts) if hosts else 1
            if count > _LARGE_CIDR_THRESHOLD and not confirm_large:
                raise ValueError(
                    f"CIDR '{part}' would scan {count:,} hosts. "
                    f"Use --force-large-scan to proceed."
                )
            targets.extend(str(h) for h in hosts) if hosts else \
                targets.append(str(net.network_address))
        except ValueError as e:
            if "CIDR" in str(e):
                raise
            m = re.match(r"^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$", part)
            if m:
                prefix, s, e2 = m.group(1), int(m.group(2)), int(m.group(3))
                targets.extend(f"{prefix}.{i}" for i in range(s, e2+1))
            else:
                targets.append(part)
    return targets


def parse_ports(raw: str) -> List[int]:
    if not raw or not raw.strip():
        return sorted(set(PORT_PROFILES["top-100"]))
    if raw.strip() in PORT_PROFILES:
        return sorted(set(PORT_PROFILES[raw.strip()]))
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            halves = part.split("-", 1)
            if len(halves) == 2 and halves[0].isdigit() and halves[1].isdigit():
                ports.extend(range(int(halves[0]), min(int(halves[1])+1, 65536)))
        elif part.isdigit():
            n = int(part)
            if 0 < n < 65536:
                ports.append(n)
    return sorted(set(ports)) if ports else sorted(set(PORT_PROFILES["top-100"]))


class NetScanner:
    def __init__(
        self,
        scan_type:   ScanType  = ScanType.TCP_CONNECT,
        timeout:     float     = 1.0,
        threads:     int       = 300,
        do_banner:   bool      = True,
        do_cve:      bool      = True,
        skip_ping:   bool      = False,
        os_detect:   bool      = False,
        show_closed: bool      = False,
        rate_limit:  float     = 0.0,
        progress_cb: Optional[Callable[[int, int], None]] = None,
        found_cb:    Optional[Callable[[PortResult], None]] = None,
    ):
        self.scan_type          = scan_type
        self.timeout            = timeout
        self.do_banner          = do_banner
        self.do_cve             = do_cve
        self.skip_ping          = skip_ping
        self.os_detect          = os_detect
        self.show_closed        = show_closed
        self.rate_limit         = rate_limit
        self.progress_cb        = progress_cb
        self.found_cb           = found_cb
        self._stop              = threading.Event()
        self._requested_threads = min(threads, _MAX_THREADS)

    def stop(self):
        self._stop.set()

    def scan(self, target: str, ports: List[int]) -> ScanResult:
        """Scan a single target."""
        self._stop.clear()
        r            = ScanResult(target=target, scan_type=self.scan_type)
        r.start_time = time.time()
        r.total_scanned = len(ports)

        self.threads = min(self._requested_threads, max(len(ports), 1))

        ip, hostname, resolved_from = resolve_target(target)
        if not ip:
            r.error    = resolved_from or f"Cannot resolve: {target}"
            r.end_time = time.time()
            return r

        r.ip            = ip
        r.hostname      = hostname
        r.resolved_from = resolved_from

        if not self.skip_ping:
            r.is_up = is_host_up(r.ip, self.timeout * 2)

        if self.os_detect:
            r.os_hint, r.ttl = detect_os(r.ip)

        if self.scan_type == ScanType.UDP:
            def fn(p): return udp_scan_port(r.ip, p, self.timeout)
        else:
            def fn(p): return tcp_connect(r.ip, p, self.timeout,
                                          self.do_banner, self.do_cve)

        total = len(ports)
        done  = 0
        lock  = threading.Lock()

        def _scan(port: int) -> Optional[PortResult]:
            nonlocal done
            if self._stop.is_set():
                return None
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)
            pr = fn(port)
            with lock:
                done += 1
                if self.progress_cb:
                    try:
                        self.progress_cb(done, total)
                    except Exception:
                        pass
            if pr.state == PortState.OPEN and self.found_cb:
                try:
                    self.found_cb(pr)
                except Exception:
                    pass
            return pr

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            for pr in ex.map(_scan, ports):
                if pr is None:
                    continue
                if self.show_closed:
                    r.ports.append(pr)
                elif pr.state in (PortState.OPEN, PortState.OPEN_FILTERED):
                    r.ports.append(pr)

        r.ports.sort(key=lambda x: x.port)
        r.end_time = time.time()
        return r

    def scan_many(self, targets: List[str], ports: List[int],
                  max_parallel_hosts: int = 10) -> Iterator[ScanResult]:
        """
        v1.3 NEW: Scan multiple hosts in parallel.
        Yields ScanResult objects as each host completes.
        """
        host_threads = min(max_parallel_hosts, len(targets), 20)

        def _scan_host(target: str) -> ScanResult:
            scanner = NetScanner(
                scan_type   = self.scan_type,
                timeout     = self.timeout,
                threads     = max(self._requested_threads // host_threads, 10),
                do_banner   = self.do_banner,
                do_cve      = self.do_cve,
                skip_ping   = self.skip_ping,
                os_detect   = self.os_detect,
                show_closed = self.show_closed,
                rate_limit  = self.rate_limit,
                progress_cb = None,
                found_cb    = self.found_cb,
            )
            return scanner.scan(target, ports)

        with ThreadPoolExecutor(max_workers=host_threads) as ex:
            futures = {ex.submit(_scan_host, t): t for t in targets}
            for future in as_completed(futures):
                try:
                    yield future.result()
                except Exception as e:
                    t = futures[future]
                    r = ScanResult(target=t, error=str(e))
                    r.start_time = r.end_time = time.time()
                    yield r
