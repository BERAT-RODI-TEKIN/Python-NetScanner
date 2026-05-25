"""
NetScanner — Full Release
Core scanning engine: TCP/UDP, banner grabbing, OS detection, DNS lookup
"""

import socket
import threading
import time
import ipaddress
import re
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Callable, Tuple
from enum import Enum

VERSION    = "Full Release"
BUILD      = "3.0.0"
GITHUB     = "https://github.com/BERAT-RODI-TEKIN/Python-NetScanner"
YEAR       = "2026"


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
    port:     int
    state:    PortState
    service:  str = "unknown"
    banner:   str = ""
    version:  str = ""
    protocol: str = "tcp"
    reason:   str = ""
    extra:    str = ""


@dataclass
class ScanResult:
    target:        str
    ip:            str       = ""
    hostname:      str       = ""
    resolved_from: str       = ""   # domain → IP
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


# ── Service database ──────────────────────────────────────────
SERVICE_DB: Dict[int, str] = {
    7:"echo", 9:"discard", 13:"daytime", 19:"chargen",
    20:"ftp-data", 21:"ftp", 22:"ssh", 23:"telnet",
    25:"smtp", 37:"time", 43:"whois", 53:"dns",
    67:"dhcp-s", 68:"dhcp-c", 69:"tftp", 79:"finger",
    80:"http", 88:"kerberos", 110:"pop3", 111:"rpcbind",
    113:"ident", 119:"nntp", 123:"ntp", 135:"msrpc",
    137:"netbios-ns", 138:"netbios-dgm", 139:"netbios-ssn",
    143:"imap", 161:"snmp", 162:"snmptrap", 179:"bgp",
    194:"irc", 389:"ldap", 443:"https", 445:"smb",
    465:"smtps", 500:"isakmp", 512:"rexec", 513:"rlogin",
    514:"rsh", 515:"lpd", 587:"smtp-sub", 631:"ipp",
    636:"ldaps", 873:"rsync", 902:"vmware", 990:"ftps",
    993:"imaps", 995:"pop3s", 1080:"socks5", 1194:"openvpn",
    1433:"mssql", 1521:"oracle", 1723:"pptp", 1883:"mqtt",
    2049:"nfs", 2082:"cpanel", 2083:"cpanel-ssl",
    2181:"zookeeper", 2222:"ssh-alt", 2375:"docker",
    2376:"docker-ssl", 3000:"http-dev", 3306:"mysql",
    3389:"rdp", 3690:"svn", 4444:"metasploit",
    4848:"glassfish", 5000:"upnp", 5432:"postgresql",
    5601:"kibana", 5672:"amqp", 5900:"vnc",
    5985:"winrm-http", 5986:"winrm-https",
    6379:"redis", 6443:"kubernetes", 6667:"irc",
    7001:"weblogic", 7474:"neo4j", 8000:"http-alt",
    8080:"http-proxy", 8081:"http-alt2", 8443:"https-alt",
    8888:"jupyter", 9000:"sonarqube", 9090:"prometheus",
    9092:"kafka", 9200:"elasticsearch", 9300:"elasticsearch-tcp",
    10000:"webmin", 11211:"memcached", 15672:"rabbitmq",
    27017:"mongodb", 27018:"mongodb-shard",
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


# ── DNS / Domain → IP resolution ─────────────────────────────
def resolve_target(target: str) -> Tuple[str, str, str]:
    """
    Returns (ip, hostname, resolved_from).
    Works for: IPs, hostnames, domain names (google.com, etc.)
    """
    # Already an IP?
    try:
        ipaddress.ip_address(target)
        # Reverse lookup
        try:
            hostname = socket.gethostbyaddr(target)[0]
        except Exception:
            hostname = ""
        return target, hostname, ""
    except ValueError:
        pass

    # Hostname / domain — resolve to IP
    try:
        ip = socket.gethostbyname(target)
        # Also try reverse
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = target
        return ip, hostname, target
    except socket.gaierror as e:
        return "", "", f"DNS error: {e}"


def resolve_domain_info(domain: str) -> Dict[str, str]:
    """
    Return all IPs for a domain (multiple A records).
    """
    info = {"domain": domain, "ips": [], "hostname": ""}
    try:
        results = socket.getaddrinfo(domain, None)
        ips = list(dict.fromkeys(r[4][0] for r in results))
        info["ips"] = ips
        if ips:
            try:
                info["hostname"] = socket.gethostbyaddr(ips[0])[0]
            except Exception:
                info["hostname"] = domain
    except Exception as e:
        info["error"] = str(e)
    return info


# ── Banner grabbing ───────────────────────────────────────────
HTTP_PROBE = (
    b"HEAD / HTTP/1.0\r\n"
    b"Host: target\r\n"
    b"User-Agent: NetScanner/3.0\r\n"
    b"Accept: */*\r\n\r\n"
)

def grab_banner(ip: str, port: int, timeout: float = 2.5) -> Tuple[str, str, str]:
    """Returns (banner, version, extra)."""
    svc = SERVICE_DB.get(port, "")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            if svc in ("http","http-alt","http-alt2","http-proxy","http-dev") \
               or port in (80, 8080, 8000, 8081, 3000, 9000, 8888):
                s.send(HTTP_PROBE)
            elif port in (443, 8443) or svc in ("https","https-alt"):
                return "SSL/TLS", "HTTPS (SSL/TLS encrypted)", ""
            else:
                time.sleep(0.35)
                try:
                    s.send(b"\r\n")
                except Exception:
                    pass

            try:
                raw = s.recv(4096).decode("utf-8", errors="replace")
            except socket.timeout:
                return "", "", ""

            if not raw.strip():
                return "", "", ""

            lines = [l.strip() for l in raw.split("\n") if l.strip()]
            first = lines[0][:100] if lines else ""

            # HTTP response
            if raw.startswith("HTTP/"):
                banner  = first[:80]
                version = ""
                extra   = []
                for line in lines:
                    low = line.lower()
                    if low.startswith("server:"):
                        version = line[7:].strip()[:60]
                    elif low.startswith("x-powered-by:"):
                        extra.append(line[13:].strip())
                    elif low.startswith("location:"):
                        extra.append("→ " + line[9:].strip()[:40])
                return banner, version, "  ".join(extra[:2])

            # SSH
            m = re.search(r"SSH-([\d.]+)-(\S+)", first)
            if m:
                ver = f"SSH-{m.group(1)} / {m.group(2)}"
                return first[:80], ver, ""

            # FTP / SMTP / POP3
            if re.match(r"^2[0-9][0-9][\s-]", first):
                return first[:80], first[:60], ""

            if first.startswith("+OK"):
                return first[:80], first[:60], ""

            return first[:80], first[:60], ""

    except (ConnectionRefusedError, OSError):
        return "", "", ""
    except Exception:
        return "", "", ""


# ── TCP Connect scan ─────────────────────────────────────────
def tcp_connect(ip: str, port: int, timeout: float = 1.0,
                do_banner: bool = True) -> PortResult:
    svc = SERVICE_DB.get(port, "unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            err = s.connect_ex((ip, port))

        if err == 0:
            banner, version, extra = ("", "", "")
            if do_banner:
                banner, version, extra = grab_banner(
                    ip, port, min(timeout * 2.5, 4.0))
            return PortResult(port, PortState.OPEN, svc,
                              banner, version, "tcp", "syn-ack", extra)
        if err in (10061, 111, 61):  # ECONNREFUSED
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


# ── UDP scan ─────────────────────────────────────────────────
def udp_scan_port(ip: str, port: int, timeout: float = 2.0) -> PortResult:
    svc = SERVICE_DB.get(port, "unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00" * 8, (ip, port))
            try:
                data, _ = s.recvfrom(1024)
                return PortResult(port, PortState.OPEN, svc,
                                  data[:30].hex(), "", "udp", "response")
            except socket.timeout:
                return PortResult(port, PortState.OPEN_FILTERED, svc,
                                  "", "", "udp", "no-response")
    except PermissionError:
        return PortResult(port, PortState.FILTERED, svc,
                          "", "", "udp", "need-root")
    except Exception as e:
        return PortResult(port, PortState.FILTERED, svc,
                          "", "", "udp", str(e)[:20])


# ── Host discovery ────────────────────────────────────────────
def is_host_up(ip: str, timeout: float = 2.0) -> bool:
    try:
        flags = ["-n","1","-w","1000"] if platform.system()=="Windows" \
                else ["-c","1","-W","1"]
        r = subprocess.run(["ping"]+flags+[ip],
                           capture_output=True, timeout=3)
        if r.returncode == 0:
            return True
    except Exception:
        pass
    for p in (80, 443, 22, 445, 8080, 135):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, p)) == 0:
                    return True
        except Exception:
            pass
    return True  # assume up (could be firewalled)


# ── OS detection ─────────────────────────────────────────────
def detect_os(ip: str) -> Tuple[str, int]:
    try:
        flags = ["-n","1"] if platform.system()=="Windows" else ["-c","1"]
        out = subprocess.check_output(
            ["ping"]+flags+[ip],
            timeout=4, stderr=subprocess.DEVNULL
        ).decode("utf-8", errors="replace")
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


# ── Target / Port parsers ─────────────────────────────────────
def parse_targets(raw: str) -> List[str]:
    targets = []
    for part in raw.replace(" ", "").split(","):
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
            hosts = list(net.hosts())
            targets.extend(str(h) for h in hosts) if hosts else \
                targets.append(str(net.network_address))
        except ValueError:
            m = re.match(r"^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$", part)
            if m:
                prefix, s, e = m.group(1), int(m.group(2)), int(m.group(3))
                targets.extend(f"{prefix}.{i}" for i in range(s, e+1))
            else:
                targets.append(part)  # hostname / domain
    return targets


def parse_ports(raw: str) -> List[int]:
    if raw in PORT_PROFILES:
        return sorted(set(PORT_PROFILES[raw]))
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit():
                ports.extend(range(int(a), min(int(b)+1, 65536)))
        elif part.isdigit():
            n = int(part)
            if 0 < n < 65536:
                ports.append(n)
    return sorted(set(ports))


# ── Main Scanner class ────────────────────────────────────────
class NetScanner:
    def __init__(
        self,
        scan_type:   ScanType  = ScanType.TCP_CONNECT,
        timeout:     float     = 1.0,
        threads:     int       = 300,
        do_banner:   bool      = True,
        skip_ping:   bool      = False,
        os_detect:   bool      = False,
        show_closed: bool      = False,
        progress_cb: Optional[Callable[[int, int], None]] = None,
        found_cb:    Optional[Callable[[PortResult], None]] = None,
    ):
        self.scan_type   = scan_type
        self.timeout     = timeout
        self.threads     = threads
        self.do_banner   = do_banner
        self.skip_ping   = skip_ping
        self.os_detect   = os_detect
        self.show_closed = show_closed
        self.progress_cb = progress_cb
        self.found_cb    = found_cb
        self._stop       = threading.Event()

    def stop(self):
        self._stop.set()

    def scan(self, target: str, ports: List[int]) -> ScanResult:
        self._stop.clear()
        r = ScanResult(target=target, scan_type=self.scan_type)
        r.start_time    = time.time()
        r.total_scanned = len(ports)

        # DNS / hostname resolution
        ip, hostname, resolved_from = resolve_target(target)
        if not ip:
            r.error    = resolved_from or f"Cannot resolve: {target}"
            r.end_time = time.time()
            return r

        r.ip            = ip
        r.hostname      = hostname
        r.resolved_from = resolved_from

        # Host up?
        if not self.skip_ping:
            r.is_up = is_host_up(r.ip, self.timeout * 2)

        # OS detection
        if self.os_detect:
            r.os_hint, r.ttl = detect_os(r.ip)

        # Scan function  (must be separate if/else — one-liner lambda causes parse bug)
        if self.scan_type == ScanType.UDP:
            fn = lambda p: udp_scan_port(r.ip, p, self.timeout)
        else:
            fn = lambda p: tcp_connect(r.ip, p, self.timeout, self.do_banner)

        total = len(ports)
        done  = 0
        lock  = threading.Lock()

        def _scan(port: int) -> Optional[PortResult]:
            nonlocal done
            if self._stop.is_set():
                return None
            pr = fn(port)
            with lock:
                done += 1
                if self.progress_cb:
                    self.progress_cb(done, total)
            if pr.state == PortState.OPEN and self.found_cb:
                self.found_cb(pr)
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
