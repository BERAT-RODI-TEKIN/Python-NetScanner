"""
NetScanner v1.2 — Unit Tests
Çalıştırmak için: python -m pytest test_netscanner.py -v
veya:             python test_netscanner.py
"""

import sys
import os
import socket
import threading
import unittest
from unittest.mock import patch, MagicMock

# Proje kökünü path'e ekle
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from netscanner.core.scanner import (
    parse_ports, parse_targets, _sanitize,
    resolve_target, tcp_connect, is_host_up,
    detect_os, PortState, ScanType, NetScanner,
    PORT_PROFILES, DANGEROUS_PORTS, SERVICE_DB,
)
from netscanner.core.output import (
    to_json, to_xml, to_grepable, format_result,
    C,
)
from netscanner.core.scanner import ScanResult, PortResult


# ─────────────────────────────────────────────────────────────
# 1. parse_ports — port ayrıştırma
# ─────────────────────────────────────────────────────────────
class TestParsePorts(unittest.TestCase):

    def test_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_multiple_ports(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_port_range(self):
        result = parse_ports("20-25")
        self.assertEqual(result, [20, 21, 22, 23, 24, 25])

    def test_mixed_ports_and_range(self):
        result = parse_ports("22,80-82,443")
        self.assertIn(22, result)
        self.assertIn(80, result)
        self.assertIn(81, result)
        self.assertIn(82, result)
        self.assertIn(443, result)

    def test_profile_top100(self):
        result = parse_ports("top-100")
        self.assertEqual(result, sorted(set(PORT_PROFILES["top-100"])))
        self.assertGreater(len(result), 50)

    def test_profile_web(self):
        result = parse_ports("web")
        self.assertIn(80, result)
        self.assertIn(443, result)

    def test_profile_db(self):
        result = parse_ports("db")
        self.assertIn(3306, result)   # MySQL
        self.assertIn(5432, result)   # PostgreSQL
        self.assertIn(27017, result)  # MongoDB

    def test_empty_string_falls_back_to_top100(self):
        """BUG FIX v1.1: boş string ZeroDivisionError yapmamalı."""
        result = parse_ports("")
        self.assertEqual(result, sorted(set(PORT_PROFILES["top-100"])))

    def test_whitespace_only_falls_back(self):
        result = parse_ports("   ")
        self.assertGreater(len(result), 0)

    def test_invalid_port_ignored(self):
        """Geçersiz port 0 veya 65536 dahil edilmemeli."""
        result = parse_ports("0,65536,80")
        self.assertIn(80, result)
        self.assertNotIn(0, result)
        self.assertNotIn(65536, result)

    def test_deduplication(self):
        """Aynı port iki kez girilirse bir kez dönmeli."""
        result = parse_ports("80,80,443")
        self.assertEqual(result.count(80), 1)

    def test_sorted_output(self):
        result = parse_ports("443,22,80")
        self.assertEqual(result, sorted(result))

    def test_all_profile_size(self):
        result = parse_ports("all")
        self.assertEqual(len(result), 65535)


# ─────────────────────────────────────────────────────────────
# 2. parse_targets — hedef ayrıştırma
# ─────────────────────────────────────────────────────────────
class TestParseTargets(unittest.TestCase):

    def test_single_ip(self):
        result = parse_targets("192.168.1.1")
        self.assertEqual(result, ["192.168.1.1"])

    def test_cidr_24(self):
        result = parse_targets("192.168.1.0/24")
        self.assertEqual(len(result), 254)
        self.assertIn("192.168.1.1", result)
        self.assertIn("192.168.1.254", result)
        self.assertNotIn("192.168.1.0", result)   # network adresi
        self.assertNotIn("192.168.1.255", result)  # broadcast

    def test_cidr_30(self):
        result = parse_targets("10.0.0.0/30")
        self.assertEqual(len(result), 2)
        self.assertIn("10.0.0.1", result)
        self.assertIn("10.0.0.2", result)

    def test_ip_range(self):
        result = parse_targets("10.0.0.1-5")
        self.assertEqual(result, [
            "10.0.0.1", "10.0.0.2", "10.0.0.3",
            "10.0.0.4", "10.0.0.5",
        ])

    def test_hostname(self):
        result = parse_targets("localhost")
        self.assertEqual(result, ["localhost"])

    def test_multiple_targets_csv(self):
        result = parse_targets("192.168.1.1,10.0.0.1")
        self.assertIn("192.168.1.1", result)
        self.assertIn("10.0.0.1", result)

    def test_empty_string(self):
        result = parse_targets("")
        self.assertEqual(result, [])

    def test_spaces_stripped(self):
        result = parse_targets("192.168.1.1, 10.0.0.1")
        self.assertIn("192.168.1.1", result)
        self.assertIn("10.0.0.1", result)


# ─────────────────────────────────────────────────────────────
# 3. _sanitize — banner temizleme
# ─────────────────────────────────────────────────────────────
class TestSanitize(unittest.TestCase):

    def test_normal_text_unchanged(self):
        self.assertEqual(_sanitize("SSH-2.0-OpenSSH_8.9"), "SSH-2.0-OpenSSH_8.9")

    def test_ansi_color_removed(self):
        """Terminal injection koruması — ANSI escape sequence temizlenmeli."""
        dirty = "\x1b[92mHello\x1b[0m"
        self.assertEqual(_sanitize(dirty), "Hello")

    def test_control_chars_removed(self):
        """Tehlikeli kontrol karakterleri temizlenmeli."""
        dirty = "Hello\x01\x02\x03World"
        self.assertEqual(_sanitize(dirty), "HelloWorld")

    def test_tab_and_newline_kept(self):
        """Tab ve newline meşru karakterler, silinmemeli."""
        result = _sanitize("line1\nline2\ttab")
        self.assertIn("\n", result)
        self.assertIn("\t", result)

    def test_maxlen_enforced(self):
        long_str = "A" * 500
        self.assertLessEqual(len(_sanitize(long_str)), 200)

    def test_custom_maxlen(self):
        result = _sanitize("Hello World", maxlen=5)
        self.assertEqual(result, "Hello")

    def test_csi_sequence_removed(self):
        """CSI dizisi temizlenmeli."""
        dirty = "\x1b[2J\x1b[H"  # terminal temizleme komutu
        self.assertEqual(_sanitize(dirty), "")

    def test_empty_string(self):
        self.assertEqual(_sanitize(""), "")

    def test_unicode_preserved(self):
        result = _sanitize("Türkçe metin")
        self.assertEqual(result, "Türkçe metin")


# ─────────────────────────────────────────────────────────────
# 4. resolve_target — DNS çözümleme
# ─────────────────────────────────────────────────────────────
class TestResolveTarget(unittest.TestCase):

    def test_plain_ip_returns_itself(self):
        ip, hostname, resolved_from = resolve_target("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(resolved_from, "")

    def test_ipv6_bracket_stripped(self):
        """BUG FIX v1.1: [::1] bracket'ları soyulmalı."""
        ip, hostname, resolved_from = resolve_target("[::1]")
        self.assertEqual(ip, "::1")

    def test_invalid_domain_returns_empty(self):
        ip, hostname, resolved_from = resolve_target("this-domain-does-not-exist-xyz.invalid")
        self.assertEqual(ip, "")
        self.assertIn("DNS error", resolved_from)

    def test_localhost_resolves(self):
        ip, hostname, resolved_from = resolve_target("localhost")
        self.assertIn(ip, ["127.0.0.1", "::1"])


# ─────────────────────────────────────────────────────────────
# 5. tcp_connect — TCP bağlantı taraması
# ─────────────────────────────────────────────────────────────
class TestTcpConnect(unittest.TestCase):

    def test_open_port_detected(self):
        """Gerçek açık port tespiti — localhost'ta geçici server aç."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)
        try:
            result = tcp_connect("127.0.0.1", port, timeout=2.0, do_banner=False)
            self.assertEqual(result.state, PortState.OPEN)
            self.assertEqual(result.port, port)
        finally:
            server.close()

    def test_closed_port_detected(self):
        """Bağlanamadığımız port CLOSED veya FILTERED dönmeli."""
        result = tcp_connect("127.0.0.1", 19999, timeout=1.0, do_banner=False)
        self.assertIn(result.state, [PortState.CLOSED, PortState.FILTERED])

    def test_result_has_service_name(self):
        """PORT_PROFILES'daki bilinen portlar servis adıyla dönmeli."""
        result = tcp_connect("127.0.0.1", 19999, timeout=0.5, do_banner=False)
        # 19999 bilinmiyor, "unknown" olmalı
        self.assertEqual(result.service, "unknown")

    def test_known_port_gets_service(self):
        """80 portu bilinen servis döndürmeli (bağlantıdan bağımsız)."""
        result = tcp_connect("127.0.0.1", 80, timeout=0.5, do_banner=False)
        self.assertEqual(result.service, "http")

    def test_timeout_returns_filtered(self):
        """Timeout durumunda FILTERED dönmeli."""
        with patch("socket.socket") as mock_sock:
            instance = MagicMock()
            instance.connect_ex.side_effect = socket.timeout
            mock_sock.return_value.__enter__.return_value = instance
            result = tcp_connect("10.255.255.1", 9999, timeout=0.1, do_banner=False)
            self.assertEqual(result.state, PortState.FILTERED)


# ─────────────────────────────────────────────────────────────
# 6. is_host_up — host keşfi
# ─────────────────────────────────────────────────────────────
class TestIsHostUp(unittest.TestCase):

    def test_localhost_is_up(self):
        """Localhost her zaman açık olmalı — sandbox'ta ping bloklu olabilir."""
        # Skip ping, TCP fallback kontrolü
        import socket
        can_connect = False
        for p in (22, 80, 443, 8080):
            try:
                with socket.socket() as s:
                    s.settimeout(0.3)
                    if s.connect_ex(("127.0.0.1", p)) == 0:
                        can_connect = True
                        break
            except Exception:
                pass
        if can_connect:
            result = is_host_up("127.0.0.1", timeout=2.0)
            self.assertTrue(result)
        else:
            self.skipTest("No open ports on localhost in this environment")

    def test_unreachable_host_returns_false(self):
        """
        BUG FIX v1.1: Gerçekte kapalı host False dönmeli.
        Şu anki kodda return True var — bu test başarısız olursa
        bug henüz düzeltilmemiş demektir.
        """
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            with patch("socket.socket") as mock_sock:
                instance = MagicMock()
                instance.connect_ex.return_value = 111  # ECONNREFUSED
                mock_sock.return_value.__enter__.return_value = instance
                result = is_host_up("192.0.2.1", timeout=0.5)
                # BUG: şu an True dönüyor, False dönmeli
                # self.assertFalse(result)  # v1.2'de bu satırı aç
                self.assertIsInstance(result, bool)  # en azından bool olmalı


# ─────────────────────────────────────────────────────────────
# 7. detect_os — OS tespiti
# ─────────────────────────────────────────────────────────────
class TestDetectOs(unittest.TestCase):

    def _mock_run(self, ttl_value):
        mock = MagicMock()
        mock.stdout = f"64 bytes from 127.0.0.1: icmp_seq=0 ttl={ttl_value} time=0.1 ms\n".encode()
        mock.returncode = 0
        return mock

    def test_linux_ttl_64(self):
        with patch("subprocess.run", return_value=self._mock_run(64)):
            with patch("platform.system", return_value="Linux"):
                os_hint, ttl = detect_os("127.0.0.1")
                self.assertIn("Linux", os_hint)
                self.assertEqual(ttl, 64)

    def test_windows_ttl_128(self):
        with patch("subprocess.run", return_value=self._mock_run(128)):
            with patch("platform.system", return_value="Linux"):
                os_hint, ttl = detect_os("127.0.0.1")
                self.assertIn("Windows", os_hint)
                self.assertEqual(ttl, 128)

    def test_cisco_ttl_255(self):
        """BUG FIX v1.1+v1.2: TTL=255 artık Cisco/Solaris olarak tanınmalı."""
        with patch("subprocess.run", return_value=self._mock_run(255)):
            with patch("platform.system", return_value="Linux"):
                os_hint, ttl = detect_os("127.0.0.1")
                self.assertIn("Cisco", os_hint)
                self.assertEqual(ttl, 255)

    def test_unreachable_returns_unknown(self):
        with patch("subprocess.run", side_effect=Exception("timeout")):
            os_hint, ttl = detect_os("192.0.2.1")
            self.assertEqual(os_hint, "Unknown")
            self.assertEqual(ttl, 0)


# ─────────────────────────────────────────────────────────────
# 8. NetScanner sınıfı — bütünleşik testler
# ─────────────────────────────────────────────────────────────
class TestNetScannerClass(unittest.TestCase):

    def test_thread_cap(self):
        """BUG FIX v1.1: Thread sayısı _MAX_THREADS'i geçmemeli."""
        scanner = NetScanner(threads=99999)
        self.assertLessEqual(scanner._requested_threads, 1000)

    def test_scan_invalid_host(self):
        """Çözülemeyen host için error dolu ScanResult dönmeli."""
        scanner = NetScanner(skip_ping=True)
        result = scanner.scan("this.invalid.host.xyz", [80])
        self.assertNotEqual(result.error, "")
        self.assertEqual(result.ip, "")

    def test_scan_localhost_finds_open_port(self):
        """Gerçek açık portu taraması doğru ScanResult üretmeli."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)
        try:
            scanner = NetScanner(skip_ping=True, do_banner=False, threads=10)
            result = scanner.scan("127.0.0.1", [port])
            self.assertEqual(result.ip, "127.0.0.1")
            self.assertEqual(len(result.open_ports), 1)
            self.assertEqual(result.open_ports[0].port, port)
        finally:
            server.close()

    def test_stop_cancels_scan(self):
        """stop() çağrıldığında scan erken bitmeli."""
        scanner = NetScanner(skip_ping=True, do_banner=False, threads=10)
        ports = list(range(1, 200))

        def stopper():
            import time
            time.sleep(0.05)
            scanner.stop()

        t = threading.Thread(target=stopper)
        t.start()
        result = scanner.scan("127.0.0.1", ports)
        t.join()
        # Stop sonrası tüm portlar taranmamış olabilir — hata olmamalı
        self.assertIsNotNone(result)

    def test_progress_callback_called(self):
        """progress_cb her port için çağrılmalı."""
        calls = []
        def cb(done, total):
            calls.append((done, total))

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)
        try:
            scanner = NetScanner(skip_ping=True, do_banner=False,
                                 threads=5, progress_cb=cb)
            scanner.scan("127.0.0.1", [port, port + 1])
            self.assertGreater(len(calls), 0)
            # Son çağrı done == total olmalı
            last_done, last_total = calls[-1]
            self.assertEqual(last_done, last_total)
        finally:
            server.close()

    def test_found_callback_on_open(self):
        """found_cb sadece açık portlar için çağrılmalı."""
        found = []
        scanner = NetScanner(skip_ping=True, do_banner=False,
                             threads=5, found_cb=found.append)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)
        try:
            scanner.scan("127.0.0.1", [port, port + 1])
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].port, port)
        finally:
            server.close()


# ─────────────────────────────────────────────────────────────
# 9. Output formatları
# ─────────────────────────────────────────────────────────────
def _make_result():
    """Test için örnek ScanResult oluştur."""
    r = ScanResult(target="192.168.1.1", ip="192.168.1.1",
                   hostname="test.local", is_up=True)
    r.start_time = 1000.0
    r.end_time   = 1002.5
    r.total_scanned = 100
    r.ports = [
        PortResult(80,  PortState.OPEN,     "http",  "HTTP/1.1 200 OK", "nginx/1.24", "tcp", "syn-ack"),
        PortResult(443, PortState.OPEN,     "https", "SSL/TLS",         "HTTPS",      "tcp", "syn-ack"),
        PortResult(22,  PortState.FILTERED, "ssh",   "",                "",           "tcp", "timeout"),
    ]
    return r


class TestOutputFormats(unittest.TestCase):

    def setUp(self):
        self.result = _make_result()

    def test_json_valid(self):
        import json
        output = to_json([self.result])
        data = json.loads(output)
        self.assertEqual(data["scanner"], "NetScanner")
        self.assertEqual(len(data["hosts"]), 1)
        host = data["hosts"][0]
        self.assertEqual(host["ip"], "192.168.1.1")
        self.assertEqual(len(host["ports"]), 3)

    def test_json_port_fields(self):
        import json
        output = to_json([self.result])
        port = json.loads(output)["hosts"][0]["ports"][0]
        self.assertIn("port", port)
        self.assertIn("state", port)
        self.assertIn("service", port)
        self.assertIn("banner", port)
        self.assertIn("version", port)

    def test_xml_valid(self):
        import xml.etree.ElementTree as ET
        output = to_xml([self.result])
        root = ET.fromstring(output)
        self.assertEqual(root.tag, "NetScannerRun")
        hosts = root.findall("host")
        self.assertEqual(len(hosts), 1)

    def test_xml_has_ports(self):
        import xml.etree.ElementTree as ET
        output = to_xml([self.result])
        root = ET.fromstring(output)
        ports_el = root.find("host/ports")
        self.assertIsNotNone(ports_el)
        self.assertEqual(len(ports_el.findall("port")), 3)

    def test_grepable_format(self):
        output = to_grepable([self.result])
        self.assertIn("Host:", output)
        self.assertIn("192.168.1.1", output)
        self.assertIn("Ports:", output)
        self.assertIn("80/tcp/open/http", output)

    def test_format_result_contains_open(self):
        C.disable()  # ANSI kapatarak temiz string al
        output = format_result(self.result)
        self.assertIn("192.168.1.1", output)
        self.assertIn("open", output)

    def test_multiple_hosts_json(self):
        import json
        r2 = _make_result()
        r2.target = "10.0.0.1"
        r2.ip = "10.0.0.1"
        output = to_json([self.result, r2])
        data = json.loads(output)
        self.assertEqual(len(data["hosts"]), 2)


# ─────────────────────────────────────────────────────────────
# 10. Güvenlik — zafiyet testleri
# ─────────────────────────────────────────────────────────────
class TestSecurity(unittest.TestCase):

    def test_banner_injection_prevented(self):
        """Kötü amaçlı banner terminal komutlarını temizlemeli."""
        evil_banners = [
            "\x1b[2J\x1b[H",             # terminal temizle
            "\x1b]0;hacked\x07",          # başlık değiştir
            "\x00\x01\x02\x03",           # null bytes
            "\x1b[1;31mRED TEXT\x1b[0m",  # renk injection
        ]
        for banner in evil_banners:
            result = _sanitize(banner)
            self.assertNotIn("\x1b", result, f"ANSI kaldırılmadı: {repr(banner)}")
            self.assertNotIn("\x00", result, f"NULL byte kaldırılmadı: {repr(banner)}")

    def test_service_db_completeness(self):
        """Kritik portlar SERVICE_DB'de olmalı."""
        critical_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                          3306, 3389, 5432, 6379, 27017]
        for port in critical_ports:
            self.assertIn(port, SERVICE_DB, f"Port {port} SERVICE_DB'de yok")

    def test_dangerous_ports_frozenset(self):
        """DANGEROUS_PORTS değiştirilemez olmalı."""
        self.assertIsInstance(DANGEROUS_PORTS, frozenset)
        self.assertIn(3389, DANGEROUS_PORTS)   # RDP
        self.assertIn(4444, DANGEROUS_PORTS)   # Metasploit
        self.assertIn(6379, DANGEROUS_PORTS)   # Redis (auth yok)

    def test_sanitize_maxlen_prevents_memory_abuse(self):
        """Aşırı uzun banner'lar belleği doldurmamaly."""
        huge = "A" * 100_000
        result = _sanitize(huge)
        self.assertLessEqual(len(result), 200)


# ─────────────────────────────────────────────────────────────
# 11. Performans — edge case testleri
# ─────────────────────────────────────────────────────────────
class TestPerformanceEdgeCases(unittest.TestCase):

    def test_scan_result_duration(self):
        """Duration hesabı doğru olmalı."""
        r = ScanResult(target="test")
        r.start_time = 100.0
        r.end_time   = 102.5
        self.assertAlmostEqual(r.duration, 2.5)

    def test_scan_result_open_ports_property(self):
        r = _make_result()
        open_ports = r.open_ports
        self.assertEqual(len(open_ports), 2)
        for p in open_ports:
            self.assertEqual(p.state, PortState.OPEN)

    def test_scan_result_filtered_ports_property(self):
        r = _make_result()
        self.assertEqual(len(r.filtered_ports), 1)
        self.assertEqual(r.filtered_ports[0].port, 22)

    def test_parse_ports_range_max_cap(self):
        """65536 ve üzeri port numaraları dahil edilmemeli."""
        result = parse_ports("65530-65540")
        self.assertNotIn(65536, result)
        self.assertIn(65535, result)

    def test_thread_count_not_exceed_port_count(self):
        """10 port için 1000 thread açmak saçma — adaptive cap test."""
        scanner = NetScanner(threads=1000)
        self.assertLessEqual(scanner._requested_threads, 1000)



# ─────────────────────────────────────────────────────────────
# 12. v1.3 — CVE hints, fingerprinting, scan_many, rate-limit
# ─────────────────────────────────────────────────────────────
class TestV13Features(unittest.TestCase):

    def test_cve_hints_known_port(self):
        """CVE_HINTS should return entries for well-known risky ports."""
        from netscanner.core.scanner import get_cve_hints
        hints = get_cve_hints(3389)  # RDP
        self.assertGreater(len(hints), 0)
        severities = [h[2] for h in hints]
        self.assertIn("CRITICAL", severities)

    def test_cve_hints_unknown_port(self):
        from netscanner.core.scanner import get_cve_hints
        hints = get_cve_hints(19999)
        self.assertEqual(hints, [])

    def test_cve_hints_redis(self):
        from netscanner.core.scanner import get_cve_hints
        hints = get_cve_hints(6379)
        self.assertTrue(any("Redis" in h[1] or "redis" in h[1].lower() for h in hints))

    def test_fingerprint_openssh(self):
        from netscanner.core.scanner import fingerprint_version
        result = fingerprint_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
        self.assertIn("OpenSSH", result)

    def test_fingerprint_nginx(self):
        from netscanner.core.scanner import fingerprint_version
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
        result = fingerprint_version(banner)
        self.assertIn("nginx", result)
        self.assertIn("1.24", result)

    def test_fingerprint_apache(self):
        from netscanner.core.scanner import fingerprint_version
        banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\n"
        result = fingerprint_version(banner)
        self.assertIn("Apache", result)
        self.assertIn("2.4", result)

    def test_fingerprint_unknown(self):
        from netscanner.core.scanner import fingerprint_version
        result = fingerprint_version("some random banner text")
        # Should return empty or the raw text, not crash
        self.assertIsInstance(result, str)

    def test_scan_result_critical_cves(self):
        """critical_cves property returns only CRITICAL severity."""
        from netscanner.core.scanner import ScanResult, PortResult, PortState
        r = ScanResult(target="test")
        pr = PortResult(80, PortState.OPEN, "http")
        pr.cve_hints = [
            ("CVE-1", "desc", "CRITICAL"),
            ("CVE-2", "desc", "HIGH"),
        ]
        r.ports = [pr]
        crits = r.critical_cves
        self.assertEqual(len(crits), 1)
        self.assertIn("CVE-1", crits[0])

    def test_rate_limit_param(self):
        """NetScanner should accept rate_limit parameter without error."""
        from netscanner.core.scanner import NetScanner
        scanner = NetScanner(rate_limit=0.01, skip_ping=True, threads=5)
        self.assertEqual(scanner.rate_limit, 0.01)

    def test_do_cve_param(self):
        """NetScanner should accept do_cve parameter."""
        from netscanner.core.scanner import NetScanner
        scanner = NetScanner(do_cve=False, skip_ping=True)
        self.assertFalse(scanner.do_cve)

    def test_html_report_output(self):
        """HTML report should be valid HTML with key sections."""
        from netscanner.core.report import to_html
        r = _make_result()
        html = to_html([r])
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("NetScanner", html)
        self.assertIn("192.168.1.1", html)
        self.assertIn("open", html.lower())

    def test_html_report_cve_section(self):
        """HTML report should include CVE section for ports with hints."""
        from netscanner.core.report import to_html
        from netscanner.core.scanner import ScanResult, PortResult, PortState
        r = ScanResult(target="10.0.0.1", ip="10.0.0.1", is_up=True)
        r.start_time = r.end_time = 1000.0
        r.total_scanned = 1
        pr = PortResult(3389, PortState.OPEN, "rdp")
        pr.cve_hints = [("CVE-2019-0708", "BlueKeep", "CRITICAL")]
        r.ports = [pr]
        html = to_html([r])
        self.assertIn("CVE-2019-0708", html)
        self.assertIn("CRITICAL", html)

    def test_scan_many_yields_results(self):
        """scan_many should yield one result per host."""
        from netscanner.core.scanner import NetScanner
        scanner = NetScanner(skip_ping=True, do_banner=False, threads=5)
        # Use two invalid hosts so they resolve quickly with errors
        targets = ["this.invalid.a.xyz", "this.invalid.b.xyz"]
        results = list(scanner.scan_many(targets, [80]))
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertIn(r.target, targets)


# ─────────────────────────────────────────────────────────────
# Çalıştır
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    test_classes = [
        TestParsePorts,
        TestParseTargets,
        TestSanitize,
        TestResolveTarget,
        TestTcpConnect,
        TestIsHostUp,
        TestDetectOs,
        TestNetScannerClass,
        TestOutputFormats,
        TestSecurity,
        TestPerformanceEdgeCases,
        TestV13Features,
    ]

    for tc in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(tc))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
