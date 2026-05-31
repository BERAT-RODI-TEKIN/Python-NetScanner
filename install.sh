#!/usr/bin/env bash
# NetScanner v1.3 — Linux/Kali Installer
set -e

# Root kontrolü
[ "$EUID" -ne 0 ] && { echo "[!] Sudo ile çalıştır: sudo bash install.sh"; exit 1; }

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   NetScanner v1.3 — Installer        ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# Python kontrolü
command -v python3 &>/dev/null || {
    echo "[*] Python3 yükleniyor..."
    apt-get update -qq && apt-get install -y python3
}

# Tkinter kontrolü (GUI için)
python3 -c "import tkinter" 2>/dev/null || {
    echo "[*] python3-tk yükleniyor..."
    apt-get install -y python3-tk
}

# Kurulum dizini
DEST="/opt/netscanner"
echo "[*] Dosyalar kopyalanıyor → $DEST"
mkdir -p "$DEST"
cp -r "$(dirname "$(realpath "$0")")/." "$DEST/"
chmod +x "$DEST/main.py"

# Wrapper script — 'netscanner' komutu
cat > /usr/local/bin/netscanner << 'WRAP'
#!/usr/bin/env bash
exec python3 /opt/netscanner/main.py "$@"
WRAP
chmod +x /usr/local/bin/netscanner

# pip ile de kurulabilir (optional)
if command -v pip3 &>/dev/null; then
    echo "[*] pip ile de kuruluyor (import netscanner için)..."
    pip3 install -e "$DEST/" --quiet 2>/dev/null || true
fi

echo ""
echo "  ✅ Kurulum tamamlandı!"
echo ""
echo "  Kullanım:"
echo "    netscanner                    → menü/GUI"
echo "    netscanner 192.168.1.1        → hızlı tarama"
echo "    netscanner 192.168.1.1 -A     → agresif tarama"
echo "    netscanner --help             → yardım"
echo ""
