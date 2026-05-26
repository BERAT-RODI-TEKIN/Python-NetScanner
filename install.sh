#!/usr/bin/env bash
# NetScanner — Full Release | Linux/Kali Installer
set -e
[ "$EUID" -ne 0 ] && { echo "[!] Run with sudo: sudo bash install.sh"; exit 1; }
command -v python3 &>/dev/null || apt-get install -y python3
python3 -c "import tkinter" 2>/dev/null || apt-get install -y python3-tk
DEST="/opt/netscanner"
mkdir -p "$DEST"
cp -r "$(dirname "$0")/." "$DEST/"
chmod +x "$DEST/main.py"
cat > /usr/local/bin/netscanner << 'WRAP'
#!/usr/bin/env bash
exec python3 /opt/netscanner/main.py "$@"
WRAP
chmod +x /usr/local/bin/netscanner
echo ""
echo "  Installation complete!"
echo "  Usage: netscanner              (menu/GUI)"
echo "         netscanner 192.168.1.1  (CLI scan)"
echo "         netscanner --gui        (open GUI)"
echo "         netscanner --help       (help)"
echo ""
