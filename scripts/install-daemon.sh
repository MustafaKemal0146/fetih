#!/usr/bin/env bash
# SETH Daemon Kurulum Scripti
set -e

SETH_USER="${SUDO_USER:-$USER}"
SETH_HOME="$(eval echo ~$SETH_USER)"
SETH_DIR="$SETH_HOME/.seth"
SERVICE_NAME="seth-daemon"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}@.service"
BIN_PATH="$(which seth 2>/dev/null || echo '/usr/local/bin/seth')"

log()  { echo "  → $1"; }
ok()   { echo "  ✔ $1"; }
warn() { echo "  ⚠ $1" >&2; }
fail() { echo "  ✘ $1" >&2; exit 1; }

echo ""
echo "┌─ SETH Daemon Kurulumu"
echo "│"

# Root kontrolü
if [ "$EUID" -ne 0 ]; then
  fail "Bu script root yetkileri gerektirir. 'sudo $0' ile çalıştırın."
fi

# SETH binary kontrolü
if [ ! -f "$BIN_PATH" ] && ! command -v seth &>/dev/null; then
  warn "seth binary'si bulunamadı ($BIN_PATH)"
  warn "Önce 'npm install -g' ile SETH'i global kurun."
  log "Geçici olarak devam ediliyor..."
fi

# Dizin oluştur
log "State dizini oluşturuluyor: $SETH_DIR"
if [ ! -d "$SETH_DIR" ]; then
  mkdir -p "$SETH_DIR"
  chown "$SETH_USER:$SETH_USER" "$SETH_DIR"
  chmod 700 "$SETH_DIR"
  ok "Dizin oluşturuldu"
else
  ok "Dizin zaten var"
fi

# systemd service dosyasını kur
log "systemd service dosyası kopyalanıyor..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/seth-daemon.service" "$SERVICE_FILE"
chmod 644 "$SERVICE_FILE"
ok "Service dosyası: $SERVICE_FILE"

# systemd reload
log "systemd daemon-reload yapılıyor..."
systemctl daemon-reload
ok "systemd yeniden yüklendi"

# Servisi etkinleştir
log "Servis etkinleştiriliyor..."
systemctl enable "${SERVICE_NAME}@${SETH_USER}"
ok "Servis etkinleştirildi"

echo "│"
echo "├─ Kullanım:"
echo "│  sudo systemctl start  ${SERVICE_NAME}@${SETH_USER}"
echo "│  sudo systemctl stop   ${SERVICE_NAME}@${SETH_USER}"
echo "│  sudo systemctl status ${SERVICE_NAME}@${SETH_USER}"
echo "│"
echo "├─ Veya doğrudan SETH CLI ile:"
echo "│  seth daemon start"
echo "│  seth daemon stop"
echo "│  seth daemon status"
echo "│  seth daemon restart"
echo "│"
echo "└─ Tamamlandı. 🚀"
