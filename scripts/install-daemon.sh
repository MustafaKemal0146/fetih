#!/usr/bin/env bash
# FETIH Daemon Kurulum Scripti
set -e

FETIH_USER="${SUDO_USER:-$USER}"
FETIH_HOME="$(eval echo ~$FETIH_USER)"
FETIH_DIR="$FETIH_HOME/.fetih"
SERVICE_NAME="fetih-daemon"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}@.service"
BIN_PATH="$(which fetih 2>/dev/null || echo '/usr/local/bin/fetih')"

log()  { echo "  → $1"; }
ok()   { echo "  ✔ $1"; }
warn() { echo "  ⚠ $1" >&2; }
fail() { echo "  ✘ $1" >&2; exit 1; }

echo ""
echo "┌─ FETIH Daemon Kurulumu"
echo "│"

# Root kontrolü
if [ "$EUID" -ne 0 ]; then
  fail "Bu script root yetkileri gerektirir. 'sudo $0' ile çalıştırın."
fi

# FETIH binary kontrolü
if [ ! -f "$BIN_PATH" ] && ! command -v fetih &>/dev/null; then
  warn "fetih binary'si bulunamadı ($BIN_PATH)"
  warn "Önce 'npm install -g' ile FETIH'i global kurun."
  log "Geçici olarak devam ediliyor..."
fi

# Dizin oluştur
log "State dizini oluşturuluyor: $FETIH_DIR"
if [ ! -d "$FETIH_DIR" ]; then
  mkdir -p "$FETIH_DIR"
  chown "$FETIH_USER:$FETIH_USER" "$FETIH_DIR"
  chmod 700 "$FETIH_DIR"
  ok "Dizin oluşturuldu"
else
  ok "Dizin zaten var"
fi

# systemd service dosyasını kur
log "systemd service dosyası kopyalanıyor..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/fetih-daemon.service" "$SERVICE_FILE"
chmod 644 "$SERVICE_FILE"
ok "Service dosyası: $SERVICE_FILE"

# systemd reload
log "systemd daemon-reload yapılıyor..."
systemctl daemon-reload
ok "systemd yeniden yüklendi"

# Servisi etkinleştir
log "Servis etkinleştiriliyor..."
systemctl enable "${SERVICE_NAME}@${FETIH_USER}"
ok "Servis etkinleştirildi"

echo "│"
echo "├─ Kullanım:"
echo "│  sudo systemctl start  ${SERVICE_NAME}@${FETIH_USER}"
echo "│  sudo systemctl stop   ${SERVICE_NAME}@${FETIH_USER}"
echo "│  sudo systemctl status ${SERVICE_NAME}@${FETIH_USER}"
echo "│"
echo "├─ Veya doğrudan FETIH CLI ile:"
echo "│  fetih daemon start"
echo "│  fetih daemon stop"
echo "│  fetih daemon status"
echo "│  fetih daemon restart"
echo "│"
echo "└─ Tamamlandı. 🚀"
