#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# NucMap v0.1.2 — Standalone LXC / VM Installer & Setup Script
# Repository: https://github.com/johestephan/NucMap
# License:    MIT
# Target OS:  Debian 12 / 13 or Ubuntu 22.04 / 24.04 (LXC or VM)
# ==============================================================================
# Usage:
#   1. One-liner inside a Debian/Ubuntu container or VM:
#        bash -c "$(curl -fsSL https://raw.githubusercontent.com/johestephan/NucMap/main/installer.sh)"
#   2. Run from a cloned repository:
#        sudo ./installer.sh
#   3. Push & install remotely from workstation via SSH:
#        ./installer.sh --remote root@192.168.1.100
# ==============================================================================

REPO_URL="https://github.com/johestephan/NucMap.git"
APP_DIR="${APP_DIR:-/opt/nucmap}"
DATA_DIR="${DATA_DIR:-/var/lib/nucmap}"
SERVICE_NAME="${SERVICE_NAME:-nucmap.service}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd || pwd)"

if [[ "${1:-}" == "--remote" || "${1:-}" == "--push" ]]; then
  if [[ -z "${2:-}" ]]; then
    echo "Usage: ./installer.sh --remote root@<TARGET_IP>"
    exit 1
  fi
  REMOTE_HOST="${2}"
  echo "[*] Pushing NucMap v0.1.2 project files to ${REMOTE_HOST}:${APP_DIR}..."
  ssh "${REMOTE_HOST}" "mkdir -p ${APP_DIR}"
  tar --exclude='node_modules' --exclude='.git' --exclude='data' -czf - -C "${SCRIPT_DIR}" . \
    | ssh "${REMOTE_HOST}" "tar -xzf - -C ${APP_DIR} && chmod +x ${APP_DIR}/installer.sh && ${APP_DIR}/installer.sh"
  exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Please run installer.sh as root (or via sudo)."
  exit 1
fi

echo "=================================================================="
echo "  NucMap v0.1.2 — ASM & Vulnerability Scanner Setup"
echo "=================================================================="

# 1. Install OS packages
echo "[1/7] Installing system dependencies via apt..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
  nmap \
  git \
  curl \
  wget \
  unzip \
  sqlite3 \
  bsdutils \
  ca-certificates \
  nodejs \
  npm \
  build-essential \
  python3

# 2. Install ProjectDiscovery Nuclei (/usr/local/bin/nuclei)
echo "[2/7] Checking ProjectDiscovery Nuclei (/usr/local/bin/nuclei)..."
if [[ ! -x /usr/local/bin/nuclei ]]; then
  ARCH="$(uname -m)"
  case "${ARCH}" in
    x86_64|amd64) NUCLEI_ARCH="amd64" ;;
    aarch64|arm64) NUCLEI_ARCH="arm64" ;;
    *) NUCLEI_ARCH="amd64" ;;
  esac

  echo "    Downloading latest Nuclei release for linux_${NUCLEI_ARCH}..."
  LATEST_URL="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
    | grep -Eo "https://[^\"]+nuclei_[0-9.]+_linux_${NUCLEI_ARCH}\.zip" | head -n 1 || true)"

  if [[ -n "${LATEST_URL}" ]]; then
    TMP_ZIP="$(mktemp /tmp/nuclei_XXXXXX.zip)"
    TMP_DIR="$(mktemp -d /tmp/nuclei_extract_XXXXXX)"
    curl -fsSL "${LATEST_URL}" -o "${TMP_ZIP}"
    unzip -q -o "${TMP_ZIP}" -d "${TMP_DIR}"
    install -m 0755 "${TMP_DIR}/nuclei" /usr/local/bin/nuclei
    rm -rf "${TMP_ZIP}" "${TMP_DIR}"
  elif command -v go >/dev/null 2>&1; then
    echo "    Building Nuclei via Go fallback..."
    GOBIN=/usr/local/bin go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  else
    echo "[!] Failed to download Nuclei binary and Go is not available."
    exit 1
  fi
fi
/usr/local/bin/nuclei -version || true

# 3. Setup Nmap NSE Vulscan, NucMap-scripts Library & Update Script DB
echo "[3/7] Configuring Nmap NSE scripts, Vulscan, and NucMap-scripts library..."
if [[ ! -d /usr/share/nmap/scripts/vulscan ]]; then
  git clone --depth 1 https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan || true
else
  git -C /usr/share/nmap/scripts/vulscan pull --ff-only || true
fi
if [[ -f /usr/share/nmap/scripts/vulscan/utilities/updater/updateFiles.sh ]]; then
  chmod +x /usr/share/nmap/scripts/vulscan/utilities/updater/updateFiles.sh
fi

NUCMAP_SCRIPTS_DIR="${NUCMAP_SCRIPTS_DIR:-/opt/nucmap-scripts}"
if [[ ! -d "${NUCMAP_SCRIPTS_DIR}/.git" ]]; then
  rm -rf "${NUCMAP_SCRIPTS_DIR}"
  git clone --depth 1 https://github.com/johestephan/NucMap-scripts.git "${NUCMAP_SCRIPTS_DIR}" || true
else
  git -C "${NUCMAP_SCRIPTS_DIR}" pull --ff-only || true
fi

if [[ -d "${NUCMAP_SCRIPTS_DIR}/nse" ]]; then
  for nse_file in "${NUCMAP_SCRIPTS_DIR}"/nse/*.nse; do
    [[ -f "${nse_file}" && "$(basename "${nse_file}")" != "nucmap-template.nse" ]] && cp "${nse_file}" /usr/share/nmap/scripts/ || true
  done
fi

nmap --script-updatedb

# 4. Initialize Nuclei Templates & Compatibility Symlinks
echo "[4/7] Initializing Nuclei templates..."
export HOME="${HOME:-/root}"
/usr/local/bin/nuclei -update-templates -nc || true
TEMPLATES_DIR="${HOME}/nuclei-templates"
if [[ -d "${TEMPLATES_DIR}" ]]; then
  [[ -d "${TEMPLATES_DIR}/http/cves" && ! -e "${TEMPLATES_DIR}/cves" ]] && ln -s "${TEMPLATES_DIR}/http/cves" "${TEMPLATES_DIR}/cves" || true
  [[ -d "${TEMPLATES_DIR}/http/exposed-panels" && ! -e "${TEMPLATES_DIR}/exposed-panels" ]] && ln -s "${TEMPLATES_DIR}/http/exposed-panels" "${TEMPLATES_DIR}/exposed-panels" || true
  if [[ -d "${NUCMAP_SCRIPTS_DIR}/nuclei" ]]; then
    mkdir -p "${TEMPLATES_DIR}/nucmap-custom"
    cp "${NUCMAP_SCRIPTS_DIR}"/nuclei/*.yaml "${TEMPLATES_DIR}/nucmap-custom/" 2>/dev/null || true
  fi
fi

# 5. Setup Directories & Fetch/Copy Application Files
echo "[5/7] Setting up directories (${DATA_DIR} & ${APP_DIR})..."
mkdir -p "${DATA_DIR}"
mkdir -p "${APP_DIR}"

if [[ -f "${SCRIPT_DIR}/package.json" && -d "${SCRIPT_DIR}/src" ]]; then
  if [[ "${SCRIPT_DIR}" != "${APP_DIR}" ]]; then
    cp -r "${SCRIPT_DIR}/package.json" "${SCRIPT_DIR}/config" "${SCRIPT_DIR}/src" "${SCRIPT_DIR}/public" "${SCRIPT_DIR}/systemd" "${APP_DIR}/"
    [[ -f "${SCRIPT_DIR}/README.md" ]] && cp "${SCRIPT_DIR}/README.md" "${APP_DIR}/" || true
    [[ -f "${SCRIPT_DIR}/LICENSE" ]] && cp "${SCRIPT_DIR}/LICENSE" "${APP_DIR}/" || true
    cp "${SCRIPT_DIR}/installer.sh" "${APP_DIR}/"
  fi
else
  echo "    Cloning ${REPO_URL} into ${APP_DIR}..."
  TMP_CLONE="$(mktemp -d /tmp/nucmap_clone_XXXXXX)"
  git clone --depth 1 "${REPO_URL}" "${TMP_CLONE}"
  cp -r "${TMP_CLONE}/." "${APP_DIR}/"
  rm -rf "${TMP_CLONE}"
fi

# 6. Install Node.js Dependencies
echo "[6/7] Installing Node.js dependencies in ${APP_DIR}..."
cd "${APP_DIR}"
npm install --omit=dev

# Record initial signature update timestamp in SQLite
node -e '
  const db = require("./src/db");
  db.setSystemMeta("last_signature_update", new Date().toISOString());
'

# 7. Configure & Start Systemd Service
echo "[7/7] Installing and starting systemd service (${SERVICE_NAME})..."
pkill -f "/usr/local/bin/nuclei" 2>/dev/null || true

cp "${APP_DIR}/systemd/nucmap.service" "/etc/systemd/system/${SERVICE_NAME}"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

sleep 2
systemctl --no-pager --full status "${SERVICE_NAME}" || true

# 8. Install in-container update command (/usr/local/bin/update)
cat << 'EOF' > /usr/local/bin/update
#!/usr/bin/env bash
set -euo pipefail
echo "=================================================================="
echo "  Updating NucMap (preserving database in /var/lib/nucmap)..."
echo "=================================================================="
bash -c "$(curl -fsSL https://raw.githubusercontent.com/johestephan/NucMap/main/installer.sh)"
EOF
chmod +x /usr/local/bin/update
ln -sf /usr/local/bin/update /usr/local/bin/nucmap-update

HOST_IP="$(hostname -I | awk "{print \$1}")"
echo "=================================================================="
echo "  NucMap v0.1.2 installation complete!"
echo "  Web UI:   http://${HOST_IP}:3000  (and http://${HOST_IP})"
echo "  Database: ${DATA_DIR}/nucmap.db"
echo "  Service:  systemctl status ${SERVICE_NAME}"
echo "  Update:   run 'update' inside container or via pct exec"
echo "=================================================================="
