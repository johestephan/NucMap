#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# NucMap v0.1.1 — Proxmox VE LXC Community-Style Creation & Deployment Script
# Repository: https://github.com/johestephan/NucMap
# License:    MIT
# ==============================================================================
# Run directly on your Proxmox VE Host shell:
#   bash -c "$(wget -qLO - https://raw.githubusercontent.com/johestephan/NucMap/main/proxmox/nucmap.sh)"
#
# Or non-interactively with custom defaults:
#   CT_ID=120 CT_HOSTNAME=nucmap CT_STORAGE=local-lvm bash proxmox/nucmap.sh --yes
# ==============================================================================

APP="NucMap"
APP_VERSION="0.1.1"
REPO_RAW="https://raw.githubusercontent.com/johestephan/NucMap/main"

# Colors
YW="\033[33m"
BL="\033[36m"
RD="\033[01;31m"
GN="\033[1;92m"
CL="\033[m"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"
INFO="${BL}ℹ${CL}"

header_info() {
  clear || true
  cat <<"EOF"
    _   __           __  ___           
   / | / /_  _______/  |/  /___ _____  
  /  |/ / / / / ___/ /|_/ / __ `/ __ \ 
 / /|  / /_/ / /__/ /  / / /_/ / /_/ / 
/_/ |_/\__,_/\___/_/  /_/\__,_/ .___/  
                             /_/       
EOF
  echo -e "${BL}${APP} v${APP_VERSION} — Proxmox VE LXC Container Installer${CL}"
  echo -e "Attack Surface Management (Nmap + ProjectDiscovery Nuclei + Vulscan)"
  echo "--------------------------------------------------------------------"
}

msg_info() { echo -e " ${INFO} ${YW}$1...${CL}"; }
msg_ok()   { echo -e " ${CM} ${GN}$1${CL}"; }
msg_err()  { echo -e " ${CROSS} ${RD}$1${CL}"; exit 1; }

# If executed inside an existing Debian/Ubuntu container or VM (no Proxmox 'pct' tool),
# fall back to running the standalone installer directly.
if ! command -v pct >/dev/null 2>&1 || ! command -v pveversion >/dev/null 2>&1; then
  echo -e "${YW}[!] Proxmox VE host tools (pct/pveversion) not detected.${CL}"
  echo -e "${BL}[*] Running standalone guest installer inside current system...${CL}"
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd || pwd)"
  if [[ -f "${SCRIPT_DIR}/../installer.sh" ]]; then
    exec bash "${SCRIPT_DIR}/../installer.sh"
  else
    exec bash -c "$(curl -fsSL ${REPO_RAW}/installer.sh)"
  fi
fi

if [[ "${EUID}" -ne 0 ]]; then
  msg_err "This script must be run as root on the Proxmox VE host."
fi

header_info

# Default Container Parameters
NEXT_ID="$(pvesh get /cluster/nextid 2>/dev/null || echo 150)"
CT_ID="${CT_ID:-${NEXT_ID}}"
CT_HOSTNAME="${CT_HOSTNAME:-nucmap}"
CT_CORES="${CT_CORES:-2}"
CT_RAM="${CT_RAM:-2048}"
CT_SWAP="${CT_SWAP:-512}"
CT_DISK="${CT_DISK:-8}"
CT_BRIDGE="${CT_BRIDGE:-vmbr0}"
CT_IP="${CT_IP:-dhcp}"
CT_GW="${CT_GW:-}"
CT_UNPRIVILEGED="${CT_UNPRIVILEGED:-1}"
CT_STORAGE="${CT_STORAGE:-}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
AUTO_YES=0

if [[ "${1:-}" == "--yes" || "${1:-}" == "-y" ]]; then
  AUTO_YES=1
fi

# Detect default rootfs storage pool if not provided
if [[ -z "${CT_STORAGE}" ]]; then
  if pvesm status -content rootdir 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "local-lvm"; then
    CT_STORAGE="local-lvm"
  elif pvesm status -content rootdir 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "local-zfs"; then
    CT_STORAGE="local-zfs"
  else
    CT_STORAGE="$(pvesm status -content rootdir 2>/dev/null | awk 'NR==2 {print $1}')"
    CT_STORAGE="${CT_STORAGE:-local-lvm}"
  fi
fi

if [[ "${AUTO_YES}" -eq 0 && -t 0 ]]; then
  echo -e "Default LXC Settings:"
  echo -e "  • Container ID:  ${BL}${CT_ID}${CL}"
  echo -e "  • Hostname:      ${BL}${CT_HOSTNAME}${CL}"
  echo -e "  • CPU / RAM:     ${BL}${CT_CORES} vCPU / ${CT_RAM} MB RAM${CL}"
  echo -e "  • Disk / Pool:   ${BL}${CT_DISK} GB on ${CT_STORAGE}${CL}"
  echo -e "  • Network:       ${BL}${CT_BRIDGE} (${CT_IP})${CL}"
  echo -e "  • Container Type:${BL} Unprivileged Debian 12 LXC${CL}"
  echo ""
  read -r -p "Use Default Settings? [Y/n/advanced]: " MODE_CHOICE
  MODE_CHOICE="${MODE_CHOICE:-Y}"

  if [[ "${MODE_CHOICE,,}" == "n" || "${MODE_CHOICE,,}" == "advanced" || "${MODE_CHOICE,,}" == "a" ]]; then
    read -r -p "Enter Container ID [${CT_ID}]: " input_id
    CT_ID="${input_id:-${CT_ID}}"

    read -r -p "Enter Hostname [${CT_HOSTNAME}]: " input_hn
    CT_HOSTNAME="${input_hn:-${CT_HOSTNAME}}"

    read -r -p "Enter CPU Cores [${CT_CORES}]: " input_cores
    CT_CORES="${input_cores:-${CT_CORES}}"

    read -r -p "Enter RAM in MB [${CT_RAM}]: " input_ram
    CT_RAM="${input_ram:-${CT_RAM}}"

    read -r -p "Enter Disk Size in GB [${CT_DISK}]: " input_disk
    CT_DISK="${input_disk:-${CT_DISK}}"

    echo "Available rootdir storages:"
    pvesm status -content rootdir | awk 'NR>1 {print "  - " $1 " (" $2 ")"}'
    read -r -p "Enter Storage Pool [${CT_STORAGE}]: " input_storage
    CT_STORAGE="${input_storage:-${CT_STORAGE}}"

    read -r -p "Enter Network Bridge [${CT_BRIDGE}]: " input_bridge
    CT_BRIDGE="${input_bridge:-${CT_BRIDGE}}"

    read -r -p "Enter IPv4 CIDR or 'dhcp' (e.g. 192.168.1.50/24 or dhcp) [${CT_IP}]: " input_ip
    CT_IP="${input_ip:-${CT_IP}}"

    if [[ "${CT_IP}" != "dhcp" ]]; then
      read -r -p "Enter Gateway IP (e.g. 192.168.1.1): " input_gw
      CT_GW="${input_gw:-}"
    fi
  fi
fi

# Verify CT_ID is not already in use
if pct status "${CT_ID}" >/dev/null 2>&1; then
  msg_err "Container ID ${CT_ID} already exists on this Proxmox host."
fi

# 1. Locate or download Debian 12/13 LXC template
msg_info "Updating Proxmox LXC appliance template catalog (pveam update)"
pveam update >/dev/null 2>&1 || true

DEBIAN_TPL="$(pveam available -section system | awk '{print $2}' | grep -E '^debian-(12|13)-standard_' | sort -V | tail -n 1)"
if [[ -z "${DEBIAN_TPL}" ]]; then
  msg_err "Could not find a Debian 12/13 standard template in pveam."
fi

if ! pveam list "${TEMPLATE_STORAGE}" 2>/dev/null | grep -q "${DEBIAN_TPL}"; then
  msg_info "Downloading LXC template ${DEBIAN_TPL} to ${TEMPLATE_STORAGE}"
  pveam download "${TEMPLATE_STORAGE}" "${DEBIAN_TPL}"
fi
msg_ok "Template ready: ${TEMPLATE_STORAGE}:vztmpl/${DEBIAN_TPL}"

# 2. Build network string
NET_CFG="name=eth0,bridge=${CT_BRIDGE},ip=${CT_IP}"
if [[ "${CT_IP}" != "dhcp" && -n "${CT_GW}" ]]; then
  NET_CFG="${NET_CFG},gw=${CT_GW}"
fi

# 3. Create LXC Container
msg_info "Creating LXC Container ${CT_ID} (${CT_HOSTNAME})"
pct create "${CT_ID}" "${TEMPLATE_STORAGE}:vztmpl/${DEBIAN_TPL}" \
  --hostname "${CT_HOSTNAME}" \
  --cores "${CT_CORES}" \
  --memory "${CT_RAM}" \
  --swap "${CT_SWAP}" \
  --rootfs "${CT_STORAGE}:${CT_DISK}" \
  --net0 "${NET_CFG}" \
  --unprivileged "${CT_UNPRIVILEGED}" \
  --features nesting=1,keyctl=1 \
  --onboot 1 \
  --start 1
msg_ok "LXC Container ${CT_ID} created and started"

# 4. Wait for network inside container
msg_info "Waiting for container network initialization"
for _ in {1..20}; do
  if pct exec "${CT_ID}" -- hostname -I 2>/dev/null | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
    break
  fi
  sleep 2
done
msg_ok "Container network is online"

# 5. Provision NucMap inside the container
msg_info "Installing NucMap v${APP_VERSION} inside LXC ${CT_ID} (Nmap, Nuclei, Vulscan, Node.js)"
pct exec "${CT_ID}" -- bash -c "apt-get update -y && apt-get install -y curl ca-certificates git"
pct exec "${CT_ID}" -- bash -c "curl -fsSL ${REPO_RAW}/installer.sh | bash"
msg_ok "NucMap v${APP_VERSION} installed and started inside LXC ${CT_ID}"

CT_ACTUAL_IP="$(pct exec "${CT_ID}" -- hostname -I | awk '{print $1}')"

echo ""
echo "===================================================================="
echo -e " ${CM} ${GN}${APP} v${APP_VERSION} Proxmox LXC Deployment Complete!${CL}"
echo "===================================================================="
echo -e "  • Container ID:  ${BL}${CT_ID}${CL} (${CT_HOSTNAME})"
echo -e "  • Web Dashboard: ${GN}http://${CT_ACTUAL_IP}:3000${CL}  (and ${GN}http://${CT_ACTUAL_IP}${CL})"
echo -e "  • SQLite DB:     ${BL}/var/lib/nucmap/nucmap.db${CL}"
echo -e "  • Service Logs:  ${YW}pct exec ${CT_ID} -- journalctl -u nucmap -f${CL}"
echo "===================================================================="
