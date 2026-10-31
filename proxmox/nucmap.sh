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
APP_VERSION="0.1.2"
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
CT_DEBIAN_VER="${CT_DEBIAN_VER:-12}"
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

# Detect valid template storage pool that supports 'vztmpl'
if ! pvesm status -content vztmpl 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "${TEMPLATE_STORAGE}"; then
  DETECTED_TPL_STORAGE="$(pvesm status -content vztmpl 2>/dev/null | awk 'NR==2 {print $1}')"
  TEMPLATE_STORAGE="${DETECTED_TPL_STORAGE:-local}"
fi

if [[ "${AUTO_YES}" -eq 0 && -t 0 ]]; then
  echo -e "Default LXC Settings:"
  echo -e "  • Container ID:  ${BL}${CT_ID}${CL}"
  echo -e "  • Hostname:      ${BL}${CT_HOSTNAME}${CL}"
  echo -e "  • OS Template:   ${BL}Debian ${CT_DEBIAN_VER} (Bookworm - PVE 8/9 Compatible)${CL}"
  echo -e "  • CPU / RAM:     ${BL}${CT_CORES} vCPU / ${CT_RAM} MB RAM${CL}"
  echo -e "  • Disk / Pool:   ${BL}${CT_DISK} GB on ${CT_STORAGE}${CL}"
  echo -e "  • Network:       ${BL}${CT_BRIDGE} (${CT_IP})${CL}"
  echo -e "  • Container Type:${BL} $( [[ "${CT_UNPRIVILEGED}" == "1" ]] && echo "Unprivileged" || echo "Privileged" )${CL}"
  echo ""
  read -r -p "Use Default Settings? [Y/n/advanced]: " MODE_CHOICE
  MODE_CHOICE="${MODE_CHOICE:-Y}"

  if [[ "${MODE_CHOICE,,}" == "n" || "${MODE_CHOICE,,}" == "advanced" || "${MODE_CHOICE,,}" == "a" ]]; then
    read -r -p "Enter Container ID [${CT_ID}]: " input_id
    CT_ID="${input_id:-${CT_ID}}"

    read -r -p "Enter Hostname [${CT_HOSTNAME}]: " input_hn
    CT_HOSTNAME="${input_hn:-${CT_HOSTNAME}}"

    read -r -p "Enter Debian Version (12 or 13) [${CT_DEBIAN_VER}]: " input_deb
    CT_DEBIAN_VER="${input_deb:-${CT_DEBIAN_VER}}"

    read -r -p "Unprivileged Container? (1=Unprivileged, 0=Privileged) [${CT_UNPRIVILEGED}]: " input_unpriv
    CT_UNPRIVILEGED="${input_unpriv:-${CT_UNPRIVILEGED}}"

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

# Sanitize hostname for LXC (lowercase alphanumeric & hyphens)
CT_HOSTNAME="$(echo "${CT_HOSTNAME}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9-]+/-/g; s/^-+|-+$//g')"
CT_HOSTNAME="${CT_HOSTNAME:-nucmap}"

# Ensure static IP has CIDR mask (e.g., /24) so pve-bridge does not fail at LXC sequence 7
if [[ "${CT_IP}" != "dhcp" && "${CT_IP}" != */* ]]; then
  echo -e " ${INFO} ${YW}Adding default /24 CIDR prefix to static IP: ${CT_IP}/24${CL}"
  CT_IP="${CT_IP}/24"
fi

# Check if CT_ID already exists (e.g. from a previous failed attempt)
if pct status "${CT_ID}" >/dev/null 2>&1; then
  EXISTING_STATUS="$(pct status "${CT_ID}" | awk '{print $2}')"
  if [[ "${AUTO_YES}" -eq 0 && -t 0 ]]; then
    read -r -p "Container ${CT_ID} already exists (${EXISTING_STATUS}). Destroy and recreate it? [y/N]: " DESTROY_CHOICE
    if [[ "${DESTROY_CHOICE,,}" == "y" || "${DESTROY_CHOICE,,}" == "yes" ]]; then
      msg_info "Stopping and destroying existing container ${CT_ID}"
      pct stop "${CT_ID}" >/dev/null 2>&1 || true
      pct destroy "${CT_ID}" --purge >/dev/null 2>&1 || pct destroy "${CT_ID}"
      msg_ok "Removed existing container ${CT_ID}"
    else
      msg_err "Aborted because Container ID ${CT_ID} already exists."
    fi
  else
    msg_err "Container ID ${CT_ID} already exists on this Proxmox host."
  fi
fi

# 1. Locate or download Debian LXC template matching the Proxmox host CPU architecture (amd64 / arm64)
HOST_ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
msg_info "Updating Proxmox LXC appliance template catalog (pveam update, arch: ${HOST_ARCH})"
pveam update >/dev/null 2>&1 || true

DEBIAN_TPL="$(pveam available -section system | awk '{print $2}' | grep -E "^debian-${CT_DEBIAN_VER}-standard_.*_${HOST_ARCH}\.tar\." | sort -V | tail -n 1 || true)"
if [[ -z "${DEBIAN_TPL}" ]]; then
  DEBIAN_TPL="$(pveam available -section system | awk '{print $2}' | grep -E "^debian-12-standard_.*_${HOST_ARCH}\.tar\." | sort -V | tail -n 1 || true)"
fi
if [[ -z "${DEBIAN_TPL}" ]]; then
  msg_err "Could not find a Debian standard template for architecture '${HOST_ARCH}' in pveam."
fi

if ! pveam list "${TEMPLATE_STORAGE}" 2>/dev/null | grep -q "${DEBIAN_TPL}"; then
  msg_info "Downloading LXC template ${DEBIAN_TPL} to ${TEMPLATE_STORAGE}"
  pveam download "${TEMPLATE_STORAGE}" "${DEBIAN_TPL}"
fi
msg_ok "Template ready: ${TEMPLATE_STORAGE}:vztmpl/${DEBIAN_TPL}"

# 2. Build network string & locate Proxmox host SSH authorized keys
NET_CFG="name=eth0,bridge=${CT_BRIDGE},ip=${CT_IP}"
if [[ "${CT_IP}" != "dhcp" && -n "${CT_GW}" ]]; then
  NET_CFG="${NET_CFG},gw=${CT_GW}"
fi

HOST_SSH_KEY=""
for key_candidate in /root/.ssh/authorized_keys /etc/pve/priv/authorized_keys; do
  if [[ -f "${key_candidate}" && -s "${key_candidate}" ]]; then
    HOST_SSH_KEY="${key_candidate}"
    break
  fi
done

PCT_EXTRA_ARGS=()
if [[ -n "${HOST_SSH_KEY}" ]]; then
  msg_ok "Detected Proxmox host SSH key: ${HOST_SSH_KEY}"
  PCT_EXTRA_ARGS+=(--ssh-public-keys "${HOST_SSH_KEY}")
fi

# 3. Create LXC Container (without --start 1 so we can start and verify cleanly)
msg_info "Creating LXC Container ${CT_ID} (${CT_HOSTNAME})"
pct create "${CT_ID}" "${TEMPLATE_STORAGE}:vztmpl/${DEBIAN_TPL}" \
  --arch "${HOST_ARCH}" \
  --ostype debian \
  --hostname "${CT_HOSTNAME}" \
  --cores "${CT_CORES}" \
  --memory "${CT_RAM}" \
  --swap "${CT_SWAP}" \
  --rootfs "${CT_STORAGE}:${CT_DISK}" \
  --net0 "${NET_CFG}" \
  --unprivileged "${CT_UNPRIVILEGED}" \
  --features nesting=1 \
  --onboot 1 \
  "${PCT_EXTRA_ARGS[@]}"
msg_ok "LXC Container ${CT_ID} created"

# 4. Start LXC Container (with fallback if nesting=1 is rejected by host AppArmor/kernel)
msg_info "Starting LXC Container ${CT_ID}"
if ! pct start "${CT_ID}" 2>/tmp/nucmap_lxc_start.err; then
  echo -e " ${INFO} ${YW}Initial start with nesting=1 failed; retrying without nesting feature...${CL}"
  pct set "${CT_ID}" --delete features >/dev/null 2>&1 || true
  if ! pct start "${CT_ID}"; then
    cat /tmp/nucmap_lxc_start.err >&2 || true
    lxc-start -n "${CT_ID}" -F -l ERROR -o /tmp/lxc-${CT_ID}.log >/dev/null 2>&1 || true
    [[ -f "/tmp/lxc-${CT_ID}.log" ]] && tail -n 20 "/tmp/lxc-${CT_ID}.log" >&2 || true
    msg_err "Failed to start container ${CT_ID}. See error log above."
  fi
fi
msg_ok "LXC Container ${CT_ID} started"

# 5. Provision SSH Keys inside container if found on host
if [[ -n "${HOST_SSH_KEY}" ]]; then
  msg_info "Configuring Proxmox authorized SSH keys inside container ${CT_ID}"
  pct exec "${CT_ID}" -- mkdir -p /root/.ssh
  pct exec "${CT_ID}" -- chmod 700 /root/.ssh
  pct push "${CT_ID}" "${HOST_SSH_KEY}" /root/.ssh/authorized_keys 2>/dev/null || true
  pct exec "${CT_ID}" -- chmod 600 /root/.ssh/authorized_keys 2>/dev/null || true
  msg_ok "SSH authorized_keys provisioned"
fi

# 6. Wait for network inside container
msg_info "Waiting for container network initialization"
for _ in {1..20}; do
  if pct exec "${CT_ID}" -- hostname -I 2>/dev/null | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
    break
  fi
  sleep 2
done
msg_ok "Container network is online"

# 7. Provision NucMap inside the container
msg_info "Installing NucMap v${APP_VERSION} inside LXC ${CT_ID} (Nmap, Nuclei, Vulscan, Node.js)"
pct exec "${CT_ID}" -- bash -c "apt-get update -y && apt-get install -y curl ca-certificates git openssh-server"
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
echo -e "  • SSH Login:     ${BL}ssh root@${CT_ACTUAL_IP}${CL} (Host SSH key enabled)"
echo -e "  • Update NucMap: ${YW}pct exec ${CT_ID} -- update${CL} (or 'update' inside container)"
echo -e "  • Service Logs:  ${YW}pct exec ${CT_ID} -- journalctl -u nucmap -f${CL}"
echo "===================================================================="
