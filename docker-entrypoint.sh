#!/usr/bin/env bash
set -euo pipefail

mkdir -p /data

# Initialize Nuclei templates on first container start if volume is empty
TEMPLATES_DIR="${HOME:-/root}/nuclei-templates"
if [[ ! -d "${TEMPLATES_DIR}/http" ]]; then
  echo "[NucMap] Initializing ProjectDiscovery Nuclei templates in ${TEMPLATES_DIR}..."
  /usr/local/bin/nuclei -update-templates -nc || true
fi

if [[ -d "/opt/nucmap-scripts/.git" ]]; then
  git -C /opt/nucmap-scripts pull --ff-only >/dev/null 2>&1 || true
  cp /opt/nucmap-scripts/nse/*.nse /usr/share/nmap/scripts/ 2>/dev/null || true
  rm -f /usr/share/nmap/scripts/nucmap-template.nse
fi

if [[ -d "${TEMPLATES_DIR}" ]]; then
  [[ -d "${TEMPLATES_DIR}/http/cves" && ! -e "${TEMPLATES_DIR}/cves" ]] && ln -s "${TEMPLATES_DIR}/http/cves" "${TEMPLATES_DIR}/cves" || true
  [[ -d "${TEMPLATES_DIR}/http/exposed-panels" && ! -e "${TEMPLATES_DIR}/exposed-panels" ]] && ln -s "${TEMPLATES_DIR}/http/exposed-panels" "${TEMPLATES_DIR}/exposed-panels" || true
  if [[ -d "/opt/nucmap-scripts/nuclei" ]]; then
    mkdir -p "${TEMPLATES_DIR}/nucmap-custom"
    cp /opt/nucmap-scripts/nuclei/*.yaml "${TEMPLATES_DIR}/nucmap-custom/" 2>/dev/null || true
  fi
fi

exec "$@"
