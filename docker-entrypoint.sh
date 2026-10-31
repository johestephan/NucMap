#!/usr/bin/env bash
set -euo pipefail

mkdir -p /data

# Initialize Nuclei templates on first container start if volume is empty
TEMPLATES_DIR="${HOME:-/root}/nuclei-templates"
if [[ ! -d "${TEMPLATES_DIR}/http" ]]; then
  echo "[NucMap] Initializing ProjectDiscovery Nuclei templates in ${TEMPLATES_DIR}..."
  /usr/local/bin/nuclei -update-templates -nc || true
fi

if [[ -d "${TEMPLATES_DIR}" ]]; then
  [[ -d "${TEMPLATES_DIR}/http/cves" && ! -e "${TEMPLATES_DIR}/cves" ]] && ln -s "${TEMPLATES_DIR}/http/cves" "${TEMPLATES_DIR}/cves" || true
  [[ -d "${TEMPLATES_DIR}/http/exposed-panels" && ! -e "${TEMPLATES_DIR}/exposed-panels" ]] && ln -s "${TEMPLATES_DIR}/http/exposed-panels" "${TEMPLATES_DIR}/exposed-panels" || true
fi

exec "$@"
