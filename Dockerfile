FROM node:22-bookworm-slim

LABEL org.opencontainers.image.title="NucMap" \
      org.opencontainers.image.description="Self-Hosted Attack Surface Management (ASM) & Vulnerability Scanner (Nmap + Nuclei + Vulscan)" \
      org.opencontainers.image.version="0.1.1" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/johestephan/NucMap"

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0 \
    DB_PATH=/data/nucmap.db \
    HOME=/root

# 1. Install system packages & Nmap
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    nmap \
    git \
    curl \
    wget \
    unzip \
    sqlite3 \
    bsdutils \
    ca-certificates \
    python3 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 2. Install ProjectDiscovery Nuclei (multi-arch: amd64 / arm64)
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "${ARCH}" in \
      x86_64|amd64) NUCLEI_ARCH="amd64" ;; \
      aarch64|arm64) NUCLEI_ARCH="arm64" ;; \
      *) NUCLEI_ARCH="amd64" ;; \
    esac; \
    LATEST_URL="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
      | grep -Eo "https://[^\"]+nuclei_[0-9.]+_linux_${NUCLEI_ARCH}\.zip" | head -n 1)"; \
    curl -fsSL "${LATEST_URL}" -o /tmp/nuclei.zip; \
    unzip -q -o /tmp/nuclei.zip -d /tmp/nuclei_bin; \
    install -m 0755 /tmp/nuclei_bin/nuclei /usr/local/bin/nuclei; \
    rm -rf /tmp/nuclei.zip /tmp/nuclei_bin; \
    /usr/local/bin/nuclei -version

# 3. Install Nmap NSE Vulscan, NucMap-scripts library & update Nmap script DB
RUN git clone --depth 1 https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan && \
    chmod +x /usr/share/nmap/scripts/vulscan/utilities/updater/updateFiles.sh 2>/dev/null || true && \
    git clone --depth 1 https://github.com/johestephan/NucMap-scripts.git /opt/nucmap-scripts && \
    cp /opt/nucmap-scripts/nse/*.nse /usr/share/nmap/scripts/ 2>/dev/null || true && \
    rm -f /usr/share/nmap/scripts/nucmap-template.nse && \
    nmap --script-updatedb

# 4. Install Node.js application
WORKDIR /opt/nucmap
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY config ./config
COPY src ./src
COPY public ./public
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && mkdir -p /data /root/nuclei-templates

VOLUME ["/data", "/root/nuclei-templates"]

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/api/system/status >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "src/server.js"]
