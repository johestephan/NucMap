# NucMap

[![Version](https://img.shields.io/badge/version-0.1.1-06b6d4?style=flat-square)](https://github.com/johestephan/NucMap/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald?style=flat-square)](LICENSE)
[![Proxmox VE LXC](https://img.shields.io/badge/Proxmox_VE-LXC_Helper_Script-E57000?style=flat-square&logo=proxmox)](proxmox/nucmap.sh)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?style=flat-square&logo=docker)](Dockerfile)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-339933?style=flat-square&logo=nodedotjs)](package.json)

**NucMap** is a lightweight, self-hosted **Attack Surface Management (ASM)** and **Vulnerability Verification** web platform. It orchestrates **Nmap** (for port discovery, service banner enumeration, and offline NSE `vulscan` CVE lookup) with **ProjectDiscovery Nuclei** (for template-based CVE and misconfiguration verification), storing historical states in SQLite to calculate **attack surface drift** across scans and emit real-time **JSON Syslog**, **Webhook**, and **SMTP** alerts.

---

## 🚀 Proxmox VE LXC Installation (One-Line Helper Script)

Run the following command directly in the **Proxmox VE Host Shell** (just like the Proxmox VE Community Scripts). It will create an unprivileged Debian LXC container (matching your host CPU architecture `amd64`/`arm64`), install `nmap`, `nuclei`, `vulscan`, and `nucmap`, and print the Web UI URL when finished:

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/johestephan/NucMap/main/proxmox/nucmap.sh)"
```

### Default LXC Container Specs
| Resource | Default Value | Configurable in Advanced Mode |
| :--- | :--- | :--- |
| **OS Template** | Debian 12 / 13 Standard | Auto-downloaded via `pveam` |
| **Container Type** | Unprivileged LXC | Yes |
| **CPU** | 2 vCPU Cores | Yes (`CT_CORES`) |
| **Memory** | 2048 MB RAM (512 MB Swap) | Yes (`CT_RAM`) |
| **Disk** | 8 GB | Yes (`CT_DISK` / `CT_STORAGE`) |
| **Network** | `vmbr0` (DHCP) | Yes (Static CIDR, Gateway, Bridge) |

### Non-Interactive Proxmox Deployment
```bash
CT_ID=150 CT_HOSTNAME=nucmap CT_STORAGE=local-lvm bash -c "$(wget -qLO - https://raw.githubusercontent.com/johestephan/NucMap/main/proxmox/nucmap.sh)" -s -- --yes
```

---

## 🔄 Updating NucMap (Existing Proxmox LXC or Standalone Host)

All scan history, monitored assets, custom profiles, and schedules are stored in `/opt/nucmap/data/nucmap.db` and are **preserved** during updates.

### Option A: Update from the Proxmox VE Host Shell
Replace `<CTID>` (e.g. `107`) with your NucMap container ID:

```bash
pct exec <CTID> -- bash -c "curl -fsSL https://raw.githubusercontent.com/johestephan/NucMap/main/installer.sh | bash"
```

### Option B: Update Inside the LXC Container or VM Console
Run inside the container/VM as `root`:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/johestephan/NucMap/main/installer.sh)"
```

*(Note: To update **Nuclei Templates** and the **Nmap NSE Script Database** at any time without restarting, click the **"Signatures & Templates"** button in the top-right corner of the Web UI.)*

---

## ✨ Key Features

* **Two-Stage Scanning Pipeline + Partial Stage Re-runs**:
  * **Stage 1 (`Nmap` + `TLS` + `Vulscan`)**: Fast port discovery, service banner & CPE fingerprinting (`-sV`), live SSL/TLS certificate expiry inspection, and optional offline `vulscan.nse` (`cve.csv`) banner CVE matching.
  * **Stage 2 (`ProjectDiscovery Nuclei`)**: Automatically pipes discovered HTTP/HTTPS and network services into Nuclei with `-as` (automatic Wappalyzer tech-stack template selection), `-ni` (no external OAST delays), and targeted exposure/default-login/CVE verification.
  * **Stage 3 (`Attack Surface Diffing`)**: Compares consecutive scans per asset and records `NEW_PORT`, `CLOSED_PORT`, `BANNER_CHANGED`, `NEW_VULN`, and `RESOLVED_VULN` drift events.
  * **Selective Stage Execution & Single-Port Re-verification**: Run the full pipeline, **Stage 1 Only** (ports & TLS), or **Stage 2 Only** (reuse saved ports), or click **↻ Redo Stage 1**, **↻ Redo Stage 2**, or **↻ Re-verify Port** on any individual port card without rescanning the entire host.
* **Enhanced Nmap Subnet Discovery Wizard**:
  * Auto-detects local network interfaces and subnet CIDRs for one-click selection.
  * **Fast Multi-Probe Sweep**: Combines ICMP (`-PE -PP`), TCP SYN/ACK ping probes across 15 common service ports, kernel `/proc/net/arp` + IEEE OUI hardware vendor lookup (even inside unprivileged LXC containers), and parallel reverse DNS resolution.
  * **Deep Port-Assisted Sweep (`-Pn --top-ports 25`)**: Discovers firewalled hosts that drop ICMP echo requests and previews their open ports before import.
* **Companion `NucMap-scripts` Library Integration (`https://github.com/johestephan/NucMap-scripts`)**:
  * Automatically clones, syncs, and indexes custom Nmap `.nse` Lua scripts and ProjectDiscovery Nuclei `.yaml` templates from [**NucMap-scripts**](https://github.com/johestephan/NucMap-scripts) during installation and via the **Signature & Template Updater** (`[2/4]`).
  * Any new `.nse` or `.yaml` script added to `NucMap-scripts` is automatically executed in standard scan profiles AND appears in the **NucMap-scripts Library** tab for targeted, on-demand single-script execution.
* **Custom Scan Profiles & Port Builder**:
  * Includes 7 built-in profiles (`web` [80,443], `web-backend` [80,443,3000,5000,8080...], `server` [SSH, LDAP, SMB, DB, Mail, DNS, Proxmox...], `quick`, `standard`, `deep`, `stealth`) plus a visual builder to create custom port profiles.
* **Synchronous Parallel Scanning (`1x` – `5x` Hosts)**:
  * Configurable worker pool allowing up to **5 hosts** to be scanned simultaneously, with live per-stage progress and one-click scan cancellation.
* **Automated Scheduled Scan Runs**:
  * Built-in recurring scheduler (hourly, 6h, 12h, daily, weekly) targeting all monitored assets, specific asset tags (`LAN`, `DMZ`, `IoT`, `Infra`), or individual hosts.
* **Finding Triage & Noise Suppression**:
  * Mark verified findings as **Accepted Risk** or **False Positive** so expected internal self-signed certificates or accepted findings are muted from Critical/High counters and future drift alerts.
* **JSON Syslog & Instant Push Alerts**:
  * Structured JSON logging to local `/dev/log` (`logger -t nucmap`) and/or remote UDP/TCP Syslog servers (Graylog, Loki, Splunk, Wazuh, ELK).
  * Instant push notifications on `NEW_PORT` and `NEW_VULN` via **Webhooks** (Ntfy, Discord, Slack, Gotify, Home Assistant) or local **Postfix SMTP** (`127.0.0.1:25`).
* **One-Click Exports & Database Backup**:
  * Export inventory and vulnerability summaries as **CSV** (`/api/export/assets.csv`), full **JSON** reports (`/api/export/report.json`), or download a live **SQLite database backup** (`/api/export/nucmap.db`).

---

## 🐳 Alternative Deployment Options

### Option 2: Docker & Docker Compose

#### Using Docker Compose
Clone the repository and start the container with `docker compose`:

```bash
git clone https://github.com/johestephan/NucMap.git
cd NucMap
docker compose up -d --build
```

Open **`http://<HOST_IP>:3000`** in your browser. To update a Docker deployment later, run `git pull && docker compose up -d --build`.

> **Note on Host Networking (`network_mode: host`)**:
> The provided `docker-compose.yml` uses `network_mode: host` with `NET_RAW` and `NET_ADMIN` capabilities so Nmap can perform Layer-2 ARP subnet discovery and fast raw SYN scans. If you prefer standard bridge port mapping, comment out `network_mode: host` and uncomment `ports: ["3000:3000"]` in `docker-compose.yml`.

#### Using `docker build` & `docker run`
```bash
docker build -t nucmap:0.1.1 .

docker run -d \
  --name nucmap \
  --restart unless-stopped \
  --network host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v nucmap_data:/data \
  -v nucmap_templates:/root/nuclei-templates \
  nucmap:0.1.1
```

---

### Option 3: Standalone Debian / Ubuntu LXC or VM (`installer.sh`)

If you already have a **Debian 12 / 13** or **Ubuntu 22.04 / 24.04** LXC container or VM, run the standalone installer as `root`:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/johestephan/NucMap/main/installer.sh)"
```

Or clone the repository and run locally / push via SSH to a remote host:

```bash
git clone https://github.com/johestephan/NucMap.git
cd NucMap

# Run on the current machine:
sudo ./installer.sh

# Or push & install/update onto a remote Debian/Ubuntu host via SSH:
./installer.sh --remote root@192.168.1.100
```

Once installed, the systemd service (`nucmap.service`) starts automatically and listens on:
* **`http://<HOST_IP>:3000`** (and **`http://<HOST_IP>:80`** when running as root)

---

## 🗂️ Project Structure

```text
NucMap/
├── package.json
├── LICENSE                     # MIT License
├── Dockerfile                  # Multi-arch (amd64/arm64) container image
├── docker-compose.yml          # Docker Compose configuration
├── docker-entrypoint.sh        # Container entrypoint & template initializer
├── installer.sh                # Standalone Debian/Ubuntu installer & updater
├── proxmox/
│   └── nucmap.sh               # Proxmox VE Community-Style LXC creation script
├── config/
│   └── profiles.json           # Built-in Nmap & Nuclei scan profile definitions
├── src/
│   ├── server.js               # Express HTTP server & REST API routes
│   ├── db.js                   # SQLite3 (WAL mode) schema & queries
│   ├── scanner.js              # Parallel job pool, stage re-runner & Nmap/Nuclei runner
│   ├── parser.js               # Nmap XML, Nuclei JSONL, ARP/OUI, rDNS & TLS parsers
│   ├── differ.js               # Attack surface drift & state comparison engine
│   └── syslog.js               # RFC5424 JSON Syslog, Webhook & Postfix SMTP alerts
├── public/
│   ├── index.html              # Responsive Dark-Mode Tailwind CSS SPA
│   └── app.js                  # Frontend logic, live polling & modals
└── systemd/
    └── nucmap.service          # Systemd unit with MemoryMax & auto-restart
```

---

## 🔌 REST API Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/system/status` | System health, version (`0.1.1`), profiles, queue & signature status |
| `GET` | `/api/discover/subnets` | Auto-detect local network interfaces and `/24` subnet CIDRs |
| `POST` | `/api/discover` | Run Nmap subnet discovery (`{"cidr": "192.168.1.0/24", "mode": "fast" \| "port_sweep"}`) |
| `GET` | `/api/assets` | List all monitored assets, open port badges, and active vuln counts |
| `POST` | `/api/assets` | Create or update a monitored asset |
| `POST` | `/api/assets/bulk` | Bulk-import discovered hosts and optionally trigger parallel scans |
| `POST` | `/api/scan` | Trigger scan (`{"target": "192.168.1.10", "profile": "standard", "stage_mode": "full" \| "nmap_only" \| "nuclei_only"}`) |
| `POST` | `/api/scan/:id/rerun-stage` | Re-run a specific stage or port (`{"stage": "nmap" \| "nuclei" \| "full", "port": 443}`) |
| `POST` | `/api/scan/:id/cancel` | Cancel an active or queued scan job |
| `POST` | `/api/scan/bulk-diff` | Queue rescan & drift comparison across all monitored assets |
| `GET` | `/api/scan/:id` | Poll live scan status, discovered ports, TLS certs, vulns, and diff |
| `POST` | `/api/vulns/triage` | Mark a finding as `open`, `accepted_risk`, or `false_positive` |
| `GET` | `/api/diffs` | Retrieve chronological attack surface drift events |
| `GET` | `/api/scripts` | Dynamically list all custom `.nse`, `.yaml`, and `.sh` modules from `NucMap-scripts` |
| `POST` | `/api/scripts/run` | Run selected `NucMap-scripts` modules against target(s) (`{"target": "192.168.1.10", "scripts": ["php-php2shell"]}`) |
| `GET/POST` | `/api/profiles` | List or create custom Nmap + Nuclei scan profiles |
| `GET/POST` | `/api/schedules` | List or create automated recurring scan schedules |
| `GET/POST` | `/api/system/syslog` | Configure JSON Syslog, Webhook, and Postfix email alerts |
| `POST` | `/api/system/update-signatures` | Trigger background `nuclei -update-templates` & `nmap --script-updatedb` |
| `GET` | `/api/export/assets.csv` | Download CSV asset & vulnerability inventory |
| `GET` | `/api/export/report.json` | Download full JSON assessment report |
| `GET` | `/api/export/nucmap.db` | Download portable SQLite database backup |

---

## 🔒 Security Considerations

1. **Built-in Authentication & API Key Support**: Set `NUCMAP_PASSWORD=<password>` (and optional `NUCMAP_USER=admin`) or `NUCMAP_API_KEY=<token>` in your environment / systemd unit / `docker-compose.yml` to enforce timing-safe HTTP Basic Auth and Bearer/X-API-Key authentication across the Web UI and all REST API endpoints.
2. **Strict Target & Flag Allowlists**: All scan targets (RFC-1123 FQDNs, IPv4, CIDR ranges) and custom Nmap profile flags are validated against strict allowlists and spawned via Node's `child_process.spawn(..., { shell: false })` to prevent shell or argument injection.
3. **Built-in Rate Limiting & Security Headers**: Express enforces per-IP API rate limiting (`NUCMAP_RATE_LIMIT`, default `240` req/min) and strict security headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`).
4. **Unprivileged Container Fallback**: If `nmap -sS` (SYN scan) or raw ARP discovery fails due to missing raw socket capabilities inside an unprivileged container, NucMap automatically falls back to TCP Connect (`-sT`) and kernel `/proc/net/arp` + IEEE OUI vendor lookup.

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full details.
