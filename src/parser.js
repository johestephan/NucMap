const fs = require('fs');
const dns = require('dns');
const tls = require('tls');
const xml2js = require('xml2js');

let nmapMacPrefixesMap = null;

function loadNmapMacPrefixes() {
  if (nmapMacPrefixesMap) return nmapMacPrefixesMap;
  nmapMacPrefixesMap = new Map();
  const candidates = ['/usr/share/nmap/nmap-mac-prefixes', '/usr/local/share/nmap/nmap-mac-prefixes'];
  for (const p of candidates) {
    try {
      if (!fs.existsSync(p)) continue;
      const lines = fs.readFileSync(p, 'utf8').split('\n');
      for (const line of lines) {
        if (!line || line.startsWith('#')) continue;
        const m = line.match(/^([0-9A-Fa-f]{6})\s+(.+)$/);
        if (m) {
          nmapMacPrefixesMap.set(m[1].toUpperCase(), m[2].trim());
        }
      }
      break;
    } catch (_) {}
  }
  return nmapMacPrefixesMap;
}

function lookupVendorByMac(mac) {
  if (!mac) return null;
  const prefix = mac.replace(/[^0-9A-Fa-f]/g, '').slice(0, 6).toUpperCase();
  if (prefix.length < 6) return null;
  const map = loadNmapMacPrefixes();
  return map.get(prefix) || null;
}

function readKernelArpTable() {
  const arpMap = new Map();
  try {
    if (!fs.existsSync('/proc/net/arp')) return arpMap;
    const lines = fs.readFileSync('/proc/net/arp', 'utf8').split('\n').slice(1);
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 4) {
        const ip = parts[0];
        const flags = parts[2];
        const mac = parts[3].toUpperCase();
        if (flags !== '0x0' && mac && mac !== '00:00:00:00:00:00') {
          arpMap.set(ip, mac);
        }
      }
    }
  } catch (_) {}
  return arpMap;
}

const WEB_PORTS = new Set([80, 443, 3000, 5000, 5001, 8000, 8006, 8008, 8080, 8081, 8443, 8444, 8843, 8880, 8888, 8900, 9000, 9090, 9350, 9351, 9443]);
const HTTPS_PORTS = new Set([443, 5001, 8006, 8443, 8444, 8843, 8900, 9351, 9443]);
const TLS_PORTS = new Set([443, 465, 636, 993, 995, 5001, 8006, 8443, 8444, 8843, 8900, 9351, 9443]);

function asArray(val) {
  if (!val) return [];
  return Array.isArray(val) ? val : [val];
}

// Parse Nmap NSE vulscan output from <script id="vulscan" output="..."/>
function parseVulscanScriptOutput(outputText, portNum, targetHost) {
  if (!outputText || typeof outputText !== 'string') return [];
  const lines = outputText.split('\n');
  const findings = [];
  const seen = new Set();

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    // Match CVE-YYYY-NNNNN patterns in vulscan output
    const cveMatch = line.match(/\[(CVE-\d{4}-\d{4,7})\]\s*(.*)/i) || line.match(/^(CVE-\d{4}-\d{4,7})[|:\s]+(.*)/i);
    if (!cveMatch) continue;

    const cveId = cveMatch[1].toUpperCase();
    const title = (cveMatch[2] || '').trim() || `Nmap Vulscan match ${cveId}`;

    // Skip ancient CVEs older than 2018 to avoid noisy banner false positives, and cap at 8 per port
    const yearMatch = cveId.match(/^CVE-(\d{4})-/);
    const year = yearMatch ? parseInt(yearMatch[1], 10) : 2020;
    if (year < 2018) continue;

    if (seen.has(cveId)) continue;
    seen.add(cveId);

    let severity = 'medium';
    if (/remote code execution|rce|unauthenticated|arbitrary code|command injection|auth bypass/i.test(title)) {
      severity = 'high';
    } else if (/denial of service|dos|information disclosure/i.test(title)) {
      severity = 'low';
    }

    findings.push({
      port: portNum,
      template_id: `nse-vulscan-${cveId.toLowerCase()}`,
      name: `[NSE Vulscan] ${cveId}: ${title.slice(0, 140)}`,
      severity,
      cve_id: cveId,
      matched_at: `${targetHost}:${portNum}`,
      extracted_results: ['source:nmap-vulscan'],
      description: title
    });

    if (findings.length >= 8) break;
  }

  return findings;
}

async function parseNmapXml(xmlString, defaultTarget = '') {
  if (!xmlString || !xmlString.trim()) {
    return {
      hostname: null,
      mac_address: null,
      vendor: null,
      ports: [],
      nse_vulns: [],
      hosts_up: 0
    };
  }

  const parser = new xml2js.Parser({
    explicitArray: false,
    mergeAttrs: false
  });

  const parsed = await parser.parseStringPromise(xmlString);
  const nmaprun = parsed?.nmaprun;
  if (!nmaprun) {
    return {
      hostname: null,
      mac_address: null,
      vendor: null,
      ports: [],
      nse_vulns: [],
      hosts_up: 0
    };
  }

  const hosts = asArray(nmaprun.host);
  const multiHost = hosts.length > 1;

  let primaryHostname = null;
  let primaryMac = null;
  let primaryVendor = null;
  const openPorts = [];
  const nseVulns = [];
  let hostsUp = 0;

  for (const host of hosts) {
    const statusState = host?.status?.$?.state;
    if (statusState && statusState !== 'up') {
      continue;
    }
    hostsUp++;

    const addresses = asArray(host.address);
    let hostIp = null;
    for (const addr of addresses) {
      const a = addr?.$;
      if (!a) continue;
      if (a.addrtype === 'ipv4' || a.addrtype === 'ipv6') {
        hostIp = a.addr;
      } else if (a.addrtype === 'mac') {
        if (!primaryMac) primaryMac = a.addr || null;
        if (!primaryVendor && a.vendor) primaryVendor = a.vendor;
      }
    }

    const hostnames = asArray(host?.hostnames?.hostname);
    for (const hn of hostnames) {
      if (hn?.$?.name && !primaryHostname) {
        primaryHostname = hn.$.name;
      }
    }

    const portEntries = asArray(host?.ports?.port);
    for (const p of portEntries) {
      const attrs = p?.$ || {};
      const stateAttrs = p?.state?.$ || {};
      if (stateAttrs.state !== 'open') {
        continue;
      }

      const portNum = parseInt(attrs.portid, 10);
      if (Number.isNaN(portNum)) continue;

      const protocol = (attrs.protocol || 'tcp').toLowerCase();
      const svcAttrs = p?.service?.$ || {};
      let serviceName = svcAttrs.name || 'unknown';
      const tunnel = svcAttrs.tunnel || '';
      if (tunnel === 'ssl' && !serviceName.includes('ssl') && !serviceName.includes('https')) {
        serviceName = serviceName === 'http' ? 'https' : `ssl/${serviceName}`;
      }

      const serviceProduct = svcAttrs.product || null;
      const serviceVersion = svcAttrs.version || null;
      let extraInfo = svcAttrs.extrainfo || null;
      if (multiHost && hostIp) {
        extraInfo = extraInfo ? `[${hostIp}] ${extraInfo}` : `[${hostIp}]`;
      }

      const cpeRaw = asArray(p?.service?.cpe);
      const cpeList = cpeRaw
        .map((c) => (typeof c === 'string' ? c : c?._ || ''))
        .filter(Boolean);
      const cpe = cpeList.length > 0 ? cpeList.join(', ') : null;

      // Parse NSE scripts on port (such as vulscan)
      const scripts = asArray(p?.script);
      for (const sc of scripts) {
        const scAttrs = sc?.$ || {};
        if (scAttrs.id === 'vulscan' && scAttrs.output) {
          const matchedVulns = parseVulscanScriptOutput(scAttrs.output, portNum, hostIp || defaultTarget);
          nseVulns.push(...matchedVulns);
        }
      }

      openPorts.push({
        port: portNum,
        protocol,
        state: 'open',
        service_name: serviceName,
        service_product: serviceProduct,
        service_version: serviceVersion,
        extra_info: extraInfo,
        cpe,
        host_ip: hostIp
      });
    }
  }

  // Fallback to kernel ARP cache (/proc/net/arp) for single-host scans in unprivileged LXC
  if (!primaryMac && defaultTarget) {
    const arpTable = readKernelArpTable();
    if (arpTable.has(defaultTarget)) {
      primaryMac = arpTable.get(defaultTarget);
    }
  }
  if (primaryMac && !primaryVendor) {
    primaryVendor = lookupVendorByMac(primaryMac);
  }

  return {
    hostname: primaryHostname,
    mac_address: primaryMac,
    vendor: primaryVendor,
    ports: openPorts,
    nse_vulns: nseVulns,
    hosts_up: hostsUp
  };
}

// Parse Nmap Host Discovery XML for Subnet Sweep (enriches with kernel ARP table, MAC OUI vendor & reverse DNS)
async function parseNmapHostDiscoveryXml(xmlString) {
  if (!xmlString || !xmlString.trim()) return [];
  const parser = new xml2js.Parser({ explicitArray: false, mergeAttrs: false });
  const parsed = await parser.parseStringPromise(xmlString);
  const hosts = asArray(parsed?.nmaprun?.host);
  const arpTable = readKernelArpTable();
  const discovered = [];

  for (const host of hosts) {
    const statusState = host?.status?.$?.state;
    const portEntries = asArray(host?.ports?.port);
    const openPorts = [];
    for (const p of portEntries) {
      if (p?.state?.$?.state === 'open') {
        const pNum = parseInt(p?.$?.portid, 10);
        if (!Number.isNaN(pNum)) openPorts.push(pNum);
      }
    }

    if (statusState !== 'up' && openPorts.length === 0) continue;

    const addresses = asArray(host.address);
    let ip = null;
    let mac = null;
    let vendor = null;

    for (const addr of addresses) {
      const a = addr?.$;
      if (!a) continue;
      if (a.addrtype === 'ipv4' || a.addrtype === 'ipv6') ip = a.addr;
      else if (a.addrtype === 'mac') {
        mac = a.addr ? a.addr.toUpperCase() : null;
        vendor = a.vendor || null;
      }
    }
    if (!ip) continue;

    // Fallback to kernel ARP cache (/proc/net/arp) if running in an unprivileged container
    if (!mac && arpTable.has(ip)) {
      mac = arpTable.get(ip);
    }
    if (mac && !vendor) {
      vendor = lookupVendorByMac(mac);
    }

    let hostname = null;
    const hostnames = asArray(host?.hostnames?.hostname);
    for (const hn of hostnames) {
      if (hn?.$?.name) {
        hostname = hn.$.name;
        break;
      }
    }

    discovered.push({
      target: ip,
      hostname,
      mac_address: mac,
      vendor,
      open_ports: openPorts
    });
  }

  // Enrich missing hostnames with fast reverse DNS lookups (800ms timeout)
  await Promise.all(
    discovered.map(async (item) => {
      if (item.hostname) return;
      try {
        const names = await Promise.race([
          dns.promises.reverse(item.target),
          new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 800))
        ]);
        if (Array.isArray(names) && names.length > 0) {
          item.hostname = names[0];
        }
      } catch (_) {}
    })
  );

  // Also enrich single-host Nmap XML runs with kernel ARP table if MAC was missing
  return discovered;
}

function isWebService(portObj) {
  const svc = (portObj.service_name || '').toLowerCase();
  const port = Number(portObj.port);
  if (
    svc.includes('http') ||
    svc.includes('www') ||
    svc.includes('ssl/http') ||
    svc.includes('https') ||
    svc.includes('http-proxy') ||
    svc.includes('http-alt')
  ) {
    return true;
  }
  return WEB_PORTS.has(port);
}

function isHttpsService(portObj) {
  const svc = (portObj.service_name || '').toLowerCase();
  const port = Number(portObj.port);
  if (svc.includes('https') || svc.includes('ssl') || svc.includes('tls')) {
    return true;
  }
  return HTTPS_PORTS.has(port);
}

function isTlsCandidatePort(portObj) {
  const svc = (portObj.service_name || '').toLowerCase();
  const port = Number(portObj.port);
  if (svc.includes('https') || svc.includes('ssl') || svc.includes('tls')) {
    return true;
  }
  return TLS_PORTS.has(port);
}

// Probe TLS Certificate on SSL/HTTPS ports to extract CN, Issuer, Expiry, and generate expiry warnings
function probeSingleTlsPort(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (val) => {
      if (!settled) {
        settled = true;
        resolve(val);
      }
    };

    const socket = tls.connect(
      {
        host,
        port: Number(port),
        servername: netIsIp(host) ? undefined : host,
        rejectUnauthorized: false,
        timeout: timeoutMs
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(false);
          socket.end();
          if (!cert || !cert.valid_to) {
            return finish(null);
          }
          const validToDate = new Date(cert.valid_to);
          const daysRemaining = Math.floor((validToDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
          const cn = cert.subject?.CN || cert.subject?.O || 'unknown';
          const issuer = cert.issuer?.CN || cert.issuer?.O || 'unknown';
          const selfSigned = cn === issuer;

          finish({
            cn: Array.isArray(cn) ? cn[0] : cn,
            issuer: Array.isArray(issuer) ? issuer[0] : issuer,
            valid_to: validToDate.toISOString().slice(0, 10),
            days_remaining: daysRemaining,
            self_signed: selfSigned
          });
        } catch (_) {
          socket.destroy();
          finish(null);
        }
      }
    );

    socket.on('error', () => {
      socket.destroy();
      finish(null);
    });

    socket.on('timeout', () => {
      socket.destroy();
      finish(null);
    });
  });
}

function netIsIp(str) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(str) || str.includes(':');
}

async function inspectTlsCertificates(target, openPorts) {
  const tlsFindings = [];
  const isCidr = target.includes('/');

  for (const p of openPorts) {
    if (p.state !== 'open' || !isTlsCandidatePort(p)) continue;
    const hostTarget = isCidr && p.host_ip ? p.host_ip : target;
    if (!hostTarget || hostTarget.includes('/')) continue;

    const certInfo = await probeSingleTlsPort(hostTarget, p.port, 2800);
    if (!certInfo) continue;

    const certSummary = `TLS[CN=${certInfo.cn}, exp=${certInfo.valid_to} (${certInfo.days_remaining}d)${
      certInfo.self_signed ? ', self-signed' : ''
    }]`;
    p.extra_info = p.extra_info ? `${p.extra_info} • ${certSummary}` : certSummary;

    if (certInfo.days_remaining < 0) {
      tlsFindings.push({
        port: p.port,
        template_id: 'tls-certificate-expired',
        name: `SSL/TLS Certificate Expired (${Math.abs(certInfo.days_remaining)} days ago)`,
        severity: 'high',
        cve_id: null,
        matched_at: `https://${hostTarget}:${p.port}`,
        extracted_results: [`CN=${certInfo.cn}`, `Expired=${certInfo.valid_to}`],
        description: `The TLS certificate on port ${p.port} (CN=${certInfo.cn}, Issuer=${certInfo.issuer}) expired on ${certInfo.valid_to}.`
      });
    } else if (certInfo.days_remaining <= 14) {
      tlsFindings.push({
        port: p.port,
        template_id: 'tls-certificate-expiring-soon',
        name: `SSL/TLS Certificate Expiring Soon (${certInfo.days_remaining} days left)`,
        severity: 'medium',
        cve_id: null,
        matched_at: `https://${hostTarget}:${p.port}`,
        extracted_results: [`CN=${certInfo.cn}`, `Expires=${certInfo.valid_to}`],
        description: `The TLS certificate on port ${p.port} (CN=${certInfo.cn}) will expire on ${certInfo.valid_to} (${certInfo.days_remaining} days remaining).`
      });
    }
  }

  return tlsFindings;
}

const NUCLEI_NETWORK_PORTS = new Set([
  21, 22, 23, 25, 53, 110, 111, 143, 389, 445, 465, 587, 636, 873,
  993, 995, 1099, 1433, 1521, 2049, 2181, 2375, 2376, 3306, 3389,
  4369, 5432, 5672, 5900, 5984, 6379, 6443, 7001, 8009, 9042, 9092,
  9100, 9200, 9300, 11211, 27017
]);

function buildNucleiTargets(target, openPorts, profileConfig = {}) {
  const urls = new Set();
  const isCidr = target.includes('/');

  for (const p of openPorts) {
    if (p.state !== 'open') continue;
    const hostTarget = isCidr && p.host_ip ? p.host_ip : target;
    if (!hostTarget || hostTarget.includes('/')) continue;

    if (isWebService(p)) {
      const scheme = isHttpsService(p) ? 'https' : 'http';
      urls.add(`${scheme}://${hostTarget}:${p.port}`);
    } else if (profileConfig.include_non_http_nuclei !== false && NUCLEI_NETWORK_PORTS.has(Number(p.port))) {
      urls.add(`${hostTarget}:${p.port}`);
    }
  }

  return Array.from(urls);
}

function extractPortFromMatchedAt(matchedAt, objPort) {
  if (objPort && !Number.isNaN(Number(objPort))) {
    return Number(objPort);
  }
  if (!matchedAt || typeof matchedAt !== 'string') return null;

  try {
    if (matchedAt.startsWith('http://') || matchedAt.startsWith('https://')) {
      const u = new URL(matchedAt);
      if (u.port) return parseInt(u.port, 10);
      return u.protocol === 'https:' ? 443 : 80;
    }
  } catch (_) {}

  const match = matchedAt.match(/:(\d{1,5})(?:\/|$|\s)/);
  if (match) {
    return parseInt(match[1], 10);
  }
  return null;
}

function parseNucleiJsonlLine(line) {
  if (!line || !line.trim()) return null;
  let obj;
  try {
    obj = JSON.parse(line.trim());
  } catch (_) {
    return null;
  }

  const templateId = obj['template-id'] || obj.templateID || obj.template_id;
  if (!templateId) return null;

  const info = obj.info || {};
  const matcherName = obj['matcher-name'] || obj.matcher_name || '';
  const baseName = info.name || templateId;
  const name = matcherName ? `${baseName} (${matcherName})` : baseName;
  const severity = (info.severity || 'info').toLowerCase();

  let cveId = null;
  const rawCve = info?.classification?.['cve-id'] || info?.classification?.cve_id;
  if (Array.isArray(rawCve) && rawCve.length > 0) {
    cveId = rawCve.join(', ').toUpperCase();
  } else if (typeof rawCve === 'string' && rawCve.trim()) {
    cveId = rawCve.trim().toUpperCase();
  } else if (/^CVE-\d{4}-\d+/i.test(templateId)) {
    cveId = templateId.toUpperCase();
  }

  const matchedAt = obj['matched-at'] || obj.matched || obj.host || '';
  const port = extractPortFromMatchedAt(matchedAt, obj.port);

  const extractedResults = Array.isArray(obj['extracted-results'])
    ? obj['extracted-results']
    : Array.isArray(obj.extracted_results)
    ? obj.extracted_results
    : [];

  const description = info.description || null;

  return {
    port,
    template_id: templateId,
    name,
    severity,
    cve_id: cveId,
    matched_at: matchedAt,
    extracted_results: extractedResults,
    description
  };
}

function parseNucleiJsonl(jsonlText) {
  if (!jsonlText || !jsonlText.trim()) return [];
  const lines = jsonlText.split('\n');
  const results = [];
  const seen = new Set();

  for (const line of lines) {
    const parsed = parseNucleiJsonlLine(line);
    if (!parsed) continue;
    const dedupKey = `${parsed.template_id}|${parsed.matched_at}|${parsed.name}`;
    if (!seen.has(dedupKey)) {
      seen.add(dedupKey);
      results.push(parsed);
    }
  }
  return results;
}

module.exports = {
  parseNmapXml,
  parseNmapHostDiscoveryXml,
  inspectTlsCertificates,
  buildNucleiTargets,
  parseNucleiJsonlLine,
  parseNucleiJsonl
};
