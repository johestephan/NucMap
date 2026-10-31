const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const db = require('./db');
const parser = require('./parser');
const differ = require('./differ');
const syslog = require('./syslog');

function loadProfiles() {
  return db.getAllProfilesMap();
}

function isValidHostname(str) {
  if (!str || str.length > 253) return false;
  const cleaned = str.endsWith('.') ? str.slice(0, -1) : str;
  const labels = cleaned.split('.');
  if (labels.length === 0) return false;
  for (const label of labels) {
    if (!label || label.length > 63) return false;
    if (!/^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?$/.test(label)) {
      return false;
    }
  }
  return true;
}

function isValidIpv4OrRange(ipPart) {
  const octets = ipPart.split('.');
  if (octets.length !== 4) return false;
  for (let i = 0; i < 4; i++) {
    const oct = octets[i];
    if (i === 3 && /^\d{1,3}-\d{1,3}$/.test(oct)) {
      const [start, end] = oct.split('-').map(Number);
      if (start < 0 || start > 255 || end < 0 || end > 255 || start > end) return false;
      continue;
    }
    if (!/^\d{1,3}$/.test(oct)) return false;
    const num = Number(oct);
    if (num < 0 || num > 255) return false;
  }
  return true;
}

function sanitizeAndValidateTarget(rawTarget) {
  if (!rawTarget || typeof rawTarget !== 'string') {
    throw new Error('Target is required.');
  }

  let target = rawTarget.trim();
  if (/^https?:\/\//i.test(target)) {
    target = target.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  }

  if (!target || target.length > 253) {
    throw new Error('Invalid target length.');
  }

  if (target.startsWith('-')) {
    throw new Error('Target cannot start with a hyphen (-).');
  }

  if (target.includes('/')) {
    const parts = target.split('/');
    if (parts.length !== 2 || !isValidIpv4OrRange(parts[0])) {
      throw new Error('Invalid CIDR format (expected IPv4/mask, e.g. 192.168.1.0/24).');
    }
    const mask = Number(parts[1]);
    if (!Number.isInteger(mask) || mask < 8 || mask > 32) {
      throw new Error('CIDR prefix length must be between /8 and /32.');
    }
    return target;
  }

  if (!isValidIpv4OrRange(target) && !isValidHostname(target)) {
    throw new Error('Target contains invalid characters. Only valid IPv4, CIDR (e.g. 192.168.1.0/24), or FQDN/hostname allowed.');
  }

  return target;
}

const SAFE_NMAP_STANDALONE_FLAGS = new Set([
  '-sV', '-sS', '-sT', '-sU', '-sC', '-A', '-O', '-Pn', '-PE', '-PP', '-n', '-R',
  '-T1', '-T2', '-T3', '-T4', '-T5', '--open', '--version-light', '--version-all'
]);

function filterSafeNmapTokens(rawStr) {
  const tokens = String(rawStr || '-sV --version-intensity 5 -T4').trim().split(/\s+/).filter(Boolean);
  const safe = [];
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if (SAFE_NMAP_STANDALONE_FLAGS.has(tok)) {
      safe.push(tok);
    } else if (tok === '--version-intensity' && /^[0-9]$/.test(tokens[i + 1] || '')) {
      safe.push(tok, tokens[i + 1]);
      i++;
    } else if (tok === '--max-retries' && /^[0-5]$/.test(tokens[i + 1] || '')) {
      safe.push(tok, tokens[i + 1]);
      i++;
    } else if (tok === '--host-timeout' && /^[0-9]{1,4}[ms]$/.test(tokens[i + 1] || '')) {
      safe.push(tok, tokens[i + 1]);
      i++;
    }
  }
  if (!safe.includes('-sV')) {
    safe.unshift('-sV');
  }
  return safe;
}

function validateAndBuildProfile(input) {
  const rawId = String(input.id || input.name || '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\-_]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');

  if (!rawId || rawId.length < 2 || rawId.length > 100) {
    throw new Error('Profile ID/Name must be 2–100 alphanumeric characters.');
  }

  const name = String(input.name || rawId).trim();
  const description = String(input.description || '').trim();

  const portsRaw = String(input.ports || '80,443').trim().replace(/\s+/g, '');
  let portArgs = [];
  if (portsRaw === 'top-100' || portsRaw === '-F') {
    portArgs = ['-F'];
  } else if (portsRaw === 'top-1000') {
    portArgs = [];
  } else if (portsRaw === '1-65535' || portsRaw === '-p-' || portsRaw === 'all') {
    portArgs = ['-p-'];
  } else {
    if (!/^[0-9,\-]+$/.test(portsRaw)) {
      throw new Error('Ports must be comma-separated port numbers or ranges (e.g. 80,443,3000-3010 or 1-10000).');
    }
    const segments = portsRaw.split(',').filter(Boolean);
    if (segments.length === 0) {
      throw new Error('At least one port or port range is required.');
    }
    for (const seg of segments) {
      const rangeParts = seg.split('-');
      if (rangeParts.length === 1) {
        const p = Number(rangeParts[0]);
        if (!Number.isInteger(p) || p < 1 || p > 65535) {
          throw new Error(`Invalid port number: ${seg} (must be 1–65535).`);
        }
      } else if (rangeParts.length === 2) {
        const p1 = Number(rangeParts[0]);
        const p2 = Number(rangeParts[1]);
        if (!Number.isInteger(p1) || !Number.isInteger(p2) || p1 < 1 || p2 > 65535 || p1 > p2) {
          throw new Error(`Invalid port range: ${seg} (must be 1–65535).`);
        }
      } else {
        throw new Error(`Invalid port segment: ${seg}`);
      }
    }
    portArgs = ['-p', portsRaw];
  }

  const allowedTokens = filterSafeNmapTokens(input.nmap_extra_args);

  const nmap_args = [...allowedTokens, ...portArgs];

  const allowedSevs = new Set(['info', 'low', 'medium', 'high', 'critical']);
  const sevList = String(input.nuclei_severities || 'low,medium,high,critical')
    .toLowerCase()
    .split(',')
    .map((s) => s.trim())
    .filter((s) => allowedSevs.has(s));
  const nuclei_severities = sevList.length > 0 ? sevList.join(',') : 'low,medium,high,critical';

  const tagList = String(input.nuclei_tags || 'panel,exposure,misconfig,default-login')
    .toLowerCase()
    .split(',')
    .map((t) => t.trim().replace(/[^a-z0-9\-_]/g, ''))
    .filter(Boolean);
  const nuclei_tags = tagList.join(',');

  const rateLimit = Math.min(500, Math.max(10, parseInt(input.rate_limit || '150', 10) || 150));
  const concurrency = Math.min(50, Math.max(2, parseInt(input.nuclei_concurrency || '25', 10) || 25));
  const automaticScan = input.automatic_scan !== false;

  const nuclei_args = [];
  if (automaticScan) {
    nuclei_args.push('-as');
  }
  if (input.include_non_http_nuclei) {
    nuclei_args.push('-t', 'network/');
  }
  if (
    !nuclei_tags ||
    nuclei_tags === 'panel,exposure,misconfig,default-login' ||
    nuclei_tags === 'panel,exposure,default-login'
  ) {
    nuclei_args.push('-t', 'http/exposed-panels/', '-t', 'http/default-logins/', '-t', 'http/exposures/');
  } else {
    nuclei_args.push('-tags', nuclei_tags);
  }
  nuclei_args.push(
    '-s',
    nuclei_severities,
    '-rl',
    String(rateLimit),
    '-c',
    String(concurrency),
    '-bs',
    String(Math.max(2, Math.floor(concurrency / 2))),
    '-timeout',
    '3',
    '-retries',
    '1',
    '-mhe',
    '10',
    '-ni'
  );

  const nuclei_extra_args = nuclei_args.join(' ');

  return {
    id: rawId,
    name,
    description,
    ports: portsRaw,
    nmap_extra_args: allowedTokens.join(' '),
    nmap_args,
    nuclei_tags,
    nuclei_severities,
    nuclei_extra_args,
    nuclei_args,
    include_non_http_nuclei: Boolean(input.include_non_http_nuclei),
    enable_vulscan: Boolean(input.enable_vulscan),
    is_builtin: Boolean(input.is_builtin)
  };
}

function resolveBinary(preferredPath, fallbackName) {
  try {
    if (fs.existsSync(preferredPath)) {
      return preferredPath;
    }
  } catch (_) {}
  return fallbackName;
}

const NMAP_BIN = resolveBinary('/usr/bin/nmap', 'nmap');
const NUCLEI_BIN = resolveBinary('/usr/local/bin/nuclei', 'nuclei');

const activeScanProcesses = new Map();

function runProcess(cmd, args, { scanId = null, onStdoutLine, onStderrLine, timeoutMs = 1200 * 1000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      shell: false,
      env: {
        ...process.env,
        HOME: process.env.HOME || '/root',
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
      }
    });

    if (scanId !== null) {
      activeScanProcesses.set(scanId, child);
    }

    let stdout = '';
    let stderr = '';
    let stdoutRemainder = '';
    let stderrRemainder = '';
    let killedByTimeout = false;

    const timer = timeoutMs
      ? setTimeout(() => {
          killedByTimeout = true;
          child.kill('SIGTERM');
          setTimeout(() => child.kill('SIGKILL'), 3000);
        }, timeoutMs)
      : null;

    child.stdout.on('data', (chunk) => {
      const text = chunk.toString('utf8');
      stdout += text;
      if (onStdoutLine) {
        stdoutRemainder += text;
        const lines = stdoutRemainder.split('\n');
        stdoutRemainder = lines.pop();
        for (const line of lines) {
          onStdoutLine(line);
        }
      }
    });

    child.stderr.on('data', (chunk) => {
      const text = chunk.toString('utf8');
      stderr += text;
      if (onStderrLine) {
        stderrRemainder += text;
        const lines = stderrRemainder.split('\n');
        stderrRemainder = lines.pop();
        for (const line of lines) {
          onStderrLine(line);
        }
      }
    });

    child.on('error', (err) => {
      if (timer) clearTimeout(timer);
      if (scanId !== null) activeScanProcesses.delete(scanId);
      reject(err);
    });

    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      if (scanId !== null) activeScanProcesses.delete(scanId);
      if (onStdoutLine && stdoutRemainder) onStdoutLine(stdoutRemainder);
      if (onStderrLine && stderrRemainder) onStderrLine(stderrRemainder);

      if (killedByTimeout) {
        reject(new Error(`Process ${cmd} timed out after ${timeoutMs / 1000}s`));
      } else {
        resolve({ code, stdout, stderr });
      }
    });
  });
}

// Fast Subnet Ping/ARP Sweep (-sn) for Host Discovery
async function discoverSubnetHosts(rawCidr) {
  const cidr = sanitizeAndValidateTarget(rawCidr);
  const args = ['-sn', '-T4', '-oX', '-', '--', cidr];
  const res = await runProcess(NMAP_BIN, args, { timeoutMs: 120 * 1000 });
  if (res.code !== 0 && !res.stdout.includes('<nmaprun')) {
    throw new Error(`Nmap discovery failed: ${res.stderr || 'Unknown error'}`);
  }

  const hosts = await parser.parseNmapHostDiscoveryXml(res.stdout);
  const existingAssets = db.listAssets({ includeTransient: false });
  const existingSet = new Set(existingAssets.map((a) => a.target));

  return hosts.map((h) => ({
    ...h,
    already_monitored: existingSet.has(h.target)
  }));
}

async function executeNmapStage(scanId, target, profileConfig) {
  const extraVulscanArgs = [];
  if (
    profileConfig.enable_vulscan &&
    fs.existsSync('/usr/share/nmap/scripts/vulscan/vulscan.nse')
  ) {
    extraVulscanArgs.push(
      '--script=vulscan/vulscan.nse',
      '--script-args',
      'vulscandb=cve.csv'
    );
  }

  const baseArgs = ['-oX', '-', ...profileConfig.nmap_args, ...extraVulscanArgs, '--', target];
  let result = await runProcess(NMAP_BIN, baseArgs, { scanId, timeoutMs: 900 * 1000 });

  if (
    result.code !== 0 &&
    /root privileges|raw|socket|Operation not permitted|dnet: Failed/i.test(result.stderr)
  ) {
    const fallbackFlags = profileConfig.nmap_args.map((flag) => {
      if (flag === '-sS') return '-sT';
      if (flag === '-A') return '-sC';
      return flag;
    });
    if (!fallbackFlags.includes('-sT')) {
      fallbackFlags.unshift('-sT');
    }
    const fallbackArgs = ['-oX', '-', ...fallbackFlags, ...extraVulscanArgs, '--', target];
    result = await runProcess(NMAP_BIN, fallbackArgs, { scanId, timeoutMs: 900 * 1000 });
  }

  if (result.code !== 0 && !result.stdout.includes('<nmaprun')) {
    throw new Error(`Nmap failed (exit ${result.code}): ${result.stderr || 'Unknown error'}`);
  }

  return result;
}

function ensureNucleiTemplateSymlinks() {
  const homeDir = process.env.HOME || '/root';
  const templatesDir = path.join(homeDir, 'nuclei-templates');
  try {
    if (!fs.existsSync(templatesDir)) return;
    const httpCves = path.join(templatesDir, 'http', 'cves');
    const cvesLink = path.join(templatesDir, 'cves');
    if (fs.existsSync(httpCves) && !fs.existsSync(cvesLink)) {
      fs.symlinkSync(httpCves, cvesLink);
    }

    const httpPanels = path.join(templatesDir, 'http', 'exposed-panels');
    const panelsLink = path.join(templatesDir, 'exposed-panels');
    if (fs.existsSync(httpPanels) && !fs.existsSync(panelsLink)) {
      fs.symlinkSync(httpPanels, panelsLink);
    }
  } catch (_) {}
}

async function executeNucleiStage(scanId, target, urls, profileConfig) {
  if (!urls || urls.length === 0) {
    return { code: 0, stdout: '', stderr: '' };
  }

  ensureNucleiTemplateSymlinks();

  const tmpFile = `/tmp/scan_${scanId}_urls.txt`;
  fs.writeFileSync(tmpFile, urls.join('\n') + '\n', { mode: 0o600 });

  const seenFindings = new Set();
  const baseNucleiArgs = [...(profileConfig.nuclei_args || [])];

  if (!baseNucleiArgs.includes('-timeout')) {
    baseNucleiArgs.push('-timeout', '3');
  }
  if (!baseNucleiArgs.includes('-retries')) {
    baseNucleiArgs.push('-retries', '1');
  }
  if (!baseNucleiArgs.includes('-mhe')) {
    baseNucleiArgs.push('-mhe', '10');
  }
  if (!baseNucleiArgs.includes('-ni')) {
    baseNucleiArgs.push('-ni');
  }

  const args = [
    '-l',
    tmpFile,
    ...baseNucleiArgs,
    '-jsonl',
    '-silent',
    '-nc',
    '-duc'
  ];

  try {
    const result = await runProcess(NUCLEI_BIN, args, {
      scanId,
      timeoutMs: 900 * 1000,
      onStdoutLine: (line) => {
        const parsed = parser.parseNucleiJsonlLine(line);
        if (parsed) {
          const key = `${parsed.template_id}|${parsed.matched_at}|${parsed.name}`;
          if (!seenFindings.has(key)) {
            seenFindings.add(key);
            try {
              db.insertScanVulnSingle(scanId, parsed);
              syslog.logEvent(
                'VULN_FOUND',
                {
                  scan_id: scanId,
                  target,
                  port: parsed.port,
                  template_id: parsed.template_id,
                  name: parsed.name,
                  cve_id: parsed.cve_id,
                  matched_at: parsed.matched_at
                },
                parsed.severity
              );
            } catch (_) {}
          }
        }
      }
    });
    return result;
  } finally {
    try {
      if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
    } catch (_) {}
  }
}

const scanQueue = [];
const activeScanIds = new Set();
const cancelledScanIds = new Set();

function getMaxConcurrency() {
  const meta = db.getSystemMeta('max_concurrency');
  if (meta && meta.value) {
    const val = parseInt(meta.value, 10);
    if (val >= 1 && val <= 5) return val;
  }
  return 3;
}

function setMaxConcurrency(val) {
  const clamped = Math.min(5, Math.max(1, parseInt(val, 10) || 3));
  db.setSystemMeta('max_concurrency', String(clamped));
  pumpScanPool();
  return clamped;
}

function enqueueScan(scanId) {
  if (!scanQueue.includes(scanId) && !activeScanIds.has(scanId)) {
    scanQueue.push(scanId);
  }
  pumpScanPool();
}

function pumpScanPool() {
  const maxConc = getMaxConcurrency();
  while (activeScanIds.size < maxConc && scanQueue.length > 0) {
    const scanId = scanQueue.shift();
    if (cancelledScanIds.has(scanId)) {
      cancelledScanIds.delete(scanId);
      continue;
    }
    activeScanIds.add(scanId);
    runScanPipeline(scanId)
      .catch((err) => {
        console.error(`[Scanner] Unhandled error in scan ${scanId}:`, err);
        db.updateScanStatus(scanId, 'failed', { error_log: err.message });
      })
      .finally(() => {
        activeScanIds.delete(scanId);
        cancelledScanIds.delete(scanId);
        pumpScanPool();
      });
  }
}

function cancelScan(scanId) {
  const numId = Number(scanId);
  cancelledScanIds.add(numId);

  const qIdx = scanQueue.indexOf(numId);
  if (qIdx !== -1) {
    scanQueue.splice(qIdx, 1);
  }

  const child = activeScanProcesses.get(numId);
  if (child) {
    try {
      child.kill('SIGTERM');
      setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch (_) {}
      }, 1500);
    } catch (_) {}
    activeScanProcesses.delete(numId);
  }

  db.updateScanStatus(numId, 'failed', { error_log: 'Scan cancelled by user.' });
  syslog.logEvent('SCAN_CANCELLED', { scan_id: numId }, 'warning');
  return true;
}

async function runScanPipeline(scanId) {
  const scan = db.getScanById(scanId);
  if (!scan) return;

  const profiles = loadProfiles();
  const profileKey = (scan.profile || 'standard').toLowerCase();
  const profileConfig = profiles[profileKey] || profiles.standard || Object.values(profiles)[0];

  const target = sanitizeAndValidateTarget(scan.target);

  syslog.logEvent(
    'SCAN_STARTED',
    {
      scan_id: scanId,
      asset_id: scan.asset_id,
      target,
      profile: profileConfig.id,
      ports: profileConfig.ports
    },
    'info'
  );

  // Stage 1: Nmap Discovery & Enumeration
  db.updateScanStatus(scanId, 'running_nmap');
  let nmapResult;
  try {
    nmapResult = await executeNmapStage(scanId, target, profileConfig);
  } catch (err) {
    if (cancelledScanIds.has(scanId)) return;
    db.updateScanStatus(scanId, 'failed', {
      error_log: `Stage 1 (Nmap) Error: ${err.message}`
    });
    syslog.logEvent(
      'SCAN_FAILED',
      { scan_id: scanId, target, stage: 'nmap', error: err.message },
      'error'
    );
    return;
  }

  if (cancelledScanIds.has(scanId)) return;

  const parsedNmap = await parser.parseNmapXml(nmapResult.stdout, target);

  // Inspect SSL/TLS certificates on discovered HTTPS/SSL ports
  let tlsFindings = [];
  try {
    tlsFindings = await parser.inspectTlsCertificates(target, parsedNmap.ports);
  } catch (_) {}

  db.updateAssetMetadata(scan.asset_id, {
    hostname: parsedNmap.hostname,
    mac_address: parsedNmap.mac_address,
    vendor: parsedNmap.vendor,
    last_scanned_at: new Date().toISOString().replace('T', ' ').slice(0, 19)
  });

  db.insertScanPorts(scanId, parsedNmap.ports);

  // Insert any Nmap NSE vulscan findings and TLS expiry findings right away
  const stage1Findings = [...(parsedNmap.nse_vulns || []), ...tlsFindings];
  if (stage1Findings.length > 0) {
    db.insertScanVulns(scanId, stage1Findings);
  }

  for (const p of parsedNmap.ports) {
    syslog.logEvent(
      'PORT_DISCOVERED',
      {
        scan_id: scanId,
        target,
        port: p.port,
        protocol: p.protocol,
        service_name: p.service_name,
        service_product: p.service_product,
        service_version: p.service_version,
        extra_info: p.extra_info
      },
      'info'
    );
  }

  // Stage 2: Nuclei Targeted Verification
  db.updateScanStatus(scanId, 'running_nuclei', {
    raw_nmap_xml: nmapResult.stdout
  });

  const nucleiUrls = parser.buildNucleiTargets(target, parsedNmap.ports, profileConfig);

  let nucleiRawJsonl = '';
  let nucleiWarning = null;
  if (nucleiUrls.length > 0 && !cancelledScanIds.has(scanId)) {
    try {
      const nucleiResult = await executeNucleiStage(scanId, target, nucleiUrls, profileConfig);
      nucleiRawJsonl = nucleiResult.stdout || '';
      if (nucleiResult.code !== 0 && nucleiResult.stderr) {
        nucleiWarning = `Nuclei exited with code ${nucleiResult.code}: ${nucleiResult.stderr.trim()}`;
      }
    } catch (err) {
      if (cancelledScanIds.has(scanId)) return;
      nucleiWarning = `Stage 2 (Nuclei) Warning: ${err.message}`;
    }
  }

  if (cancelledScanIds.has(scanId)) return;

  db.updateScanStatus(scanId, 'completed', {
    raw_nuclei_jsonl: nucleiRawJsonl,
    error_log: nucleiWarning
  });

  db.updateAssetMetadata(scan.asset_id, {
    last_scanned_at: new Date().toISOString().replace('T', ' ').slice(0, 19)
  });

  let diffResult = null;
  try {
    diffResult = differ.generateAndSaveDiff(scan.asset_id, scanId);
    if (diffResult && diffResult.summary && diffResult.summary.has_changes) {
      const overridesMap = db.getAssetOverridesMap(scan.asset_id);
      for (const ev of diffResult.summary.events || []) {
        // Skip alerting on NEW_VULN if the finding is already marked accepted_risk or false_positive
        if (ev.type === 'NEW_VULN') {
          const ov = overridesMap.get(`${ev.template_id}|${ev.port || 0}`);
          if (ov && (ov.status === 'accepted_risk' || ov.status === 'false_positive')) {
            continue;
          }
        }
        syslog.logEvent(
          'DRIFT_DETECTED',
          {
            scan_id: scanId,
            old_scan_id: diffResult.old_scan_id,
            target,
            drift_type: ev.type,
            details: ev
          },
          ev.type === 'NEW_VULN' ? ev.severity || 'high' : ev.type === 'NEW_PORT' ? 'warning' : 'notice'
        );
      }
    }
  } catch (diffErr) {
    console.error(`[Scanner] Failed to compute diff for scan ${scanId}:`, diffErr);
  }

  const finalScan = db.getScanById(scanId);
  syslog.logEvent(
    'SCAN_COMPLETED',
    {
      scan_id: scanId,
      target,
      profile: profileConfig.id,
      open_ports_count: (finalScan?.ports || []).length,
      vulns_count: (finalScan?.vulns || []).length,
      drift_changes: diffResult?.summary?.total_changes || 0
    },
    'info'
  );
}

function triggerScan({ target, targets, profile = 'standard', save_asset = true, tags = [], concurrency }) {
  if (concurrency !== undefined) {
    setMaxConcurrency(concurrency);
  }

  let targetList = [];
  if (Array.isArray(targets) && targets.length > 0) {
    targetList = targets;
  } else if (typeof target === 'string') {
    targetList = target
      .split(/[\s,]+/)
      .map((t) => t.trim())
      .filter(Boolean);
  }

  if (targetList.length === 0) {
    throw new Error('At least one target is required.');
  }

  const profiles = loadProfiles();
  const profileKey = (profile || 'standard').toLowerCase();
  const validProfile = profiles[profileKey] ? profileKey : 'standard';

  const jobs = [];
  for (const rawT of targetList) {
    const cleanTarget = sanitizeAndValidateTarget(rawT);
    const asset = db.upsertAsset({
      target: cleanTarget,
      tags,
      default_profile: validProfile,
      save_asset: Boolean(save_asset)
    });

    const scanId = db.createScan(asset.id, validProfile);
    enqueueScan(scanId);

    jobs.push({
      scan_id: scanId,
      asset_id: asset.id,
      target: asset.target,
      profile: validProfile,
      status: 'queued'
    });
  }

  return {
    scan_id: jobs[0].scan_id,
    asset_id: jobs[0].asset_id,
    target: jobs[0].target,
    profile: validProfile,
    status: 'queued',
    jobs,
    scan_ids: jobs.map((j) => j.scan_id)
  };
}

function triggerBulkDiffRescan({ profileOverride = null, tagFilter = null, concurrency = null } = {}) {
  if (concurrency !== null && concurrency !== undefined) {
    setMaxConcurrency(concurrency);
  }

  let assets = db.listAssets({ includeTransient: false });
  if (tagFilter) {
    const tf = tagFilter.toLowerCase().trim();
    assets = assets.filter((a) => (a.tags || []).some((t) => t.toLowerCase() === tf));
  }

  const profiles = loadProfiles();
  const queuedScans = [];

  for (const asset of assets) {
    const requestedProfile = profileOverride || asset.default_profile || 'standard';
    const profileKey = profiles[requestedProfile] ? requestedProfile : 'standard';
    const scanId = db.createScan(asset.id, profileKey);
    enqueueScan(scanId);
    queuedScans.push({
      scan_id: scanId,
      asset_id: asset.id,
      target: asset.target,
      profile: profileKey
    });
  }

  return {
    queued_count: queuedScans.length,
    scan_ids: queuedScans.map((s) => s.scan_id),
    scans: queuedScans
  };
}

function executeScheduleJob(schedule) {
  db.markScheduleExecuted(schedule.id);
  const profileOverride =
    schedule.profile && schedule.profile !== 'asset_default' ? schedule.profile : null;

  let result;
  if (schedule.target_type === 'asset' && schedule.target_value) {
    result = triggerScan({
      target: schedule.target_value,
      profile: profileOverride || 'standard',
      save_asset: true,
      concurrency: schedule.concurrency || 3
    });
  } else if (schedule.target_type === 'tag' && schedule.target_value) {
    result = triggerBulkDiffRescan({
      profileOverride,
      tagFilter: schedule.target_value,
      concurrency: schedule.concurrency || 3
    });
  } else {
    result = triggerBulkDiffRescan({
      profileOverride,
      concurrency: schedule.concurrency || 3
    });
  }

  syslog.logEvent(
    'SCHEDULE_TRIGGERED',
    {
      schedule_id: schedule.id,
      schedule_name: schedule.name,
      target_type: schedule.target_type,
      target_value: schedule.target_value,
      profile: schedule.profile,
      concurrency: schedule.concurrency,
      scan_ids: result.scan_ids || []
    },
    'info'
  );

  return result;
}

function checkDueSchedules() {
  try {
    const schedules = db.listSchedules();
    const now = Date.now();
    for (const sched of schedules) {
      if (!sched.enabled) continue;
      if (!sched.next_run_at) continue;
      const nextTime = new Date(sched.next_run_at).getTime();
      if (!Number.isNaN(nextTime) && nextTime <= now) {
        console.log(`[Scheduler] Executing due schedule #${sched.id} (${sched.name})`);
        executeScheduleJob(sched);
      }
    }
  } catch (err) {
    console.error('[Scheduler] Error checking schedules:', err.message);
  }
}

setInterval(checkDueSchedules, 30 * 1000);

const signatureUpdaterState = {
  status: 'idle',
  started_at: null,
  completed_at: null,
  logs: []
};

function appendUpdaterLog(line) {
  const timestamp = new Date().toISOString().slice(11, 19);
  signatureUpdaterState.logs.push(`[${timestamp}] ${line}`);
  if (signatureUpdaterState.logs.length > 500) {
    signatureUpdaterState.logs.shift();
  }
}

async function runSignatureUpdateJob() {
  signatureUpdaterState.status = 'running';
  signatureUpdaterState.started_at = new Date().toISOString();
  signatureUpdaterState.completed_at = null;
  signatureUpdaterState.logs = [];

  appendUpdaterLog('Starting NucMap Signature & Template Update...');

  let hasError = false;

  appendUpdaterLog('--- [1/3] Updating ProjectDiscovery Nuclei Templates ---');
  try {
    const res = await runProcess(NUCLEI_BIN, ['-update-templates', '-nc'], {
      onStdoutLine: (l) => l.trim() && appendUpdaterLog(`[nuclei] ${l}`),
      onStderrLine: (l) => l.trim() && appendUpdaterLog(`[nuclei] ${l}`)
    });
    ensureNucleiTemplateSymlinks();
    appendUpdaterLog(`Nuclei template update finished (exit code ${res.code}).`);
    if (res.code !== 0) hasError = true;
  } catch (err) {
    appendUpdaterLog(`[ERROR] Nuclei template update failed: ${err.message}`);
    hasError = true;
  }

  appendUpdaterLog('--- [2/3] Updating Nmap NSE Script Database ---');
  try {
    const res = await runProcess(NMAP_BIN, ['--script-updatedb'], {
      onStdoutLine: (l) => l.trim() && appendUpdaterLog(`[nmap] ${l}`),
      onStderrLine: (l) => l.trim() && appendUpdaterLog(`[nmap] ${l}`)
    });
    appendUpdaterLog(`Nmap script-updatedb finished (exit code ${res.code}).`);
    if (res.code !== 0) hasError = true;
  } catch (err) {
    appendUpdaterLog(`[ERROR] Nmap script-updatedb failed: ${err.message}`);
    hasError = true;
  }

  appendUpdaterLog('--- [3/3] Checking Nmap Vulscan Local CSV Databases ---');
  const vulscanUpdaterPath = '/usr/share/nmap/scripts/vulscan/utilities/updater/updateFiles.sh';
  const vulscanUpdateSh = '/usr/share/nmap/scripts/vulscan/update.sh';

  try {
    if (fs.existsSync(vulscanUpdaterPath)) {
      appendUpdaterLog(`Found ${vulscanUpdaterPath}, executing...`);
      const res = await runProcess('/bin/sh', [vulscanUpdaterPath], {
        onStdoutLine: (l) => l.trim() && appendUpdaterLog(`[vulscan] ${l}`),
        onStderrLine: (l) => l.trim() && appendUpdaterLog(`[vulscan] ${l}`),
        timeoutMs: 180 * 1000
      });
      appendUpdaterLog(`Vulscan updater finished (exit code ${res.code}).`);
    } else if (fs.existsSync(vulscanUpdateSh)) {
      appendUpdaterLog(`Found ${vulscanUpdateSh}, local CSV databases verified.`);
    } else {
      appendUpdaterLog('Vulscan optional updater script not installed, skipping.');
    }
  } catch (err) {
    appendUpdaterLog(`[WARN] Vulscan update check warning: ${err.message}`);
  }

  const finishedIso = new Date().toISOString();
  signatureUpdaterState.completed_at = finishedIso;

  if (hasError) {
    signatureUpdaterState.status = 'failed';
    appendUpdaterLog('Signature update completed with warnings/errors.');
    syslog.logEvent('SIGNATURE_UPDATE', { status: 'failed' }, 'warning');
  } else {
    signatureUpdaterState.status = 'completed';
    db.setSystemMeta('last_signature_update', finishedIso);
    appendUpdaterLog('All signatures and templates updated successfully!');
    syslog.logEvent('SIGNATURE_UPDATE', { status: 'completed', updated_at: finishedIso }, 'info');
  }
}

function triggerSignatureUpdate() {
  if (signatureUpdaterState.status === 'running') {
    return getSignatureUpdateStatus();
  }
  runSignatureUpdateJob().catch((err) => {
    signatureUpdaterState.status = 'failed';
    signatureUpdaterState.completed_at = new Date().toISOString();
    appendUpdaterLog(`Fatal error: ${err.message}`);
  });
  return getSignatureUpdateStatus();
}

function getSignatureUpdateStatus() {
  const lastMeta = db.getSystemMeta('last_signature_update');
  return {
    status: signatureUpdaterState.status,
    started_at: signatureUpdaterState.started_at,
    completed_at: signatureUpdaterState.completed_at,
    last_updated_at: lastMeta ? lastMeta.value : null,
    output_log: signatureUpdaterState.logs.join('\n'),
    logs: signatureUpdaterState.logs
  };
}

function getQueueState() {
  return {
    is_processing: activeScanIds.size > 0,
    active_scan_ids: Array.from(activeScanIds),
    queued_scan_ids: [...scanQueue],
    max_concurrency: getMaxConcurrency()
  };
}

module.exports = {
  loadProfiles,
  validateAndBuildProfile,
  sanitizeAndValidateTarget,
  discoverSubnetHosts,
  getMaxConcurrency,
  setMaxConcurrency,
  triggerScan,
  cancelScan,
  triggerBulkDiffRescan,
  executeScheduleJob,
  triggerSignatureUpdate,
  getSignatureUpdateStatus,
  getQueueState
};
