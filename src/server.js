const http = require('http');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const db = require('./db');
const scanner = require('./scanner');
const syslog = require('./syslog');

const app = express();
app.disable('x-powered-by');

// Security Headers & Same-Origin Protection
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  next();
});

// Built-in Rate Limiting for API routes (default: 240 requests / 60s per IP)
const rateBuckets = new Map();
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX_REQ = parseInt(process.env.NUCMAP_RATE_LIMIT || '240', 10) || 240;

app.use('/api', (req, res, next) => {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const now = Date.now();
  let bucket = rateBuckets.get(ip);
  if (!bucket || now - bucket.start > RATE_WINDOW_MS) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(ip, bucket);
  }
  bucket.count += 1;
  if (bucket.count > RATE_MAX_REQ) {
    return res.status(429).json({ error: 'Rate limit exceeded. Please try again shortly.' });
  }
  next();
});

// Optional HTTP Basic Auth / API Key Protection (enabled when NUCMAP_PASSWORD or NUCMAP_API_KEY is set)
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a || ''));
  const bufB = Buffer.from(String(b || ''));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

app.use((req, res, next) => {
  const requiredPass = process.env.NUCMAP_PASSWORD || '';
  const requiredKey = process.env.NUCMAP_API_KEY || '';
  if (!requiredPass && !requiredKey) return next();

  const expectedUser = process.env.NUCMAP_USER || 'admin';
  const authHeader = req.headers.authorization || '';
  const apiKeyHeader = req.headers['x-api-key'] || '';

  if (requiredKey && apiKeyHeader && safeEqual(apiKeyHeader, requiredKey)) {
    return next();
  }

  if (authHeader.startsWith('Bearer ') && requiredKey) {
    const token = authHeader.slice(7).trim();
    if (safeEqual(token, requiredKey)) return next();
  }

  if (authHeader.startsWith('Basic ') && requiredPass) {
    const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
    const sepIdx = decoded.indexOf(':');
    if (sepIdx !== -1) {
      const user = decoded.slice(0, sepIdx);
      const pass = decoded.slice(sepIdx + 1);
      if (safeEqual(user, expectedUser) && safeEqual(pass, requiredPass)) {
        return next();
      }
    }
  }

  syslog.logEvent('AUTH_FAILED', { ip: req.ip, path: req.path }, 'warning');
  res.setHeader('WWW-Authenticate', 'Basic realm="NucMap"');
  return res.status(401).json({ error: 'Authentication required.' });
});

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// GET /api/system/status - Profiles, signature timestamp, queue state, syslog config
app.get('/api/system/status', (req, res) => {
  try {
    const profiles = scanner.loadProfiles();
    const sigStatus = scanner.getSignatureUpdateStatus();
    const queue = scanner.getQueueState();
    const syslogConfig = syslog.getSyslogConfig();
    res.json({
      ok: true,
      name: 'NucMap',
      version: '0.1.1',
      auth_enabled: Boolean(process.env.NUCMAP_PASSWORD || process.env.NUCMAP_API_KEY),
      db_file: path.basename(db.dbPath),
      profiles,
      signatures: sigStatus,
      queue,
      syslog: syslogConfig
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/system/concurrency - Configure synchronous scanning concurrency (1 to 5 hosts)
app.post('/api/system/concurrency', (req, res) => {
  try {
    const { max_concurrency } = req.body || {};
    const updated = scanner.setMaxConcurrency(max_concurrency);
    res.json({ ok: true, max_concurrency: updated, queue: scanner.getQueueState() });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ==================== SUBNET HOST DISCOVERY API ====================

app.post('/api/discover', async (req, res) => {
  try {
    const { cidr } = req.body || {};
    if (!cidr) return res.status(400).json({ error: 'Subnet CIDR or IP range is required (e.g. 192.168.1.0/24).' });
    const hosts = await scanner.discoverSubnetHosts(cidr);
    syslog.logEvent('SUBNET_DISCOVERY', { cidr, discovered_count: hosts.length }, 'info');
    res.json({ cidr, discovered_count: hosts.length, hosts });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/assets/bulk', (req, res) => {
  try {
    const { hosts = [], tags = ['LAN'], default_profile = 'standard', scan_now = false } = req.body || {};
    if (!Array.isArray(hosts) || hosts.length === 0) {
      return res.status(400).json({ error: 'No hosts provided for import.' });
    }

    const parsedTags = Array.isArray(tags)
      ? tags
      : typeof tags === 'string' && tags.trim()
      ? tags.split(',').map((t) => t.trim()).filter(Boolean)
      : ['LAN'];

    const imported = [];
    const scanTargets = [];

    for (const h of hosts) {
      const cleanTarget = scanner.sanitizeAndValidateTarget(h.target || h);
      const asset = db.upsertAsset({
        target: cleanTarget,
        hostname: h.hostname || null,
        mac_address: h.mac_address || null,
        vendor: h.vendor || null,
        tags: parsedTags,
        default_profile,
        save_asset: true
      });
      imported.push(asset);
      scanTargets.push(cleanTarget);
    }

    let scanResult = null;
    if (scan_now && scanTargets.length > 0) {
      scanResult = scanner.triggerScan({
        targets: scanTargets,
        profile: default_profile,
        save_asset: true,
        tags: parsedTags
      });
    }

    res.status(201).json({
      imported_count: imported.length,
      assets: imported,
      scan_result: scanResult
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ==================== FINDING TRIAGE API ====================

app.post('/api/vulns/triage', (req, res) => {
  try {
    const { asset_id, template_id, port = 0, status = 'open', notes = '' } = req.body || {};
    if (!asset_id || !template_id) {
      return res.status(400).json({ error: 'asset_id and template_id are required.' });
    }
    const allowed = new Set(['open', 'accepted_risk', 'false_positive']);
    const cleanStatus = allowed.has(status) ? status : 'open';
    const override = db.setVulnOverride({
      asset_id: Number(asset_id),
      template_id: String(template_id),
      port: Number(port) || 0,
      status: cleanStatus,
      notes: String(notes || '')
    });
    syslog.logEvent('VULN_TRIAGED', { asset_id, template_id, port, status: cleanStatus }, 'info');
    res.json({ ok: true, override });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ==================== EXPORT & DB BACKUP API ====================

function csvEscape(val) {
  if (val === null || val === undefined) return '""';
  const s = String(val).replace(/"/g, '""');
  return `"${s}"`;
}

app.get('/api/export/assets.csv', (req, res) => {
  try {
    const assets = db.listAssets({ includeTransient: false });
    const header = [
      'ID',
      'Target',
      'Hostname',
      'MAC Address',
      'Vendor',
      'Tags',
      'Default Profile',
      'Open Port Count',
      'Open Ports',
      'Critical Vulns',
      'High Vulns',
      'Medium Vulns',
      'Low Vulns',
      'Suppressed Vulns',
      'Last Scanned At'
    ].join(',');

    const rows = assets.map((a) => {
      const portsStr = (a.open_ports || [])
        .map((p) => `${p.port}/${p.protocol}(${p.service_name || ''})`)
        .join('; ');
      const vc = a.vuln_counts || {};
      return [
        a.id,
        csvEscape(a.target),
        csvEscape(a.hostname || ''),
        csvEscape(a.mac_address || ''),
        csvEscape(a.vendor || ''),
        csvEscape((a.tags || []).join(', ')),
        csvEscape(a.default_profile),
        a.open_port_count || 0,
        csvEscape(portsStr),
        vc.critical || 0,
        vc.high || 0,
        vc.medium || 0,
        vc.low || 0,
        vc.suppressed || 0,
        csvEscape(a.last_scanned_at || '')
      ].join(',');
    });

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="nucmap-assets.csv"');
    res.send([header, ...rows].join('\n'));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/export/report.json', (req, res) => {
  try {
    const assets = db.listAssets({ includeTransient: false });
    const diffs = db.getAllDiffs(100);
    const profiles = db.listProfiles();
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="nucmap-report.json"');
    res.send(
      JSON.stringify(
        {
          app: 'NucMap',
          version: '0.1.1',
          exported_at: new Date().toISOString(),
          assets,
          recent_diffs: diffs,
          profiles
        },
        null,
        2
      )
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/export/nucmap.db', (req, res) => {
  try {
    res.download(db.dbPath, 'nucmap.db');
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== SCAN PROFILES API ====================

app.get('/api/profiles', (req, res) => {
  try {
    res.json(db.listProfiles());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/profiles', (req, res) => {
  try {
    const built = scanner.validateAndBuildProfile({
      ...req.body,
      is_builtin: false
    });
    const saved = db.upsertProfile(built);
    syslog.logEvent('PROFILE_SAVED', { profile_id: saved.id, ports: saved.ports }, 'info');
    res.status(201).json(saved);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/profiles/:id', (req, res) => {
  try {
    const existing = db.getProfileById(req.params.id);
    if (!existing) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    const built = scanner.validateAndBuildProfile({
      ...existing,
      ...req.body,
      id: existing.id,
      is_builtin: existing.is_builtin
    });
    const saved = db.upsertProfile(built);
    syslog.logEvent('PROFILE_UPDATED', { profile_id: saved.id, ports: saved.ports }, 'info');
    res.json(saved);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/profiles/:id', (req, res) => {
  try {
    const existing = db.getProfileById(req.params.id);
    if (!existing) {
      return res.status(404).json({ error: 'Profile not found' });
    }
    if (existing.is_builtin) {
      return res.status(400).json({ error: 'Built-in profiles cannot be deleted (you can edit their ports/settings instead).' });
    }
    db.deleteProfile(req.params.id);
    res.json({ ok: true, deleted_id: req.params.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== SCHEDULED RUNS API ====================

app.get('/api/schedules', (req, res) => {
  try {
    res.json(db.listSchedules());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/schedules', (req, res) => {
  try {
    const {
      name,
      target_type = 'all',
      target_value = '',
      profile = 'standard',
      schedule_type = 'daily',
      interval_minutes = 1440,
      concurrency = 3,
      enabled = true
    } = req.body || {};

    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: 'Schedule name is required.' });
    }

    const sched = db.createSchedule({
      name: String(name).trim(),
      target_type,
      target_value: String(target_value || '').trim(),
      profile,
      schedule_type,
      interval_minutes: Number(interval_minutes) || 1440,
      concurrency: Math.min(5, Math.max(1, Number(concurrency) || 3)),
      enabled: Boolean(enabled)
    });

    syslog.logEvent('SCHEDULE_CREATED', { schedule_id: sched.id, name: sched.name, interval_minutes: sched.interval_minutes }, 'info');
    res.status(201).json(sched);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/schedules/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: 'Invalid schedule ID' });
    const updated = db.updateSchedule(id, req.body || {});
    if (!updated) return res.status(404).json({ error: 'Schedule not found' });
    res.json(updated);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/schedules/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: 'Invalid schedule ID' });
    const ok = db.deleteSchedule(id);
    if (!ok) return res.status(404).json({ error: 'Schedule not found' });
    res.json({ ok: true, deleted_id: id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/schedules/:id/run', (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const sched = db.getScheduleById(id);
    if (!sched) return res.status(404).json({ error: 'Schedule not found' });
    const result = scanner.executeScheduleJob(sched);
    res.status(202).json({ ok: true, schedule: db.getScheduleById(id), result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== SYSLOG JSON LOGGING & ALERTS API ====================

app.get('/api/system/syslog', (req, res) => {
  try {
    res.json({
      config: syslog.getSyslogConfig(),
      recent_events: syslog.getRecentSyslogEvents(60)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/system/syslog', (req, res) => {
  try {
    const updated = syslog.saveSyslogConfig(req.body || {});
    syslog.logEvent('SYSLOG_CONFIG_UPDATED', { remote_enabled: updated.remote_enabled, local_syslog: updated.local_syslog }, 'info');
    res.json({ ok: true, config: updated });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/system/syslog/test', (req, res) => {
  try {
    const ev = syslog.logEvent(
      'SYSLOG_TEST',
      {
        message: 'NucMap JSON Syslog & Alert test message verified successfully',
        triggered_by: 'manual_test'
      },
      'info'
    );
    res.json({ ok: true, event: ev, recent_events: syslog.getRecentSyslogEvents(60) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== ASSETS & SCANS API ====================

app.get('/api/assets', (req, res) => {
  try {
    const includeTransient = req.query.include_transient === 'true';
    const assets = db.listAssets({ includeTransient });
    res.json(assets);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/assets', (req, res) => {
  try {
    const { target, hostname, tags, default_profile } = req.body || {};
    const cleanTarget = scanner.sanitizeAndValidateTarget(target);
    const profiles = scanner.loadProfiles();
    const profileKey = (default_profile || 'standard').toLowerCase();
    const validProfile = profiles[profileKey] ? profileKey : 'standard';

    const parsedTags = Array.isArray(tags)
      ? tags
      : typeof tags === 'string' && tags.trim()
      ? tags.split(',').map((t) => t.trim()).filter(Boolean)
      : [];

    const asset = db.upsertAsset({
      target: cleanTarget,
      hostname: hostname ? String(hostname).trim() : null,
      tags: parsedTags,
      default_profile: validProfile,
      save_asset: true
    });

    res.status(201).json(asset);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/assets/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: 'Invalid asset ID' });
    }
    const { tags, default_profile, hostname } = req.body || {};
    const parsedTags = Array.isArray(tags)
      ? tags
      : typeof tags === 'string'
      ? tags.split(',').map((t) => t.trim()).filter(Boolean)
      : undefined;

    const updated = db.updateAssetConfig(id, {
      tags: parsedTags,
      default_profile,
      hostname
    });
    if (!updated) {
      return res.status(404).json({ error: 'Asset not found' });
    }
    res.json(updated);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/assets/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: 'Invalid asset ID' });
    }
    const deleted = db.deleteAsset(id);
    if (!deleted) {
      return res.status(404).json({ error: 'Asset not found' });
    }
    res.json({ ok: true, deleted_id: id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/scan', (req, res) => {
  try {
    const { target, targets, profile = 'standard', save_asset = true, tags = [], concurrency } = req.body || {};
    const parsedTags = Array.isArray(tags)
      ? tags
      : typeof tags === 'string' && tags.trim()
      ? tags.split(',').map((t) => t.trim()).filter(Boolean)
      : [];

    const scanJob = scanner.triggerScan({
      target,
      targets,
      profile,
      save_asset: Boolean(save_asset),
      tags: parsedTags,
      concurrency
    });

    res.status(202).json(scanJob);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/scan/:id/cancel', (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: 'Invalid scan ID' });
    scanner.cancelScan(id);
    res.json({ ok: true, cancelled_id: id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/scan/bulk-diff', (req, res) => {
  try {
    const { profile, tag, concurrency } = req.body || {};
    const result = scanner.triggerBulkDiffRescan({
      profileOverride: profile || null,
      tagFilter: tag || null,
      concurrency: concurrency !== undefined ? concurrency : null
    });
    res.status(202).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/scans', (req, res) => {
  try {
    const limit = parseInt(req.query.limit || '30', 10);
    const scans = db.listRecentScans(Number.isNaN(limit) ? 30 : limit);
    res.json({
      scans,
      queue: scanner.getQueueState()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/scan/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: 'Invalid scan ID' });
    }
    const scan = db.getScanById(id);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    res.json(scan);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/assets/:id/scans', (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: 'Invalid asset ID' });
    }
    const scans = db.listAssetScans(id);
    res.json(scans);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/assets/:id/diffs', (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: 'Invalid asset ID' });
    }
    const diffs = db.getAssetDiffs(id);
    res.json(diffs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/diffs', (req, res) => {
  try {
    const limit = parseInt(req.query.limit || '100', 10);
    const diffs = db.getAllDiffs(Number.isNaN(limit) ? 100 : limit);
    res.json(diffs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/system/update-signatures', (req, res) => {
  try {
    const state = scanner.triggerSignatureUpdate();
    res.status(202).json(state);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/system/update-signatures', (req, res) => {
  try {
    const state = scanner.getSignatureUpdateStatus();
    res.json(state);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';

const primaryServer = http.createServer(app);
primaryServer.listen(PORT, HOST, () => {
  console.log(`[NucMap v0.1.1] Server listening on http://${HOST}:${PORT}`);
  console.log(`[NucMap v0.1.1] SQLite Database: ${db.dbPath}`);
});

if (PORT !== 80 && typeof process.getuid === 'function' && process.getuid() === 0 && process.env.DISABLE_PORT_80 !== 'true') {
  const port80Server = http.createServer(app);
  port80Server.on('error', (err) => {
    console.log(`[NucMap] Port 80 binding skipped (${err.code || err.message}), primary port ${PORT} is active.`);
  });
  port80Server.listen(80, HOST, () => {
    console.log(`[NucMap] Also listening on http://${HOST}:80`);
  });
}
