const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

function resolveDbPath() {
  let targetPath;
  if (process.env.DB_PATH) {
    const dir = path.dirname(process.env.DB_PATH);
    fs.mkdirSync(dir, { recursive: true });
    targetPath = process.env.DB_PATH;
  } else {
    const defaultDir = '/var/lib/nucmap';
    try {
      fs.mkdirSync(defaultDir, { recursive: true });
      fs.accessSync(defaultDir, fs.constants.W_OK);
      targetPath = path.join(defaultDir, 'nucmap.db');
    } catch (err) {
      const fallbackDir = path.join(__dirname, '..', 'data');
      fs.mkdirSync(fallbackDir, { recursive: true });
      targetPath = path.join(fallbackDir, 'nucmap.db');
    }
  }

  // Auto-recovery / migration from legacy paths if target DB has no data
  try {
    let targetHasData = false;
    if (fs.existsSync(targetPath) && fs.statSync(targetPath).size > 2048) {
      try {
        const testDb = new Database(targetPath, { readonly: true });
        const tbl = testDb.prepare("SELECT count(*) as c FROM sqlite_master WHERE type='table' AND name='assets'").get();
        if (tbl && tbl.c > 0) {
          const row = testDb.prepare("SELECT count(*) as c FROM assets").get();
          if (row && row.c > 0) targetHasData = true;
        }
        testDb.close();
      } catch (_) {}
    }

    if (!targetHasData) {
      const legacyCandidates = [
        path.join(__dirname, '..', 'data', 'nucmap.db'),
        '/opt/nucmap/data/nucmap.db',
        '/var/lib/sechost/sechost.db',
        '/opt/sechost-manager/data/sechost.db',
        '/data/nucmap.db'
      ];
      for (const legacy of legacyCandidates) {
        if (legacy !== targetPath && fs.existsSync(legacy) && fs.statSync(legacy).size > 2048) {
          try {
            const legDb = new Database(legacy, { readonly: true });
            const lTbl = legDb.prepare("SELECT count(*) as c FROM sqlite_master WHERE type='table' AND name='assets'").get();
            let lHasAssets = false;
            if (lTbl && lTbl.c > 0) {
              const lRow = legDb.prepare("SELECT count(*) as c FROM assets").get();
              if (lRow && lRow.c > 0) lHasAssets = true;
            }
            legDb.close();
            if (lHasAssets) {
              console.log(`[DB] Auto-migrating populated database from legacy path: ${legacy} -> ${targetPath}`);
              fs.copyFileSync(legacy, targetPath);
              break;
            }
          } catch (_) {}
        }
      }
    }
  } catch (err) {
    console.warn('[DB] Legacy migration check notice:', err.message);
  }

  return targetPath;
}

const dbPath = resolveDbPath();
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function safeParseJson(str, fallback) {
  if (!str) return fallback;
  try {
    return JSON.parse(str);
  } catch (_) {
    return fallback;
  }
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT UNIQUE NOT NULL,       -- IP or FQDN
        hostname TEXT,
        mac_address TEXT,
        vendor TEXT,
        tags TEXT,                         -- JSON array of strings
        default_profile TEXT DEFAULT 'standard',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_scanned_at DATETIME
    );

    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL,
        profile TEXT NOT NULL,
        status TEXT NOT NULL,              -- 'queued', 'running_nmap', 'running_nuclei', 'completed', 'failed'
        started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME,
        raw_nmap_xml TEXT,
        raw_nuclei_jsonl TEXT,
        error_log TEXT,
        FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scan_ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL,            -- 'tcp' or 'udp'
        state TEXT NOT NULL,               -- 'open'
        service_name TEXT,                 -- e.g., 'http'
        service_product TEXT,              -- e.g., 'nginx'
        service_version TEXT,              -- e.g., '1.24.0'
        extra_info TEXT,
        cpe TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scan_vulns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        port INTEGER,
        template_id TEXT NOT NULL,         -- e.g., 'CVE-2026-109618' or 'synology-dsm-panel'
        name TEXT NOT NULL,
        severity TEXT NOT NULL,            -- 'info', 'low', 'medium', 'high', 'critical'
        cve_id TEXT,
        matched_at TEXT,                   -- URL or host:port
        extracted_results TEXT,            -- JSON array
        description TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS vuln_overrides (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL,
        template_id TEXT NOT NULL,
        port INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'open', -- 'open', 'accepted_risk', 'false_positive'
        notes TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(asset_id, template_id, port),
        FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scan_diffs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL,
        old_scan_id INTEGER NOT NULL,
        new_scan_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        diff_summary_json TEXT NOT NULL,   -- Structured JSON of added/removed ports & vulns
        FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS system_meta (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS scan_profiles (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        ports TEXT NOT NULL,               -- e.g. '80,443', '1-10000', 'top-100', 'top-1000', '1-65535'
        nmap_extra_args TEXT,
        nmap_args_json TEXT NOT NULL,
        nuclei_tags TEXT,
        nuclei_severities TEXT,
        nuclei_extra_args TEXT,
        nuclei_args_json TEXT NOT NULL,
        include_non_http_nuclei INTEGER DEFAULT 0,
        enable_vulscan INTEGER DEFAULT 0,
        is_builtin INTEGER DEFAULT 0,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        target_type TEXT NOT NULL DEFAULT 'all', -- 'all', 'tag', 'asset'
        target_value TEXT,                       -- tag string or asset target/id
        profile TEXT NOT NULL DEFAULT 'standard',
        schedule_type TEXT NOT NULL DEFAULT 'daily',
        interval_minutes INTEGER NOT NULL DEFAULT 1440,
        concurrency INTEGER NOT NULL DEFAULT 3,
        enabled INTEGER NOT NULL DEFAULT 1,
        last_run_at DATETIME,
        next_run_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_scans_asset_id ON scans(asset_id);
    CREATE INDEX IF NOT EXISTS idx_scan_ports_scan_id ON scan_ports(scan_id);
    CREATE INDEX IF NOT EXISTS idx_scan_vulns_scan_id ON scan_vulns(scan_id);
    CREATE INDEX IF NOT EXISTS idx_scan_diffs_asset_id ON scan_diffs(asset_id);
  `);

  // Add enable_vulscan column if migrating from earlier schema
  try {
    db.exec('ALTER TABLE scan_profiles ADD COLUMN enable_vulscan INTEGER DEFAULT 0');
  } catch (_) {}

  db.prepare(`
    UPDATE scans
    SET status = 'failed',
        completed_at = CURRENT_TIMESTAMP,
        error_log = COALESCE(error_log || '\n', '') || 'Scan interrupted by service restart'
    WHERE status IN ('queued', 'running_nmap', 'running_nuclei')
  `).run();

  // Clean up legacy _transient tags so all existing scanned assets appear in Monitored Assets
  try {
    const allRows = db.prepare('SELECT id, tags FROM assets').all();
    for (const r of allRows) {
      const t = safeParseJson(r.tags, []);
      if (t.includes('_transient') || t.length === 0) {
        const cleaned = t.filter((x) => x !== '_transient');
        const finalTags = cleaned.length > 0 ? cleaned : ['LAN'];
        db.prepare('UPDATE assets SET tags = ? WHERE id = ?').run(JSON.stringify(finalTags), r.id);
      }
    }
    db.prepare("UPDATE assets SET tags = '[\"LAN\"]' WHERE tags IS NULL OR tags = '' OR tags = '[]' OR tags LIKE '%_transient%'").run();
  } catch (_) {}

  seedDefaultProfiles();
}

function seedDefaultProfiles() {
  const profilesPath = path.join(__dirname, '..', 'config', 'profiles.json');
  if (!fs.existsSync(profilesPath)) return;

  try {
    const defaults = JSON.parse(fs.readFileSync(profilesPath, 'utf8'));
    const upsertStmt = db.prepare(`
      INSERT INTO scan_profiles (
        id, name, description, ports, nmap_extra_args, nmap_args_json,
        nuclei_tags, nuclei_severities, nuclei_extra_args, nuclei_args_json,
        include_non_http_nuclei, enable_vulscan, is_builtin, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        ports = excluded.ports,
        nmap_extra_args = excluded.nmap_extra_args,
        nmap_args_json = excluded.nmap_args_json,
        nuclei_tags = excluded.nuclei_tags,
        nuclei_severities = excluded.nuclei_severities,
        nuclei_extra_args = excluded.nuclei_extra_args,
        nuclei_args_json = excluded.nuclei_args_json,
        include_non_http_nuclei = excluded.include_non_http_nuclei,
        is_builtin = excluded.is_builtin,
        updated_at = CURRENT_TIMESTAMP
      WHERE scan_profiles.is_builtin = 1
    `);

    for (const [id, p] of Object.entries(defaults)) {
      upsertStmt.run(
        id,
        p.name || id,
        p.description || '',
        p.ports || '1-10000',
        p.nmap_extra_args || '-sV -T4',
        JSON.stringify(p.nmap_args || []),
        p.nuclei_tags || '',
        p.nuclei_severities || 'low,medium,high,critical',
        p.nuclei_extra_args || '',
        JSON.stringify(p.nuclei_args || []),
        p.include_non_http_nuclei ? 1 : 0,
        p.enable_vulscan ? 1 : 0,
        p.is_builtin ? 1 : 0
      );
    }
  } catch (err) {
    console.error('[DB] Failed to seed default profiles:', err.message);
  }
}

initSchema();

// Scan Profile Queries
function getAllProfilesMap() {
  const rows = db.prepare('SELECT * FROM scan_profiles ORDER BY is_builtin DESC, name ASC').all();
  const map = {};
  for (const r of rows) {
    map[r.id] = {
      id: r.id,
      name: r.name,
      description: r.description,
      ports: r.ports,
      nmap_extra_args: r.nmap_extra_args,
      nmap_args: safeParseJson(r.nmap_args_json, []),
      nuclei_tags: r.nuclei_tags,
      nuclei_severities: r.nuclei_severities,
      nuclei_extra_args: r.nuclei_extra_args,
      nuclei_args: safeParseJson(r.nuclei_args_json, []),
      include_non_http_nuclei: Boolean(r.include_non_http_nuclei),
      enable_vulscan: Boolean(r.enable_vulscan),
      is_builtin: Boolean(r.is_builtin),
      updated_at: r.updated_at
    };
  }
  return map;
}

function listProfiles() {
  return Object.values(getAllProfilesMap());
}

function getProfileById(id) {
  const map = getAllProfilesMap();
  return map[id] || null;
}

function upsertProfile(profile) {
  db.prepare(`
    INSERT INTO scan_profiles (
      id, name, description, ports, nmap_extra_args, nmap_args_json,
      nuclei_tags, nuclei_severities, nuclei_extra_args, nuclei_args_json,
      include_non_http_nuclei, enable_vulscan, is_builtin, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name,
      description = excluded.description,
      ports = excluded.ports,
      nmap_extra_args = excluded.nmap_extra_args,
      nmap_args_json = excluded.nmap_args_json,
      nuclei_tags = excluded.nuclei_tags,
      nuclei_severities = excluded.nuclei_severities,
      nuclei_extra_args = excluded.nuclei_extra_args,
      nuclei_args_json = excluded.nuclei_args_json,
      include_non_http_nuclei = excluded.include_non_http_nuclei,
      enable_vulscan = excluded.enable_vulscan,
      updated_at = CURRENT_TIMESTAMP
  `).run(
    profile.id,
    profile.name,
    profile.description || '',
    profile.ports,
    profile.nmap_extra_args || '',
    JSON.stringify(profile.nmap_args || []),
    profile.nuclei_tags || '',
    profile.nuclei_severities || 'low,medium,high,critical',
    profile.nuclei_extra_args || '',
    JSON.stringify(profile.nuclei_args || []),
    profile.include_non_http_nuclei ? 1 : 0,
    profile.enable_vulscan ? 1 : 0,
    profile.is_builtin ? 1 : 0
  );
  return getProfileById(profile.id);
}

function deleteProfile(id) {
  const existing = getProfileById(id);
  if (!existing) return false;
  const res = db.prepare('DELETE FROM scan_profiles WHERE id = ?').run(id);
  return res.changes > 0;
}

// Finding Triage / Overrides Queries
function setVulnOverride({ asset_id, template_id, port = 0, status = 'open', notes = '' }) {
  const normPort = port ? Number(port) : 0;
  if (status === 'open') {
    db.prepare('DELETE FROM vuln_overrides WHERE asset_id = ? AND template_id = ? AND port = ?').run(
      asset_id,
      template_id,
      normPort
    );
    return { asset_id, template_id, port: normPort, status: 'open', notes: '' };
  }
  db.prepare(`
    INSERT INTO vuln_overrides (asset_id, template_id, port, status, notes, updated_at)
    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(asset_id, template_id, port) DO UPDATE SET
      status = excluded.status,
      notes = excluded.notes,
      updated_at = CURRENT_TIMESTAMP
  `).run(asset_id, template_id, normPort, status, notes || '');

  return db
    .prepare('SELECT * FROM vuln_overrides WHERE asset_id = ? AND template_id = ? AND port = ?')
    .get(asset_id, template_id, normPort);
}

function getAssetOverridesMap(assetId) {
  const rows = db.prepare('SELECT * FROM vuln_overrides WHERE asset_id = ?').all(assetId);
  const map = new Map();
  for (const r of rows) {
    map.set(`${r.template_id}|${r.port || 0}`, r);
  }
  return map;
}

// Schedule Queries
function listSchedules() {
  const rows = db.prepare('SELECT * FROM schedules ORDER BY id DESC').all();
  return rows.map((r) => ({
    ...r,
    enabled: Boolean(r.enabled)
  }));
}

function getScheduleById(id) {
  const row = db.prepare('SELECT * FROM schedules WHERE id = ?').get(id);
  if (!row) return null;
  return { ...row, enabled: Boolean(row.enabled) };
}

function computeNextRunIso(intervalMinutes, fromDate = new Date()) {
  const ms = Math.max(1, Number(intervalMinutes) || 60) * 60 * 1000;
  return new Date(fromDate.getTime() + ms).toISOString();
}

function createSchedule({
  name,
  target_type = 'all',
  target_value = '',
  profile = 'standard',
  schedule_type = 'daily',
  interval_minutes = 1440,
  concurrency = 3,
  enabled = true
}) {
  const nextRun = computeNextRunIso(interval_minutes);
  const info = db.prepare(`
    INSERT INTO schedules (
      name, target_type, target_value, profile, schedule_type,
      interval_minutes, concurrency, enabled, next_run_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    name,
    target_type,
    target_value || '',
    profile || 'standard',
    schedule_type || 'daily',
    Number(interval_minutes) || 1440,
    Math.min(5, Math.max(1, Number(concurrency) || 3)),
    enabled ? 1 : 0,
    nextRun
  );
  return getScheduleById(info.lastInsertRowid);
}

function updateSchedule(id, fields) {
  const existing = getScheduleById(id);
  if (!existing) return null;

  const name = fields.name !== undefined ? fields.name : existing.name;
  const target_type = fields.target_type !== undefined ? fields.target_type : existing.target_type;
  const target_value = fields.target_value !== undefined ? fields.target_value : existing.target_value;
  const profile = fields.profile !== undefined ? fields.profile : existing.profile;
  const schedule_type = fields.schedule_type !== undefined ? fields.schedule_type : existing.schedule_type;
  const interval_minutes =
    fields.interval_minutes !== undefined ? Number(fields.interval_minutes) : existing.interval_minutes;
  const concurrency =
    fields.concurrency !== undefined
      ? Math.min(5, Math.max(1, Number(fields.concurrency)))
      : existing.concurrency;
  const enabled = fields.enabled !== undefined ? (fields.enabled ? 1 : 0) : existing.enabled ? 1 : 0;
  const next_run_at =
    fields.next_run_at !== undefined
      ? fields.next_run_at
      : fields.interval_minutes !== undefined
      ? computeNextRunIso(interval_minutes)
      : existing.next_run_at;

  db.prepare(`
    UPDATE schedules
    SET name = ?, target_type = ?, target_value = ?, profile = ?,
        schedule_type = ?, interval_minutes = ?, concurrency = ?,
        enabled = ?, next_run_at = ?
    WHERE id = ?
  `).run(
    name,
    target_type,
    target_value,
    profile,
    schedule_type,
    interval_minutes,
    concurrency,
    enabled,
    next_run_at,
    id
  );
  return getScheduleById(id);
}

function markScheduleExecuted(id) {
  const existing = getScheduleById(id);
  if (!existing) return null;
  const nowIso = new Date().toISOString();
  const nextIso = computeNextRunIso(existing.interval_minutes, new Date());
  db.prepare(`
    UPDATE schedules
    SET last_run_at = ?, next_run_at = ?
    WHERE id = ?
  `).run(nowIso, nextIso, id);
  return getScheduleById(id);
}

function deleteSchedule(id) {
  const res = db.prepare('DELETE FROM schedules WHERE id = ?').run(id);
  return res.changes > 0;
}

// Asset Queries
function getAssetById(id) {
  const row = db.prepare('SELECT * FROM assets WHERE id = ?').get(id);
  if (!row) return null;
  const tags = safeParseJson(row.tags, []);
  return {
    ...row,
    tags: tags.filter((t) => t !== '_transient'),
    is_transient: tags.includes('_transient')
  };
}

function getAssetByTarget(target) {
  const row = db.prepare('SELECT * FROM assets WHERE target = ?').get(target);
  if (!row) return null;
  const tags = safeParseJson(row.tags, []);
  return {
    ...row,
    tags: tags.filter((t) => t !== '_transient'),
    is_transient: tags.includes('_transient')
  };
}

function upsertAsset({ target, hostname, mac_address, vendor, tags = [], default_profile = 'standard', save_asset = true }) {
  const existing = db.prepare('SELECT * FROM assets WHERE target = ?').get(target);
  const cleanTags = Array.isArray(tags)
    ? tags.map((t) => String(t).trim()).filter((t) => t && t !== '_transient')
    : [];

  if (existing) {
    const existingTags = safeParseJson(existing.tags, []).filter((t) => t !== '_transient');
    const finalTags = cleanTags.length > 0 ? cleanTags : (existingTags.length > 0 ? existingTags : ['LAN']);
    const newProfile = default_profile || existing.default_profile || 'standard';

    db.prepare(`
      UPDATE assets
      SET tags = ?,
          default_profile = ?,
          hostname = COALESCE(?, hostname),
          mac_address = COALESCE(?, mac_address),
          vendor = COALESCE(?, vendor)
      WHERE id = ?
    `).run(
      JSON.stringify(finalTags),
      newProfile,
      hostname || null,
      mac_address || null,
      vendor || null,
      existing.id
    );

    return getAssetById(existing.id);
  } else {
    const storedTags = cleanTags.length > 0 ? cleanTags : ['LAN'];
    const info = db.prepare(`
      INSERT INTO assets (target, hostname, mac_address, vendor, tags, default_profile)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      target,
      hostname || null,
      mac_address || null,
      vendor || null,
      JSON.stringify(storedTags),
      default_profile || 'standard'
    );
    return getAssetById(info.lastInsertRowid);
  }
}

function updateAssetMetadata(assetId, { hostname, mac_address, vendor, last_scanned_at }) {
  const existing = db.prepare('SELECT * FROM assets WHERE id = ?').get(assetId);
  if (!existing) return;
  db.prepare(`
    UPDATE assets
    SET hostname = COALESCE(?, hostname),
        mac_address = COALESCE(?, mac_address),
        vendor = COALESCE(?, vendor),
        last_scanned_at = COALESCE(?, last_scanned_at)
    WHERE id = ?
  `).run(
    hostname || null,
    mac_address || null,
    vendor || null,
    last_scanned_at || null,
    assetId
  );
}

function updateAssetConfig(assetId, { tags, default_profile, hostname }) {
  const existing = db.prepare('SELECT * FROM assets WHERE id = ?').get(assetId);
  if (!existing) return null;

  const cleanTags = Array.isArray(tags)
    ? tags.map((t) => String(t).trim()).filter((t) => t && t !== '_transient')
    : safeParseJson(existing.tags, []).filter((t) => t !== '_transient');

  db.prepare(`
    UPDATE assets
    SET tags = ?,
        default_profile = COALESCE(?, default_profile),
        hostname = COALESCE(?, hostname)
    WHERE id = ?
  `).run(
    JSON.stringify(cleanTags.length > 0 ? cleanTags : ['LAN']),
    default_profile || null,
    hostname !== undefined ? hostname : null,
    assetId
  );
  return getAssetById(assetId);
}

function deleteAsset(assetId) {
  const res = db.prepare('DELETE FROM assets WHERE id = ?').run(assetId);
  return res.changes > 0;
}

function listAssets({ includeTransient = true } = {}) {
  const rows = db.prepare('SELECT * FROM assets ORDER BY created_at DESC').all();
  const result = [];

  for (const row of rows) {
    const rawTags = safeParseJson(row.tags, []);
    const isTransient = rawTags.includes('_transient');
    if (isTransient && !includeTransient) continue;

    const latestCompletedScan = db.prepare(`
      SELECT id, profile, status, started_at, completed_at
      FROM scans
      WHERE asset_id = ? AND status = 'completed'
      ORDER BY id DESC
      LIMIT 1
    `).get(row.id);

    const latestScan = db.prepare(`
      SELECT id, profile, status, started_at, completed_at
      FROM scans
      WHERE asset_id = ?
      ORDER BY id DESC
      LIMIT 1
    `).get(row.id);

    let openPorts = [];
    const vulnCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0, suppressed: 0 };

    if (latestCompletedScan) {
      openPorts = db.prepare(`
        SELECT port, protocol, state, service_name, service_product, service_version, extra_info
        FROM scan_ports
        WHERE scan_id = ? AND state = 'open'
        ORDER BY port ASC
      `).all(latestCompletedScan.id);

      const overridesMap = getAssetOverridesMap(row.id);
      const vulnRows = db.prepare(`
        SELECT template_id, port, LOWER(severity) AS sev
        FROM scan_vulns
        WHERE scan_id = ?
      `).all(latestCompletedScan.id);

      for (const v of vulnRows) {
        const ov = overridesMap.get(`${v.template_id}|${v.port || 0}`);
        if (ov && (ov.status === 'accepted_risk' || ov.status === 'false_positive')) {
          vulnCounts.suppressed += 1;
          continue;
        }
        if (vulnCounts[v.sev] !== undefined) {
          vulnCounts[v.sev] += 1;
        }
        vulnCounts.total += 1;
      }
    }

    result.push({
      id: row.id,
      target: row.target,
      hostname: row.hostname,
      mac_address: row.mac_address,
      vendor: row.vendor,
      tags: rawTags.filter((t) => t !== '_transient'),
      is_transient: isTransient,
      default_profile: row.default_profile || 'standard',
      created_at: row.created_at,
      last_scanned_at: row.last_scanned_at,
      latest_scan: latestScan || null,
      latest_completed_scan_id: latestCompletedScan ? latestCompletedScan.id : null,
      open_port_count: openPorts.length,
      open_ports: openPorts,
      vuln_counts: vulnCounts
    });
  }

  return result;
}

// Scan Queries
function createScan(assetId, profile) {
  const info = db.prepare(`
    INSERT INTO scans (asset_id, profile, status, started_at)
    VALUES (?, ?, 'queued', CURRENT_TIMESTAMP)
  `).run(assetId, profile);
  return Number(info.lastInsertRowid);
}

function updateScanStatus(scanId, status, extra = {}) {
  const fields = ['status = ?'];
  const params = [status];

  if (extra.raw_nmap_xml !== undefined) {
    fields.push('raw_nmap_xml = ?');
    params.push(extra.raw_nmap_xml);
  }
  if (extra.raw_nuclei_jsonl !== undefined) {
    fields.push('raw_nuclei_jsonl = ?');
    params.push(extra.raw_nuclei_jsonl);
  }
  if (extra.error_log !== undefined) {
    fields.push('error_log = ?');
    params.push(extra.error_log);
  }
  if (status === 'completed' || status === 'failed') {
    fields.push('completed_at = CURRENT_TIMESTAMP');
  }

  params.push(scanId);
  db.prepare(`UPDATE scans SET ${fields.join(', ')} WHERE id = ?`).run(...params);
}

function deleteScanPorts(scanId) {
  db.prepare('DELETE FROM scan_ports WHERE scan_id = ?').run(scanId);
}

function deleteScanVulns(scanId, { onlyNuclei = false, port = null } = {}) {
  if (onlyNuclei && port !== null && port !== undefined) {
    db.prepare(`
      DELETE FROM scan_vulns
      WHERE scan_id = ? AND port = ?
        AND template_id NOT LIKE 'tls-certificate-%'
        AND template_id NOT LIKE 'nse-vulscan-%'
    `).run(scanId, Number(port));
  } else if (onlyNuclei) {
    db.prepare(`
      DELETE FROM scan_vulns
      WHERE scan_id = ?
        AND template_id NOT LIKE 'tls-certificate-%'
        AND template_id NOT LIKE 'nse-vulscan-%'
    `).run(scanId);
  } else {
    db.prepare('DELETE FROM scan_vulns WHERE scan_id = ?').run(scanId);
  }
}

function insertScanPorts(scanId, ports) {
  const stmt = db.prepare(`
    INSERT INTO scan_ports (scan_id, port, protocol, state, service_name, service_product, service_version, extra_info, cpe)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const insertMany = db.transaction((items) => {
    for (const p of items) {
      stmt.run(
        scanId,
        p.port,
        p.protocol || 'tcp',
        p.state || 'open',
        p.service_name || null,
        p.service_product || null,
        p.service_version || null,
        p.extra_info || null,
        p.cpe || null
      );
    }
  });
  insertMany(ports);
}

function insertScanVulns(scanId, vulns) {
  const stmt = db.prepare(`
    INSERT INTO scan_vulns (scan_id, port, template_id, name, severity, cve_id, matched_at, extracted_results, description)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const insertMany = db.transaction((items) => {
    for (const v of items) {
      stmt.run(
        scanId,
        v.port !== undefined && v.port !== null ? v.port : null,
        v.template_id,
        v.name || v.template_id,
        (v.severity || 'info').toLowerCase(),
        v.cve_id || null,
        v.matched_at || null,
        JSON.stringify(v.extracted_results || []),
        v.description || null
      );
    }
  });
  insertMany(vulns);
}

function insertScanVulnSingle(scanId, v) {
  db.prepare(`
    INSERT INTO scan_vulns (scan_id, port, template_id, name, severity, cve_id, matched_at, extracted_results, description)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    scanId,
    v.port !== undefined && v.port !== null ? v.port : null,
    v.template_id,
    v.name || v.template_id,
    (v.severity || 'info').toLowerCase(),
    v.cve_id || null,
    v.matched_at || null,
    JSON.stringify(v.extracted_results || []),
    v.description || null
  );
}

function getScanById(scanId) {
  const scan = db.prepare(`
    SELECT s.*, a.target, a.hostname, a.mac_address, a.vendor, a.tags
    FROM scans s
    JOIN assets a ON a.id = s.asset_id
    WHERE s.id = ?
  `).get(scanId);

  if (!scan) return null;

  const ports = db.prepare(`
    SELECT * FROM scan_ports WHERE scan_id = ? ORDER BY port ASC, protocol ASC
  `).all(scanId);

  const overridesMap = getAssetOverridesMap(scan.asset_id);

  const vulns = db.prepare(`
    SELECT * FROM scan_vulns WHERE scan_id = ?
    ORDER BY CASE LOWER(severity)
      WHEN 'critical' THEN 1
      WHEN 'high' THEN 2
      WHEN 'medium' THEN 3
      WHEN 'low' THEN 4
      ELSE 5
    END ASC, id ASC
  `).all(scanId).map((v) => {
    const ov = overridesMap.get(`${v.template_id}|${v.port || 0}`);
    return {
      ...v,
      extracted_results: safeParseJson(v.extracted_results, []),
      triage_status: ov ? ov.status : 'open',
      triage_notes: ov ? ov.notes : ''
    };
  });

  const diffRow = db.prepare(`
    SELECT * FROM scan_diffs WHERE new_scan_id = ? ORDER BY id DESC LIMIT 1
  `).get(scanId);

  const rawTags = safeParseJson(scan.tags, []);

  return {
    id: scan.id,
    asset_id: scan.asset_id,
    target: scan.target,
    hostname: scan.hostname,
    mac_address: scan.mac_address,
    vendor: scan.vendor,
    asset_tags: rawTags.filter((t) => t !== '_transient'),
    asset_is_transient: rawTags.includes('_transient'),
    profile: scan.profile,
    status: scan.status,
    started_at: scan.started_at,
    completed_at: scan.completed_at,
    error_log: scan.error_log,
    ports,
    vulns,
    diff: diffRow
      ? {
          id: diffRow.id,
          old_scan_id: diffRow.old_scan_id,
          new_scan_id: diffRow.new_scan_id,
          created_at: diffRow.created_at,
          summary: safeParseJson(diffRow.diff_summary_json, {})
        }
      : null
  };
}

function listRecentScans(limit = 25) {
  return db.prepare(`
    SELECT s.id, s.asset_id, a.target, a.hostname, s.profile, s.status, s.started_at, s.completed_at, s.error_log,
           (SELECT COUNT(*) FROM scan_ports sp WHERE sp.scan_id = s.id AND sp.state = 'open') AS open_port_count,
           (SELECT COUNT(*) FROM scan_vulns sv WHERE sv.scan_id = s.id) AS vuln_count
    FROM scans s
    JOIN assets a ON a.id = s.asset_id
    ORDER BY s.id DESC
    LIMIT ?
  `).all(limit);
}

function listAssetScans(assetId, limit = 20) {
  return db.prepare(`
    SELECT s.id, s.asset_id, s.profile, s.status, s.started_at, s.completed_at, s.error_log,
           (SELECT COUNT(*) FROM scan_ports sp WHERE sp.scan_id = s.id AND sp.state = 'open') AS open_port_count,
           (SELECT COUNT(*) FROM scan_vulns sv WHERE sv.scan_id = s.id) AS vuln_count
    FROM scans s
    WHERE s.asset_id = ?
    ORDER BY s.id DESC
    LIMIT ?
  `).all(assetId, limit);
}

function getPreviousCompletedScan(assetId, currentScanId) {
  return db.prepare(`
    SELECT * FROM scans
    WHERE asset_id = ? AND status = 'completed' AND id < ?
    ORDER BY id DESC
    LIMIT 1
  `).get(assetId, currentScanId);
}

function getScanPorts(scanId) {
  return db.prepare('SELECT * FROM scan_ports WHERE scan_id = ? ORDER BY port ASC').all(scanId);
}

function getScanVulns(scanId) {
  return db.prepare('SELECT * FROM scan_vulns WHERE scan_id = ? ORDER BY id ASC').all(scanId).map((v) => ({
    ...v,
    extracted_results: safeParseJson(v.extracted_results, [])
  }));
}

// Diff Queries
function insertScanDiff({ asset_id, old_scan_id, new_scan_id, diff_summary }) {
  const info = db.prepare(`
    INSERT INTO scan_diffs (asset_id, old_scan_id, new_scan_id, diff_summary_json)
    VALUES (?, ?, ?, ?)
  `).run(asset_id, old_scan_id, new_scan_id, JSON.stringify(diff_summary));
  return Number(info.lastInsertRowid);
}

function getAssetDiffs(assetId, limit = 50) {
  const rows = db.prepare(`
    SELECT d.*, a.target, a.hostname,
           os.started_at AS old_scan_started_at, os.profile AS old_scan_profile,
           ns.started_at AS new_scan_started_at, ns.profile AS new_scan_profile
    FROM scan_diffs d
    JOIN assets a ON a.id = d.asset_id
    LEFT JOIN scans os ON os.id = d.old_scan_id
    LEFT JOIN scans ns ON ns.id = d.new_scan_id
    WHERE d.asset_id = ?
    ORDER BY d.id DESC
    LIMIT ?
  `).all(assetId, limit);

  return rows.map((r) => ({
    id: r.id,
    asset_id: r.asset_id,
    target: r.target,
    hostname: r.hostname,
    old_scan_id: r.old_scan_id,
    new_scan_id: r.new_scan_id,
    old_scan_started_at: r.old_scan_started_at,
    new_scan_started_at: r.new_scan_started_at,
    old_scan_profile: r.old_scan_profile,
    new_scan_profile: r.new_scan_profile,
    created_at: r.created_at,
    summary: safeParseJson(r.diff_summary_json, {})
  }));
}

function getAllDiffs(limit = 100) {
  const rows = db.prepare(`
    SELECT d.*, a.target, a.hostname,
           os.started_at AS old_scan_started_at, os.profile AS old_scan_profile,
           ns.started_at AS new_scan_started_at, ns.profile AS new_scan_profile
    FROM scan_diffs d
    JOIN assets a ON a.id = d.asset_id
    LEFT JOIN scans os ON os.id = d.old_scan_id
    LEFT JOIN scans ns ON ns.id = d.new_scan_id
    ORDER BY d.id DESC
    LIMIT ?
  `).all(limit);

  return rows.map((r) => ({
    id: r.id,
    asset_id: r.asset_id,
    target: r.target,
    hostname: r.hostname,
    old_scan_id: r.old_scan_id,
    new_scan_id: r.new_scan_id,
    old_scan_started_at: r.old_scan_started_at,
    new_scan_started_at: r.new_scan_started_at,
    old_scan_profile: r.old_scan_profile,
    new_scan_profile: r.new_scan_profile,
    created_at: r.created_at,
    summary: safeParseJson(r.diff_summary_json, {})
  }));
}

// System Meta Queries
function getSystemMeta(key) {
  const row = db.prepare('SELECT * FROM system_meta WHERE key = ?').get(key);
  return row || null;
}

function setSystemMeta(key, value) {
  db.prepare(`
    INSERT INTO system_meta (key, value, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET
      value = excluded.value,
      updated_at = CURRENT_TIMESTAMP
  `).run(key, String(value));
}

function getAllSystemMeta() {
  const rows = db.prepare('SELECT * FROM system_meta').all();
  const map = {};
  for (const r of rows) {
    map[r.key] = { value: r.value, updated_at: r.updated_at };
  }
  return map;
}

module.exports = {
  db,
  dbPath,
  getAllProfilesMap,
  listProfiles,
  getProfileById,
  upsertProfile,
  deleteProfile,
  setVulnOverride,
  getAssetOverridesMap,
  listSchedules,
  getScheduleById,
  createSchedule,
  updateSchedule,
  markScheduleExecuted,
  deleteSchedule,
  getAssetById,
  getAssetByTarget,
  upsertAsset,
  updateAssetMetadata,
  updateAssetConfig,
  deleteAsset,
  listAssets,
  createScan,
  updateScanStatus,
  deleteScanPorts,
  deleteScanVulns,
  insertScanPorts,
  insertScanVulns,
  insertScanVulnSingle,
  getScanById,
  listRecentScans,
  listAssetScans,
  getPreviousCompletedScan,
  getScanPorts,
  getScanVulns,
  insertScanDiff,
  getAssetDiffs,
  getAllDiffs,
  getSystemMeta,
  setSystemMeta,
  getAllSystemMeta
};
