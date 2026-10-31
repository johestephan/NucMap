const db = require('./db');

function portKey(p) {
  return `${p.port}/${(p.protocol || 'tcp').toLowerCase()}`;
}

function vulnKey(v) {
  return `${v.template_id}|${v.matched_at || v.port || ''}`;
}

function computeScanDiff(previousPorts, currentPorts, previousVulns, currentVulns) {
  const prevPortMap = new Map();
  for (const p of previousPorts) {
    if (p.state === 'open') {
      prevPortMap.set(portKey(p), p);
    }
  }

  const currPortMap = new Map();
  for (const p of currentPorts) {
    if (p.state === 'open') {
      currPortMap.set(portKey(p), p);
    }
  }

  const added_ports = [];
  const removed_ports = [];
  const changed_ports = [];
  const events = [];

  // Check NEW_PORT and BANNER_CHANGED
  for (const [key, curr] of currPortMap.entries()) {
    const prev = prevPortMap.get(key);
    if (!prev) {
      const item = {
        type: 'NEW_PORT',
        port: curr.port,
        protocol: curr.protocol,
        service_name: curr.service_name,
        service_product: curr.service_product,
        service_version: curr.service_version
      };
      added_ports.push(item);
      events.push(item);
    } else {
      const prevProd = (prev.service_product || '').trim();
      const currProd = (curr.service_product || '').trim();
      const prevVer = (prev.service_version || '').trim();
      const currVer = (curr.service_version || '').trim();

      if (prevProd !== currProd || prevVer !== currVer) {
        const item = {
          type: 'BANNER_CHANGED',
          port: curr.port,
          protocol: curr.protocol,
          service_name: curr.service_name,
          old_product: prev.service_product || null,
          old_version: prev.service_version || null,
          new_product: curr.service_product || null,
          new_version: curr.service_version || null
        };
        changed_ports.push(item);
        events.push(item);
      }
    }
  }

  // Check CLOSED_PORT
  for (const [key, prev] of prevPortMap.entries()) {
    if (!currPortMap.has(key)) {
      const item = {
        type: 'CLOSED_PORT',
        port: prev.port,
        protocol: prev.protocol,
        service_name: prev.service_name,
        service_product: prev.service_product,
        service_version: prev.service_version
      };
      removed_ports.push(item);
      events.push(item);
    }
  }

  // Vulnerability Drift
  const prevVulnMap = new Map();
  for (const v of previousVulns) {
    prevVulnMap.set(vulnKey(v), v);
  }

  const currVulnMap = new Map();
  for (const v of currentVulns) {
    currVulnMap.set(vulnKey(v), v);
  }

  const added_vulns = [];
  const resolved_vulns = [];

  for (const [key, curr] of currVulnMap.entries()) {
    if (!prevVulnMap.has(key)) {
      const item = {
        type: 'NEW_VULN',
        port: curr.port,
        template_id: curr.template_id,
        name: curr.name,
        severity: curr.severity,
        cve_id: curr.cve_id,
        matched_at: curr.matched_at
      };
      added_vulns.push(item);
      events.push(item);
    }
  }

  for (const [key, prev] of prevVulnMap.entries()) {
    if (!currVulnMap.has(key)) {
      const item = {
        type: 'RESOLVED_VULN',
        port: prev.port,
        template_id: prev.template_id,
        name: prev.name,
        severity: prev.severity,
        cve_id: prev.cve_id,
        matched_at: prev.matched_at
      };
      resolved_vulns.push(item);
      events.push(item);
    }
  }

  const total_changes =
    added_ports.length +
    removed_ports.length +
    changed_ports.length +
    added_vulns.length +
    resolved_vulns.length;

  return {
    has_changes: total_changes > 0,
    total_changes,
    added_ports,
    removed_ports,
    changed_ports,
    added_vulns,
    resolved_vulns,
    events
  };
}

function generateAndSaveDiff(assetId, currentScanId) {
  const previousScan = db.getPreviousCompletedScan(assetId, currentScanId);
  if (!previousScan) {
    return null;
  }

  const prevPorts = db.getScanPorts(previousScan.id);
  const currPorts = db.getScanPorts(currentScanId);
  const prevVulns = db.getScanVulns(previousScan.id);
  const currVulns = db.getScanVulns(currentScanId);

  const summary = computeScanDiff(prevPorts, currPorts, prevVulns, currVulns);

  const diffId = db.insertScanDiff({
    asset_id: assetId,
    old_scan_id: previousScan.id,
    new_scan_id: currentScanId,
    diff_summary: summary
  });

  return {
    id: diffId,
    asset_id: assetId,
    old_scan_id: previousScan.id,
    new_scan_id: currentScanId,
    summary
  };
}

module.exports = {
  computeScanDiff,
  generateAndSaveDiff
};
