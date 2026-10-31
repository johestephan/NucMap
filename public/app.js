const state = {
  activeTab: 'assets',
  assets: [],
  selectedAssetTargets: new Set(),
  discoveredHosts: [],
  selectedDiscoveredIps: new Set(),
  profiles: {},
  schedules: [],
  recentScans: [],
  currentScanId: null,
  currentScan: null,
  diffs: [],
  queue: { is_processing: false, active_scan_ids: [], queued_scan_ids: [], max_concurrency: 3 },
  signatures: { status: 'idle', last_updated_at: null, output_log: '' },
  syslogConfig: {},
  syslogEvents: [],
  expandedPorts: new Set(),
  pollTimer: null,
  sigPollTimer: null
};

const WEB_PORT_SET = new Set([80, 443, 3000, 5000, 5001, 8000, 8006, 8008, 8080, 8081, 8443, 8444, 8843, 8880, 8888, 8900, 9000, 9090, 9350, 9351, 9443]);
const HTTPS_PORT_SET = new Set([443, 5001, 8006, 8443, 8444, 8843, 8900, 9351, 9443]);

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getPortWebUrl(target, portObj) {
  if (!target || target.includes('/')) return null;
  const svc = (portObj.service_name || '').toLowerCase();
  const port = Number(portObj.port);
  const isHttps = svc.includes('https') || svc.includes('ssl') || svc.includes('tls') || HTTPS_PORT_SET.has(port);
  const isWeb = isHttps || svc.includes('http') || WEB_PORT_SET.has(port);
  if (!isWeb) return null;
  const scheme = isHttps ? 'https' : 'http';
  return `${scheme}://${target}:${port}`;
}

function formatRelativeTime(dateStr) {
  if (!dateStr) return 'Never';
  const normalized = dateStr.includes('T') ? dateStr : dateStr.replace(' ', 'T') + 'Z';
  const d = new Date(normalized);
  if (Number.isNaN(d.getTime())) return dateStr;

  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diffSec < -60) {
    const futureMin = Math.ceil(Math.abs(diffSec) / 60);
    if (futureMin < 60) return `in ${futureMin}m`;
    const futureHr = Math.round(futureMin / 60);
    return `in ${futureHr}h`;
  }
  if (diffSec < 60) return 'Just now';
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDays = Math.floor(diffHr / 24);
  return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
}

function formatDateTime(dateStr) {
  if (!dateStr) return '—';
  const normalized = dateStr.includes('T') ? dateStr : dateStr.replace(' ', 'T') + 'Z';
  const d = new Date(normalized);
  if (Number.isNaN(d.getTime())) return dateStr;
  return d.toLocaleString();
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const colors = {
    info: 'bg-slate-900 border-cyan-500/50 text-cyan-200',
    success: 'bg-slate-900 border-emerald-500/50 text-emerald-200',
    error: 'bg-rose-950 border-rose-500/60 text-rose-200'
  };

  const el = document.createElement('div');
  el.className = `pointer-events-auto px-4 py-3 rounded-xl border shadow-xl text-xs font-medium flex items-center justify-between gap-3 transition-all ${colors[type] || colors.info}`;
  el.innerHTML = `<span>${escapeHtml(message)}</span>`;
  container.appendChild(el);

  setTimeout(() => {
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 300);
  }, 4000);
}

function severityBadge(severity, count = null) {
  const sev = (severity || 'info').toLowerCase();
  const map = {
    critical: 'bg-red-500/20 text-red-300 border-red-500/40',
    high: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
    medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
    low: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
    info: 'bg-slate-700/50 text-slate-300 border-slate-600/50'
  };
  const cls = map[sev] || map.info;
  const label = count !== null ? `${sev.toUpperCase()}: ${count}` : sev.toUpperCase();
  return `<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold border ${cls}">${escapeHtml(label)}</span>`;
}

function scanStatusBadge(status) {
  const map = {
    queued: { label: 'Queued', cls: 'bg-slate-800 text-slate-300 border-slate-700' },
    running_nmap: { label: 'Stage 1: Nmap Running', cls: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 animate-pulse' },
    running_nuclei: { label: 'Stage 2: Nuclei Running', cls: 'bg-amber-500/20 text-amber-300 border-amber-500/40 animate-pulse' },
    completed: { label: 'Completed', cls: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' },
    failed: { label: 'Failed / Stopped', cls: 'bg-rose-500/20 text-rose-300 border-rose-500/40' }
  };
  const item = map[status] || { label: status, cls: 'bg-slate-800 text-slate-300 border-slate-700' };
  return `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${item.cls}">${escapeHtml(item.label)}</span>`;
}

// Tab Switching
function switchTab(tabName) {
  state.activeTab = tabName;
  const tabs = ['assets', 'active-scan', 'diffs', 'profiles', 'schedules'];
  for (const t of tabs) {
    const panel = document.getElementById(`tab-panel-${t}`);
    const btn = document.getElementById(`tab-btn-${t}`);
    if (!panel || !btn) continue;
    if (t === tabName) {
      panel.classList.remove('hidden');
      btn.classList.add('border-cyan-400', 'text-cyan-400', 'bg-slate-900/60');
      btn.classList.remove('border-transparent', 'text-slate-400');
    } else {
      panel.classList.add('hidden');
      btn.classList.remove('border-cyan-400', 'text-cyan-400', 'bg-slate-900/60');
      btn.classList.add('border-transparent', 'text-slate-400');
    }
  }

  if (tabName === 'assets') {
    fetchAssets();
  } else if (tabName === 'active-scan') {
    refreshRecentScans();
    if (state.currentScanId) {
      fetchScanDetail(state.currentScanId);
    }
  } else if (tabName === 'diffs') {
    fetchDiffs();
  } else if (tabName === 'profiles') {
    fetchProfiles();
  } else if (tabName === 'schedules') {
    fetchSchedules();
    fetchSyslogData();
  }
}

// System Status & Concurrency
async function fetchSystemStatus() {
  try {
    const res = await fetch('/api/system/status');
    if (!res.ok) return;
    const data = await res.json();
    state.signatures = data.signatures || state.signatures;
    state.queue = data.queue || state.queue;
    if (data.profiles) {
      state.profiles = data.profiles;
      populateProfileDropdowns();
      renderProfilesList();
    }
    const concSelect = document.getElementById('global-concurrency-select');
    if (concSelect && state.queue.max_concurrency) {
      concSelect.value = String(state.queue.max_concurrency);
    }
    updateSignatureBadges();
    updateQueueIndicators();
  } catch (_) {}
}

async function updateGlobalConcurrency(val) {
  try {
    const res = await fetch('/api/system/concurrency', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ max_concurrency: Number(val) })
    });
    const data = await res.json();
    if (res.ok) {
      state.queue = data.queue || state.queue;
      showToast(`Parallel scanning concurrency set to ${data.max_concurrency}x hosts`, 'success');
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function populateProfileDropdowns() {
  const profileEntries = Object.values(state.profiles);
  if (profileEntries.length === 0) return;

  const badge = document.getElementById('tab-badge-profiles');
  if (badge) badge.textContent = profileEntries.length;

  const selectIds = ['scan-profile-select', 'asset-modal-profile', 'sched-profile', 'discover-import-profile'];
  for (const id of selectIds) {
    const el = document.getElementById(id);
    if (!el) continue;
    const prev = el.value || 'standard';
    const opts = [];
    if (id === 'sched-profile') {
      opts.push(`<option value="asset_default" ${prev === 'asset_default' ? 'selected' : ''}>Use Each Asset's Default Profile</option>`);
    }
    for (const p of profileEntries) {
      const selected = p.id === prev ? 'selected' : '';
      opts.push(
        `<option value="${escapeHtml(p.id)}" ${selected}>${escapeHtml(p.name)} [${escapeHtml(
          p.ports.length > 26 ? p.ports.slice(0, 26) + '…' : p.ports
        )}]</option>`
      );
    }
    el.innerHTML = opts.join('');
  }
}

function updateSignatureBadges() {
  const badge = document.getElementById('sig-last-updated-badge');
  const modalLast = document.getElementById('sig-modal-last-updated');
  const rel = state.signatures.last_updated_at
    ? formatRelativeTime(state.signatures.last_updated_at)
    : 'Never';

  if (badge) badge.textContent = rel;
  if (modalLast) {
    modalLast.textContent = state.signatures.last_updated_at
      ? `Last updated: ${formatDateTime(state.signatures.last_updated_at)} (${rel})`
      : 'Last updated: Never';
  }
}

function updateQueueIndicators() {
  const activeScans = state.recentScans.filter(
    (s) => s.status === 'queued' || s.status === 'running_nmap' || s.status === 'running_nuclei'
  );
  const runningCount = (state.queue.active_scan_ids || []).length;
  const queuedCount = (state.queue.queued_scan_ids || []).length;
  const totalCount = Math.max(activeScans.length, runningCount + queuedCount);

  const desk = document.getElementById('queue-badge-desktop');
  const mob = document.getElementById('queue-badge-mobile');
  const tabDot = document.getElementById('tab-badge-active');

  if (totalCount > 0 || state.queue.is_processing) {
    const label = `${runningCount || 1} running${queuedCount > 0 ? ` (${queuedCount} queued)` : ''}`;
    document.getElementById('queue-count-desktop').textContent = label;
    document.getElementById('queue-count-mobile').textContent = label;
    desk.classList.remove('hidden');
    desk.classList.add('inline-flex');
    mob.classList.remove('hidden');
    mob.classList.add('inline-flex');
    tabDot.classList.remove('hidden');
  } else {
    desk.classList.add('hidden');
    desk.classList.remove('inline-flex');
    mob.classList.add('hidden');
    mob.classList.remove('inline-flex');
    tabDot.classList.add('hidden');
  }
}

// Assets Inventory (Tab 1)
async function fetchAssets() {
  try {
    const res = await fetch('/api/assets');
    if (!res.ok) return;
    state.assets = await res.json();
    renderAssetsTable();
    updateOverviewStats();
    populateDiffAssetFilter();
  } catch (err) {
    console.error('Failed to fetch assets:', err);
  }
}

function updateOverviewStats() {
  const totalAssets = state.assets.length;
  let totalPorts = 0;
  let critHigh = 0;

  for (const a of state.assets) {
    totalPorts += a.open_port_count || 0;
    if (a.vuln_counts) {
      critHigh += (a.vuln_counts.critical || 0) + (a.vuln_counts.high || 0);
    }
  }

  document.getElementById('stat-total-assets').textContent = totalAssets;
  document.getElementById('stat-total-ports').textContent = totalPorts;
  document.getElementById('stat-crit-high-vulns').textContent = critHigh;
  document.getElementById('stat-total-diffs').textContent = state.diffs.length;
  document.getElementById('tab-badge-assets').textContent = totalAssets;
  document.getElementById('tab-badge-diffs').textContent = state.diffs.length;
}

function toggleAssetSelection(target, checked) {
  if (checked) {
    state.selectedAssetTargets.add(target);
  } else {
    state.selectedAssetTargets.delete(target);
  }
  updateSelectedAssetsButton();
}

function toggleSelectAllAssets(checked) {
  if (checked) {
    for (const a of state.assets) {
      state.selectedAssetTargets.add(a.target);
    }
  } else {
    state.selectedAssetTargets.clear();
  }
  renderAssetsTable();
  updateSelectedAssetsButton();
}

function updateSelectedAssetsButton() {
  const btn = document.getElementById('btn-scan-selected');
  if (!btn) return;
  const count = state.selectedAssetTargets.size;
  if (count > 0) {
    btn.classList.remove('hidden');
    btn.textContent = `Scan Selected (${count} Host${count === 1 ? '' : 's'})`;
  } else {
    btn.classList.add('hidden');
  }
}

async function scanSelectedAssets() {
  const targets = Array.from(state.selectedAssetTargets);
  if (targets.length === 0) return;
  const profile = document.getElementById('scan-profile-select')?.value || 'standard';
  const concurrency = Math.min(5, Math.max(1, Number(document.getElementById('global-concurrency-select')?.value || 3)));

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targets, profile, save_asset: true, concurrency })
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to queue selected scans', 'error');
      return;
    }
    showToast(`Started parallel scan of ${targets.length} host(s) (${concurrency}x concurrency)`, 'success');
    state.selectedAssetTargets.clear();
    updateSelectedAssetsButton();
    state.currentScanId = data.scan_id;
    switchTab('active-scan');
    await refreshRecentScans();
    await fetchScanDetail(data.scan_id);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function renderAssetsTable() {
  const tbody = document.getElementById('assets-table-body');
  const filter = (document.getElementById('asset-filter-input')?.value || '').toLowerCase().trim();

  const filtered = state.assets.filter((a) => {
    if (!filter) return true;
    const targetMatch = (a.target || '').toLowerCase().includes(filter);
    const hostMatch = (a.hostname || '').toLowerCase().includes(filter);
    const vendorMatch = (a.vendor || '').toLowerCase().includes(filter);
    const tagMatch = (a.tags || []).some((t) => t.toLowerCase().includes(filter));
    const portMatch = (a.open_ports || []).some(
      (p) => String(p.port).includes(filter) || (p.service_name || '').toLowerCase().includes(filter)
    );
    return targetMatch || hostMatch || vendorMatch || tagMatch || portMatch;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="px-5 py-12 text-center text-slate-400">
          <div class="max-w-md mx-auto space-y-2">
            <p class="font-semibold text-slate-200">No monitored assets found</p>
            <p class="text-xs text-slate-400">Click "Discover Subnet" to sweep your LAN, or enter targets in the Quick Scan bar above.</p>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered
    .map((asset) => {
      const isChecked = state.selectedAssetTargets.has(asset.target) ? 'checked' : '';
      const tagsHtml = (asset.tags || [])
        .map(
          (t) =>
            `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">${escapeHtml(
              t
            )}</span>`
        )
        .join(' ');

      const portsHtml =
        asset.open_ports && asset.open_ports.length > 0
          ? asset.open_ports
              .slice(0, 8)
              .map((p) => {
                const webUrl = getPortWebUrl(asset.target, p);
                const titleInfo = [p.service_product, p.service_version, p.extra_info].filter(Boolean).join(' ');
                if (webUrl) {
                  return `<a href="${escapeHtml(webUrl)}" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 hover:bg-cyan-950 text-emerald-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/50 transition" title="${escapeHtml(
                    `Open ${webUrl} — ${titleInfo}`
                  )}">${p.port}/${escapeHtml(p.protocol)} <span class="text-slate-400 font-sans">${escapeHtml(
                    p.service_name || ''
                  )} ↗</span></a>`;
                }
                return `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-emerald-300 border border-slate-700" title="${escapeHtml(
                  titleInfo
                )}">${p.port}/${escapeHtml(p.protocol)} <span class="text-slate-400 font-sans">${escapeHtml(
                  p.service_name || ''
                )}</span></span>`;
              })
              .join(' ') +
            (asset.open_ports.length > 8
              ? ` <span class="text-xs text-slate-400">+${asset.open_ports.length - 8} more</span>`
              : '')
          : `<span class="text-xs text-slate-500">No open ports</span>`;

      const vc = asset.vuln_counts || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0, suppressed: 0 };
      const vulnBadges = [];
      if (vc.critical > 0) vulnBadges.push(severityBadge('critical', vc.critical));
      if (vc.high > 0) vulnBadges.push(severityBadge('high', vc.high));
      if (vc.medium > 0) vulnBadges.push(severityBadge('medium', vc.medium));
      if (vc.low > 0) vulnBadges.push(severityBadge('low', vc.low));
      if (vc.info > 0) vulnBadges.push(severityBadge('info', vc.info));
      if (vc.suppressed > 0) {
        vulnBadges.push(
          `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 border border-slate-700" title="Accepted Risk / False Positive">${vc.suppressed} triaged</span>`
        );
      }
      const vulnsHtml =
        vulnBadges.length > 0
          ? vulnBadges.join(' ')
          : `<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Clean (0)</span>`;

      const activeScanRunning =
        asset.latest_scan &&
        ['queued', 'running_nmap', 'running_nuclei'].includes(asset.latest_scan.status);

      const lastScannedHtml = activeScanRunning
        ? scanStatusBadge(asset.latest_scan.status)
        : `<div class="text-xs text-slate-200">${escapeHtml(formatRelativeTime(asset.last_scanned_at))}</div>
           <div class="text-[11px] text-slate-500">${escapeHtml(formatDateTime(asset.last_scanned_at))}</div>`;

      return `
        <tr class="hover:bg-slate-850/60 transition">
          <td class="px-4 py-4 align-top">
            <input type="checkbox" ${isChecked} onchange="toggleAssetSelection('${escapeHtml(asset.target)}', this.checked)" class="rounded bg-slate-950 border-slate-700 text-cyan-500" />
          </td>
          <td class="px-4 py-4 align-top">
            <div class="flex items-center gap-2">
              <span class="font-bold text-white font-mono">${escapeHtml(asset.target)}</span>
              <span class="text-[10px] uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">${escapeHtml(
                asset.default_profile || 'standard'
              )}</span>
            </div>
            ${
              asset.hostname
                ? `<div class="text-xs text-slate-400 mt-0.5">${escapeHtml(asset.hostname)}</div>`
                : ''
            }
            ${tagsHtml ? `<div class="flex flex-wrap gap-1 mt-1.5">${tagsHtml}</div>` : ''}
          </td>

          <td class="px-4 py-4 align-top">
            ${
              asset.mac_address
                ? `<div class="text-xs font-mono text-slate-200">${escapeHtml(asset.mac_address)}</div>`
                : `<div class="text-xs text-slate-500">—</div>`
            }
            ${
              asset.vendor
                ? `<div class="text-[11px] text-slate-400 mt-0.5">${escapeHtml(asset.vendor)}</div>`
                : ''
            }
          </td>

          <td class="px-4 py-4 align-top max-w-xs">
            <div class="flex flex-wrap gap-1">${portsHtml}</div>
          </td>

          <td class="px-4 py-4 align-top">
            <div class="flex flex-wrap gap-1">${vulnsHtml}</div>
          </td>

          <td class="px-4 py-4 align-top whitespace-nowrap">
            ${lastScannedHtml}
          </td>

          <td class="px-5 py-4 align-top text-right whitespace-nowrap">
            <div class="inline-flex items-center gap-1.5">
              <button
                onclick="scanSavedAsset('${escapeHtml(asset.target)}', '${escapeHtml(asset.default_profile || 'standard')}')"
                class="px-2.5 py-1 rounded text-xs font-semibold bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 transition"
                title="Trigger immediate scan"
              >
                Rescan
              </button>
              ${
                asset.latest_scan
                  ? `<button
                      onclick="openScanInTab(${asset.latest_scan.id})"
                      class="px-2.5 py-1 rounded text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                      title="Inspect latest scan results"
                    >
                      Results
                    </button>`
                  : ''
              }
              <button
                onclick="openAssetHistoryModal(${asset.id}, '${escapeHtml(asset.target)}')"
                class="px-2.5 py-1 rounded text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                title="View Scan History & Drift"
              >
                History
              </button>
              <button
                onclick="openEditAssetModal(${asset.id})"
                class="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition"
                title="Edit Asset Tags & Profile"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
              </button>
              <button
                onclick="deleteAssetById(${asset.id}, '${escapeHtml(asset.target)}')"
                class="p-1.5 rounded text-rose-400 hover:text-rose-300 hover:bg-rose-950/50 transition"
                title="Delete Asset"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
            </div>
          </td>
        </tr>
      `;
    })
    .join('');
}

// Subnet Host Discovery Wizard (Modal 4)
function openDiscoverModal() {
  populateProfileDropdowns();
  document.getElementById('discover-modal').classList.remove('hidden');
}

function closeDiscoverModal() {
  document.getElementById('discover-modal').classList.add('hidden');
}

async function runSubnetDiscovery(e) {
  e.preventDefault();
  const cidr = document.getElementById('discover-cidr-input').value.trim();
  if (!cidr) return;

  const btn = document.getElementById('btn-run-discovery');
  const area = document.getElementById('discover-results-area');
  btn.disabled = true;
  btn.textContent = 'Sweeping Subnet...';
  area.innerHTML = `<div class="p-8 text-center text-xs text-emerald-300 animate-pulse border border-emerald-500/30 rounded-xl bg-emerald-950/20">Running Nmap ARP/Ping sweep (\`nmap -sn ${escapeHtml(cidr)}\`)...</div>`;

  try {
    const res = await fetch('/api/discover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cidr })
    });
    const data = await res.json();
    if (!res.ok) {
      area.innerHTML = `<div class="p-4 text-xs text-rose-300 bg-rose-950/40 border border-rose-700 rounded-xl">${escapeHtml(data.error || 'Discovery failed')}</div>`;
      return;
    }

    state.discoveredHosts = data.hosts || [];
    state.selectedDiscoveredIps.clear();
    for (const h of state.discoveredHosts) {
      if (!h.already_monitored) {
        state.selectedDiscoveredIps.add(h.target);
      }
    }
    renderDiscoveredHostsList();
  } catch (err) {
    area.innerHTML = `<div class="p-4 text-xs text-rose-300 bg-rose-950/40 border border-rose-700 rounded-xl">${escapeHtml(err.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run ARP / Ping Sweep';
  }
}

function toggleDiscoveredIp(ip, checked) {
  if (checked) {
    state.selectedDiscoveredIps.add(ip);
  } else {
    state.selectedDiscoveredIps.delete(ip);
  }
}

function renderDiscoveredHostsList() {
  const area = document.getElementById('discover-results-area');
  if (state.discoveredHosts.length === 0) {
    area.innerHTML = `<div class="p-6 text-center text-xs text-slate-400 border border-slate-800 rounded-xl">No live hosts responded in that range.</div>`;
    return;
  }

  area.innerHTML = `
    <div class="flex items-center justify-between text-xs text-slate-300 px-1">
      <span>Discovered <strong>${state.discoveredHosts.length}</strong> live host(s):</span>
      <div class="space-x-2">
        <button type="button" onclick="state.discoveredHosts.forEach(h=>state.selectedDiscoveredIps.add(h.target)); renderDiscoveredHostsList();" class="text-cyan-400 hover:underline">Select All</button>
        <button type="button" onclick="state.selectedDiscoveredIps.clear(); renderDiscoveredHostsList();" class="text-slate-400 hover:underline">Clear</button>
      </div>
    </div>
    <div class="border border-slate-800 rounded-xl overflow-hidden divide-y divide-slate-800 max-h-80 overflow-y-auto bg-slate-950/60">
      ${state.discoveredHosts
        .map((h) => {
          const checked = state.selectedDiscoveredIps.has(h.target) ? 'checked' : '';
          return `
            <label class="px-4 py-2.5 flex items-center justify-between gap-3 hover:bg-slate-900 cursor-pointer text-xs">
              <div class="flex items-center gap-3">
                <input type="checkbox" ${checked} onchange="toggleDiscoveredIp('${escapeHtml(h.target)}', this.checked)" class="rounded bg-slate-900 border-slate-700 text-cyan-500" />
                <div>
                  <span class="font-mono font-bold text-white">${escapeHtml(h.target)}</span>
                  ${h.hostname ? `<span class="ml-2 text-cyan-300">${escapeHtml(h.hostname)}</span>` : ''}
                  ${h.vendor || h.mac_address ? `<div class="text-[11px] text-slate-400 font-mono">${escapeHtml(h.mac_address || '')} ${escapeHtml(h.vendor ? `(${h.vendor})` : '')}</div>` : ''}
                </div>
              </div>
              <div>
                ${
                  h.already_monitored
                    ? `<span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 border border-slate-700">Already Monitored</span>`
                    : `<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">New Host</span>`
                }
              </div>
            </label>
          `;
        })
        .join('')}
    </div>
  `;
}

async function importDiscoveredHosts(scanNow = false) {
  const selected = state.discoveredHosts.filter((h) => state.selectedDiscoveredIps.has(h.target));
  if (selected.length === 0) {
    showToast('Select at least one discovered host to import', 'info');
    return;
  }

  const tags = document
    .getElementById('discover-import-tags')
    .value.split(',')
    .map((t) => t.trim())
    .filter(Boolean);
  const default_profile = document.getElementById('discover-import-profile').value || 'standard';

  try {
    const res = await fetch('/api/assets/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hosts: selected,
        tags,
        default_profile,
        scan_now: scanNow
      })
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Import failed', 'error');
      return;
    }

    showToast(
      scanNow
        ? `Imported & queued scans for ${data.imported_count} host(s)!`
        : `Imported ${data.imported_count} host(s) to Monitored Assets`,
      'success'
    );
    closeDiscoverModal();
    await fetchAssets();

    if (scanNow && data.scan_result?.scan_id) {
      state.currentScanId = data.scan_result.scan_id;
      switchTab('active-scan');
      await refreshRecentScans();
      await fetchScanDetail(state.currentScanId);
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Trigger Quick Scan from Top Bar
async function handleQuickScanSubmit(e) {
  e.preventDefault();
  const targetInput = document.getElementById('scan-target-input');
  const profileSelect = document.getElementById('scan-profile-select');
  const tagsInput = document.getElementById('scan-tags-input');
  const saveAssetCheckbox = document.getElementById('scan-save-asset');
  const concurrency = Number(document.getElementById('global-concurrency-select')?.value || 3);

  const target = targetInput.value.trim();
  if (!target) return;

  const profile = profileSelect.value;
  const save_asset = saveAssetCheckbox.checked;
  const tags = tagsInput.value
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, profile, save_asset, tags, concurrency })
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to start scan', 'error');
      return;
    }

    const jobCount = (data.jobs || []).length || 1;
    showToast(
      jobCount > 1
        ? `Started ${jobCount} synchronous host scans (${profile})`
        : `Scan #${data.scan_id} queued for ${data.target} (${data.profile})`,
      'success'
    );
    targetInput.value = '';
    state.currentScanId = data.scan_id;
    switchTab('active-scan');
    await refreshRecentScans();
    await fetchScanDetail(data.scan_id);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function scanSavedAsset(target, profile = 'standard') {
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, profile, save_asset: true })
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to start scan', 'error');
      return;
    }
    showToast(`Rescan #${data.scan_id} started for ${target}`, 'success');
    state.currentScanId = data.scan_id;
    switchTab('active-scan');
    await refreshRecentScans();
    await fetchScanDetail(data.scan_id);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function cancelCurrentScan() {
  if (!state.currentScanId) return;
  try {
    const res = await fetch(`/api/scan/${state.currentScanId}/cancel`, { method: 'POST' });
    if (res.ok) {
      showToast(`Cancelled Scan #${state.currentScanId}`, 'info');
      await refreshRecentScans();
      await fetchScanDetail(state.currentScanId);
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function triggerBulkRescan() {
  const concurrency = Number(document.getElementById('global-concurrency-select')?.value || 3);
  try {
    const res = await fetch('/api/scan/bulk-diff', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ concurrency })
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to trigger bulk rescan', 'error');
      return;
    }
    if (data.queued_count === 0) {
      showToast('No monitored assets to rescan. Save an asset first!', 'info');
      return;
    }
    showToast(`Queued ${data.queued_count} monitored asset(s) (${concurrency}x parallel workers)`, 'success');
    if (data.scan_ids && data.scan_ids.length > 0) {
      state.currentScanId = data.scan_ids[0];
      switchTab('active-scan');
      await refreshRecentScans();
      await fetchScanDetail(state.currentScanId);
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Recent Scans & Active Scan Detail (Tab 2)
async function refreshRecentScans() {
  try {
    const res = await fetch('/api/scans?limit=30');
    if (!res.ok) return;
    const data = await res.json();
    state.recentScans = data.scans || [];
    state.queue = data.queue || state.queue;
    updateQueueIndicators();
    renderRecentScansList();

    if (!state.currentScanId && state.recentScans.length > 0) {
      state.currentScanId = state.recentScans[0].id;
      fetchScanDetail(state.currentScanId);
    }
  } catch (_) {}
}

function renderRecentScansList() {
  const container = document.getElementById('recent-scans-list');
  if (!container) return;

  if (state.recentScans.length === 0) {
    container.innerHTML = `<div class="p-6 text-center text-xs text-slate-500">No scans triggered yet.</div>`;
    return;
  }

  container.innerHTML = state.recentScans
    .map((s) => {
      const isSelected = s.id === state.currentScanId;
      const bg = isSelected ? 'bg-cyan-500/10 border-l-4 border-l-cyan-400' : 'hover:bg-slate-800/60';
      return `
        <button
          onclick="selectScanFromList(${s.id})"
          class="w-full text-left p-3.5 transition flex items-start justify-between gap-2 ${bg}"
        >
          <div class="min-w-0">
            <div class="flex items-center gap-2">
              <span class="text-xs font-mono text-cyan-400">#${s.id}</span>
              <span class="text-sm font-bold text-white truncate">${escapeHtml(s.target)}</span>
            </div>
            <div class="text-[11px] text-slate-400 mt-1 flex items-center gap-2">
              <span class="uppercase font-semibold text-slate-300">${escapeHtml(s.profile)}</span>
              <span>•</span>
              <span>${s.open_port_count || 0} ports</span>
              <span>•</span>
              <span>${s.vuln_count || 0} vulns</span>
            </div>
            <div class="text-[10px] text-slate-500 mt-0.5">${escapeHtml(formatRelativeTime(s.started_at))}</div>
          </div>
          <div class="shrink-0">
            ${scanStatusBadge(s.status)}
          </div>
        </button>
      `;
    })
    .join('');
}

function selectScanFromList(scanId) {
  state.currentScanId = scanId;
  state.expandedPorts.clear();
  renderRecentScansList();
  fetchScanDetail(scanId);
}

function openScanInTab(scanId) {
  state.currentScanId = scanId;
  state.expandedPorts.clear();
  switchTab('active-scan');
}

async function fetchScanDetail(scanId) {
  if (!scanId) return;
  try {
    const res = await fetch(`/api/scan/${scanId}`);
    if (!res.ok) return;
    const scan = await res.json();
    state.currentScan = scan;
    renderActiveScanDetail(scan);
  } catch (err) {
    console.error('Error fetching scan detail:', err);
  }
}

function renderActiveScanDetail(scan) {
  const emptyEl = document.getElementById('active-scan-empty');
  const detailEl = document.getElementById('active-scan-detail');
  if (!scan) {
    emptyEl.classList.remove('hidden');
    detailEl.classList.add('hidden');
    return;
  }

  emptyEl.classList.add('hidden');
  detailEl.classList.remove('hidden');

  document.getElementById('scan-detail-id').textContent = `#${scan.id}`;
  document.getElementById('scan-detail-target').textContent = scan.target;
  document.getElementById('scan-detail-profile').textContent = scan.profile;
  document.getElementById('scan-detail-status-badge').outerHTML = `<span id="scan-detail-status-badge">${scanStatusBadge(scan.status)}</span>`;

  const metaParts = [];
  if (scan.hostname) metaParts.push(`Hostname: ${scan.hostname}`);
  if (scan.mac_address) metaParts.push(`MAC: ${scan.mac_address}${scan.vendor ? ` (${scan.vendor})` : ''}`);
  metaParts.push(`Started: ${formatDateTime(scan.started_at)}`);
  if (scan.completed_at) metaParts.push(`Finished: ${formatDateTime(scan.completed_at)}`);
  document.getElementById('scan-detail-meta').textContent = metaParts.join('  |  ');

  const cancelBtn = document.getElementById('btn-cancel-scan');
  if (['queued', 'running_nmap', 'running_nuclei'].includes(scan.status)) {
    cancelBtn.classList.remove('hidden');
  } else {
    cancelBtn.classList.add('hidden');
  }

  const promoteBtn = document.getElementById('btn-promote-transient');
  if (scan.asset_is_transient) {
    promoteBtn.classList.remove('hidden');
  } else {
    promoteBtn.classList.add('hidden');
  }

  updateStepperUI(scan);

  const errBanner = document.getElementById('scan-error-banner');
  if (scan.error_log) {
    errBanner.textContent = scan.error_log;
    errBanner.classList.remove('hidden');
  } else {
    errBanner.classList.add('hidden');
  }

  const diffBanner = document.getElementById('scan-diff-banner');
  if (scan.diff && scan.diff.summary) {
    const s = scan.diff.summary;
    if (s.has_changes) {
      diffBanner.classList.remove('hidden');
      diffBanner.innerHTML = `
        <div class="flex items-center justify-between">
          <div class="font-semibold text-indigo-200">
            Attack Surface Drift Detected (Compared to Scan #${scan.diff.old_scan_id}):
            <span class="ml-2 text-emerald-300">+${(s.added_ports || []).length} New Ports</span>,
            <span class="ml-1 text-rose-300">-${(s.removed_ports || []).length} Closed Ports</span>,
            <span class="ml-1 text-amber-300">~${(s.changed_ports || []).length} Banner Changes</span>,
            <span class="ml-1 text-rose-400">+${(s.added_vulns || []).length} New Vulns</span>,
            <span class="ml-1 text-emerald-400">✓${(s.resolved_vulns || []).length} Resolved Vulns</span>
          </div>
          <button onclick="switchTab('diffs')" class="text-indigo-300 hover:text-white underline font-medium">View Full Diff Timeline →</button>
        </div>
      `;
    } else {
      diffBanner.classList.remove('hidden');
      diffBanner.innerHTML = `<span class="text-slate-300">No attack surface drift compared to previous Scan #${scan.diff.old_scan_id} (0 changes).</span>`;
    }
  } else {
    diffBanner.classList.add('hidden');
  }

  renderScanPortCards(scan);
}

function updateStepperUI(scan) {
  const s1Box = document.getElementById('step-1-box');
  const s1Icon = document.getElementById('step-1-icon');
  const s1Sub = document.getElementById('step-1-sub');

  const s2Box = document.getElementById('step-2-box');
  const s2Icon = document.getElementById('step-2-icon');
  const s2Sub = document.getElementById('step-2-sub');

  const s3Box = document.getElementById('step-3-box');
  const s3Icon = document.getElementById('step-3-icon');
  const s3Sub = document.getElementById('step-3-sub');

  [s1Box, s2Box, s3Box].forEach((b) => {
    b.className = 'p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 flex items-center gap-3';
  });

  if (scan.status === 'queued') {
    s1Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-slate-800 text-slate-300 text-xs font-bold';
    s1Icon.textContent = '1';
    s1Sub.textContent = 'Waiting for parallel worker slot...';
    s2Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-slate-800 text-slate-500 text-xs font-bold';
    s2Icon.textContent = '2';
    s2Sub.textContent = 'Pending Stage 1';
    s3Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-slate-800 text-slate-500 text-xs font-bold';
    s3Icon.textContent = '3';
    s3Sub.textContent = 'Pending completion';
  } else if (scan.status === 'running_nmap') {
    s1Box.className = 'p-3.5 rounded-lg border border-cyan-500/50 bg-cyan-950/20 flex items-center gap-3';
    s1Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-cyan-500 text-slate-950 text-xs font-bold animate-pulse';
    s1Icon.textContent = '1';
    s1Sub.textContent = 'Enumerating open ports, TLS & banners...';

    s2Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-slate-800 text-slate-500 text-xs font-bold';
    s2Icon.textContent = '2';
    s2Sub.textContent = 'Waiting for Nmap XML...';

    s3Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-slate-800 text-slate-500 text-xs font-bold';
    s3Icon.textContent = '3';
    s3Sub.textContent = 'Pending completion';
  } else if (scan.status === 'running_nuclei') {
    s1Box.className = 'p-3.5 rounded-lg border border-emerald-500/30 bg-emerald-950/10 flex items-center gap-3';
    s1Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-emerald-500 text-slate-950 text-xs font-bold';
    s1Icon.textContent = '✓';
    s1Sub.textContent = `Discovered ${(scan.ports || []).length} open port(s)`;

    s2Box.className = 'p-3.5 rounded-lg border border-amber-500/50 bg-amber-950/20 flex items-center gap-3';
    s2Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-amber-400 text-slate-950 text-xs font-bold animate-pulse';
    s2Icon.textContent = '2';
    s2Sub.textContent = `Running Nuclei (${(scan.vulns || []).length} findings so far)...`;

    s3Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-slate-800 text-slate-500 text-xs font-bold';
    s3Icon.textContent = '3';
    s3Sub.textContent = 'Pending Nuclei completion';
  } else if (scan.status === 'completed') {
    s1Box.className = 'p-3.5 rounded-lg border border-emerald-500/30 bg-emerald-950/10 flex items-center gap-3';
    s1Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-emerald-500 text-slate-950 text-xs font-bold';
    s1Icon.textContent = '✓';
    s1Sub.textContent = `${(scan.ports || []).length} open port(s) enumerated`;

    s2Box.className = 'p-3.5 rounded-lg border border-emerald-500/30 bg-emerald-950/10 flex items-center gap-3';
    s2Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-emerald-500 text-slate-950 text-xs font-bold';
    s2Icon.textContent = '✓';
    s2Sub.textContent = `${(scan.vulns || []).length} finding(s) verified`;

    s3Box.className = 'p-3.5 rounded-lg border border-emerald-500/30 bg-emerald-950/10 flex items-center gap-3';
    s3Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-emerald-500 text-slate-950 text-xs font-bold';
    s3Icon.textContent = '✓';
    s3Sub.textContent = scan.diff
      ? `${scan.diff.summary?.total_changes || 0} drift event(s) & JSON syslog`
      : 'Baseline state & JSON syslog stored';
  } else if (scan.status === 'failed') {
    s1Box.className = 'p-3.5 rounded-lg border border-rose-500/40 bg-rose-950/20 flex items-center gap-3';
    s1Icon.className = 'w-8 h-8 rounded-full flex items-center justify-center bg-rose-500 text-white text-xs font-bold';
    s1Icon.textContent = '!';
    s1Sub.textContent = 'Scan stopped or failed';
  }
}

function togglePortCard(portKey) {
  if (state.expandedPorts.has(portKey)) {
    state.expandedPorts.delete(portKey);
  } else {
    state.expandedPorts.add(portKey);
  }
  if (state.currentScan) {
    renderScanPortCards(state.currentScan);
  }
}

function renderScanPortCards(scan) {
  const container = document.getElementById('scan-ports-cards');
  const label = document.getElementById('scan-ports-summary-label');
  const ports = scan.ports || [];
  const vulns = scan.vulns || [];

  label.textContent = `${ports.length} open port${ports.length === 1 ? '' : 's'} • ${vulns.length} finding${vulns.length === 1 ? '' : 's'}`;

  if (ports.length === 0 && vulns.length === 0) {
    if (scan.status === 'queued' || scan.status === 'running_nmap') {
      container.innerHTML = `
        <div class="bg-slate-900/70 border border-slate-800 rounded-xl p-8 text-center text-xs text-slate-400">
          Nmap is currently scanning <span class="text-white font-mono">${escapeHtml(scan.target)}</span>... Open ports will appear here as soon as Stage 1 completes.
        </div>
      `;
    } else {
      container.innerHTML = `
        <div class="bg-slate-900/70 border border-slate-800 rounded-xl p-8 text-center text-xs text-slate-400">
          No open ports were discovered on <span class="text-white font-mono">${escapeHtml(scan.target)}</span> with the <span class="uppercase">${escapeHtml(scan.profile)}</span> profile.
        </div>
      `;
    }
    return;
  }

  const vulnsByPort = new Map();
  const unmatchedVulns = [];
  const portNums = new Set(ports.map((p) => Number(p.port)));

  for (const v of vulns) {
    const pNum = v.port !== null && v.port !== undefined ? Number(v.port) : null;
    if (pNum && portNums.has(pNum)) {
      if (!vulnsByPort.has(pNum)) vulnsByPort.set(pNum, []);
      vulnsByPort.get(pNum).push(v);
    } else {
      unmatchedVulns.push(v);
    }
  }

  const cardsHtml = ports.map((p) => {
    const pKey = `${p.port}/${p.protocol}`;
    const pVulns = vulnsByPort.get(Number(p.port)) || [];
    const isExpanded = state.expandedPorts.has(pKey) || pVulns.length > 0 || ports.length <= 5;
    const banner = [p.service_product, p.service_version, p.extra_info].filter(Boolean).join(' ');
    const webUrl = getPortWebUrl(scan.target, p);

    const vulnBadgesHtml =
      pVulns.length > 0
        ? pVulns.map((v) => severityBadge(v.severity)).join(' ')
        : `<span class="text-[11px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">0 findings</span>`;

    return `
      <div class="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow">
        <div class="w-full px-5 py-3.5 flex flex-wrap items-center justify-between gap-3 hover:bg-slate-850/70 transition">
          <div onclick="togglePortCard('${escapeHtml(pKey)}')" class="flex items-center gap-3 cursor-pointer flex-1">
            <span class="px-2.5 py-1 rounded-lg font-mono text-xs font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              ${p.port}/${escapeHtml(p.protocol)}
            </span>
            <div>
              <div class="flex flex-wrap items-center gap-2">
                <span class="text-sm font-semibold text-white">${escapeHtml(p.service_name || 'unknown')}</span>
                ${banner ? `<span class="text-xs text-slate-300 font-mono">${escapeHtml(banner)}</span>` : ''}
              </div>
              ${p.cpe ? `<div class="text-[11px] text-slate-500 font-mono mt-0.5">${escapeHtml(p.cpe)}</div>` : ''}
            </div>
          </div>

          <div class="flex items-center gap-2">
            ${
              webUrl
                ? `<a href="${escapeHtml(webUrl)}" target="_blank" rel="noopener noreferrer" class="px-2 py-0.5 rounded text-[11px] font-medium bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30">Open ↗</a>`
                : ''
            }
            ${vulnBadgesHtml}
            <button type="button" onclick="togglePortCard('${escapeHtml(pKey)}')" class="p-1 text-slate-400 hover:text-white">
              <svg class="w-4 h-4 transform transition ${isExpanded ? 'rotate-180' : ''}" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" />
              </svg>
            </button>
          </div>
        </div>

        ${
          isExpanded
            ? `
          <div class="px-5 py-3.5 bg-slate-950/60 border-t border-slate-800/80 space-y-2.5">
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs text-slate-400">
              <div><span class="text-slate-500">Service:</span> <span class="text-slate-200 font-mono">${escapeHtml(p.service_name || '—')}</span></div>
              <div><span class="text-slate-500">Product:</span> <span class="text-slate-200 font-mono">${escapeHtml(p.service_product || '—')}</span></div>
              <div><span class="text-slate-500">Version / TLS:</span> <span class="text-slate-200 font-mono">${escapeHtml([p.service_version, p.extra_info].filter(Boolean).join(' • ') || '—')}</span></div>
            </div>
            ${
              pVulns.length > 0
                ? `<div class="pt-2 space-y-2">
                    <div class="text-xs font-semibold text-slate-300 uppercase tracking-wider">Verified Findings (${pVulns.length})</div>
                    ${pVulns.map((v) => renderVulnItem(scan.asset_id, v)).join('')}
                   </div>`
                : `<div class="text-xs text-slate-500 italic pt-1">
                    ${
                      scan.status === 'running_nuclei'
                        ? 'Nuclei is currently testing templates against this port...'
                        : 'No vulnerabilities or exposures matched on this port.'
                    }
                   </div>`
            }
          </div>
        `
            : ''
        }
      </div>
    `;
  });

  if (unmatchedVulns.length > 0) {
    cardsHtml.push(`
      <div class="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow">
        <div class="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
          <span class="text-sm font-semibold text-white">Host / Network-Level Findings</span>
          <span class="text-xs text-slate-400">${unmatchedVulns.length} finding(s)</span>
        </div>
        <div class="p-5 bg-slate-950/60 space-y-2">
          ${unmatchedVulns.map((v) => renderVulnItem(scan.asset_id, v)).join('')}
        </div>
      </div>
    `);
  }

  container.innerHTML = cardsHtml.join('');
}

function renderVulnItem(assetId, v) {
  const isSuppressed = v.triage_status === 'accepted_risk' || v.triage_status === 'false_positive';
  const triageBadge =
    v.triage_status === 'accepted_risk'
      ? `<span class="text-[10px] uppercase px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Accepted Risk</span>`
      : v.triage_status === 'false_positive'
      ? `<span class="text-[10px] uppercase px-2 py-0.5 rounded bg-slate-700 text-slate-300 border border-slate-600">False Positive</span>`
      : '';

  const extracted = Array.isArray(v.extracted_results) && v.extracted_results.length > 0
    ? `<div class="mt-1 text-[11px] font-mono text-cyan-300 bg-slate-900 px-2 py-1 rounded border border-slate-800">Extracted: ${escapeHtml(v.extracted_results.join(', '))}</div>`
    : '';

  return `
    <div class="p-3 rounded-lg bg-slate-900 border ${isSuppressed ? 'border-slate-800/50 opacity-65' : 'border-slate-800'} flex flex-col gap-1.5">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex flex-wrap items-center gap-2">
          ${severityBadge(v.severity)}
          ${triageBadge}
          <span class="text-xs font-bold ${isSuppressed ? 'line-through text-slate-400' : 'text-white'}">${escapeHtml(v.name)}</span>
          <span class="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300">${escapeHtml(v.template_id)}</span>
          ${
            v.cve_id
              ? `<span class="text-[11px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">${escapeHtml(v.cve_id)}</span>`
              : ''
          }
        </div>
        <div class="flex items-center gap-1.5">
          ${
            v.triage_status !== 'accepted_risk'
              ? `<button onclick="setFindingTriage(${assetId}, '${escapeHtml(v.template_id)}', ${v.port || 0}, 'accepted_risk')" class="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-slate-700" title="Suppress from Critical/High counter as Accepted Risk">Accept Risk</button>`
              : ''
          }
          ${
            v.triage_status !== 'false_positive'
              ? `<button onclick="setFindingTriage(${assetId}, '${escapeHtml(v.template_id)}', ${v.port || 0}, 'false_positive')" class="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700" title="Mark as False Positive">False Positive</button>`
              : ''
          }
          ${
            isSuppressed
              ? `<button onclick="setFindingTriage(${assetId}, '${escapeHtml(v.template_id)}', ${v.port || 0}, 'open')" class="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700">Reopen</button>`
              : ''
          }
        </div>
      </div>
      ${
        v.matched_at
          ? `<div class="text-[11px] font-mono text-slate-400 break-all">Matched at: ${escapeHtml(v.matched_at)}</div>`
          : ''
      }
      ${v.description ? `<p class="text-xs text-slate-400">${escapeHtml(v.description)}</p>` : ''}
      ${extracted}
    </div>
  `;
}

async function setFindingTriage(assetId, templateId, port, status) {
  try {
    const res = await fetch('/api/vulns/triage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        asset_id: assetId,
        template_id: templateId,
        port: port || 0,
        status
      })
    });
    if (!res.ok) {
      showToast('Failed to update finding triage status', 'error');
      return;
    }
    showToast(`Finding ${templateId} marked as ${status.replace('_', ' ')}`, 'info');
    if (state.currentScanId) {
      await fetchScanDetail(state.currentScanId);
    }
    await fetchAssets();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function promoteCurrentScanAsset() {
  if (!state.currentScan) return;
  try {
    const res = await fetch('/api/assets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: state.currentScan.target,
        default_profile: state.currentScan.profile,
        tags: ['LAN']
      })
    });
    if (!res.ok) {
      const err = await res.json();
      showToast(err.error || 'Failed to save asset', 'error');
      return;
    }
    showToast(`Saved ${state.currentScan.target} to Monitored Assets`, 'success');
    await fetchScanDetail(state.currentScan.id);
    await fetchAssets();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function rescanCurrentTarget() {
  if (!state.currentScan) return;
  scanSavedAsset(state.currentScan.target, state.currentScan.profile);
}

// Drift / Diff Timeline (Tab 3)
async function fetchDiffs() {
  try {
    const res = await fetch('/api/diffs?limit=100');
    if (!res.ok) return;
    state.diffs = await res.json();
    updateOverviewStats();
    renderDiffTimeline();
  } catch (err) {
    console.error('Failed to fetch diffs:', err);
  }
}

function populateDiffAssetFilter() {
  const select = document.getElementById('diff-filter-asset');
  if (!select) return;
  const currentVal = select.value || 'all';
  const options = ['<option value="all">All Assets</option>'];
  for (const a of state.assets) {
    options.push(
      `<option value="${a.id}" ${String(a.id) === String(currentVal) ? 'selected' : ''}>${escapeHtml(a.target)}${
        a.hostname ? ` (${escapeHtml(a.hostname)})` : ''
      }</option>`
    );
  }
  select.innerHTML = options.join('');
}

function renderDiffTimeline() {
  const container = document.getElementById('diff-timeline-container');
  if (!container) return;

  const assetFilter = document.getElementById('diff-filter-asset')?.value || 'all';
  const onlyChanges = document.getElementById('diff-only-changes')?.checked || false;

  const filtered = state.diffs.filter((d) => {
    if (assetFilter !== 'all' && String(d.asset_id) !== String(assetFilter)) return false;
    if (onlyChanges && !d.summary?.has_changes) return false;
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="text-center py-12 text-slate-400 text-sm">
        No drift comparisons match the current filter. Run a rescan on a monitored asset or click "Rescan &amp; Diff All".
      </div>
    `;
    return;
  }

  container.innerHTML = filtered
    .map((d) => {
      const s = d.summary || {};
      const events = renderDiffEventRows(d.target, s);

      return `
        <div class="bg-slate-950/70 border border-slate-800 rounded-xl p-4 space-y-3">
          <div class="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
            <div class="flex items-center gap-2.5">
              <span class="text-sm font-bold text-white font-mono">${escapeHtml(d.target)}</span>
              ${d.hostname ? `<span class="text-xs text-slate-400">(${escapeHtml(d.hostname)})</span>` : ''}
              <span class="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                Scan #${d.old_scan_id} → Scan #${d.new_scan_id}
              </span>
              ${
                s.has_changes
                  ? `<span class="text-xs font-semibold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">${s.total_changes} Drift Change(s)</span>`
                  : `<span class="text-xs font-medium px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">No Drift (Identical State)</span>`
              }
            </div>
            <div class="flex items-center gap-3 text-xs text-slate-400">
              <span>${escapeHtml(formatDateTime(d.created_at))} (${escapeHtml(formatRelativeTime(d.created_at))})</span>
              <button onclick="openScanInTab(${d.new_scan_id})" class="text-cyan-400 hover:text-cyan-300 font-medium">Inspect Scan #${d.new_scan_id} →</button>
            </div>
          </div>

          <div class="space-y-1.5 font-mono text-xs">
            ${events}
          </div>
        </div>
      `;
    })
    .join('');
}

function renderDiffEventRows(target, s) {
  const rows = [];

  for (const p of s.added_ports || []) {
    const svc = [p.service_name, p.service_product, p.service_version].filter(Boolean).join(' ');
    rows.push(`
      <div class="px-3 py-1.5 rounded bg-emerald-950/40 border border-emerald-700/40 text-emerald-300 flex items-center justify-between">
        <span>+ [NEW_PORT] Port ${p.port}/${escapeHtml(p.protocol)} opened on ${escapeHtml(target)} (${escapeHtml(svc || 'unknown')})</span>
        <span class="text-[10px] uppercase px-1.5 py-0.5 rounded bg-emerald-500/20">Added Port</span>
      </div>
    `);
  }

  for (const p of s.removed_ports || []) {
    const svc = [p.service_name, p.service_product, p.service_version].filter(Boolean).join(' ');
    rows.push(`
      <div class="px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-slate-300 flex items-center justify-between">
        <span>- [CLOSED_PORT] Port ${p.port}/${escapeHtml(p.protocol)} closed on ${escapeHtml(target)} (was ${escapeHtml(svc || 'open')})</span>
        <span class="text-[10px] uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">Closed Port</span>
      </div>
    `);
  }

  for (const p of s.changed_ports || []) {
    const oldB = [p.old_product, p.old_version].filter(Boolean).join(' ') || 'none';
    const newB = [p.new_product, p.new_version].filter(Boolean).join(' ') || 'none';
    rows.push(`
      <div class="px-3 py-1.5 rounded bg-amber-950/40 border border-amber-700/40 text-amber-300 flex items-center justify-between">
        <span>~ [BANNER_CHANGED] Port ${p.port}/${escapeHtml(p.protocol)} on ${escapeHtml(target)}: "${escapeHtml(oldB)}" → "${escapeHtml(newB)}"</span>
        <span class="text-[10px] uppercase px-1.5 py-0.5 rounded bg-amber-500/20">Banner Drift</span>
      </div>
    `);
  }

  for (const v of s.added_vulns || []) {
    rows.push(`
      <div class="px-3 py-1.5 rounded bg-rose-950/50 border border-rose-700/50 text-rose-200 flex items-center justify-between">
        <span>+ [NEW_VULN] [${escapeHtml((v.severity || 'info').toUpperCase())}] ${escapeHtml(v.template_id)} (${escapeHtml(v.name)}) detected at ${escapeHtml(v.matched_at || target)}</span>
        <span class="text-[10px] uppercase px-1.5 py-0.5 rounded bg-rose-500/30 text-rose-200">New Vulnerability</span>
      </div>
    `);
  }

  for (const v of s.resolved_vulns || []) {
    rows.push(`
      <div class="px-3 py-1.5 rounded bg-emerald-950/30 border border-emerald-700/30 text-emerald-300 flex items-center justify-between">
        <span>✓ [RESOLVED_VULN] [${escapeHtml((v.severity || 'info').toUpperCase())}] ${escapeHtml(v.template_id)} (${escapeHtml(v.name)}) resolved on ${escapeHtml(v.matched_at || target)}</span>
        <span class="text-[10px] uppercase px-1.5 py-0.5 rounded bg-emerald-500/20">Resolved</span>
      </div>
    `);
  }

  if (rows.length === 0) {
    return `<div class="text-slate-500 italic px-2 py-1">No port or vulnerability drift between these two consecutive scans.</div>`;
  }

  return rows.join('');
}

// ==================== TAB 4: SCAN PROFILES & PORT BUILDER ====================

async function fetchProfiles() {
  try {
    const res = await fetch('/api/profiles');
    if (!res.ok) return;
    const list = await res.json();
    const map = {};
    for (const p of list) map[p.id] = p;
    state.profiles = map;
    populateProfileDropdowns();
    renderProfilesList();
  } catch (err) {
    console.error('Failed to fetch profiles:', err);
  }
}

function appendPortsToProfile(portsStr) {
  const input = document.getElementById('prof-ports');
  const curr = input.value.trim();
  if (!curr || curr === 'top-100' || curr === 'top-1000' || curr === '1-65535' || curr === '1-10000') {
    input.value = portsStr;
    return;
  }
  const existing = new Set(curr.split(',').map((s) => s.trim()).filter(Boolean));
  for (const p of portsStr.split(',').map((s) => s.trim()).filter(Boolean)) {
    existing.add(p);
  }
  input.value = Array.from(existing).join(',');
}

function setPortsOnProfile(preset) {
  document.getElementById('prof-ports').value = preset;
}

function resetProfileForm() {
  document.getElementById('prof-edit-mode').value = 'create';
  document.getElementById('profile-form-title').textContent = 'Create Scan Profile';
  document.getElementById('prof-id').value = '';
  document.getElementById('prof-id').disabled = false;
  document.getElementById('prof-name').value = '';
  document.getElementById('prof-desc').value = '';
  document.getElementById('prof-ports').value = '80,443,8080,8443';
  document.getElementById('prof-nmap-args').value = '-sV --version-intensity 5 -T4';
  document.getElementById('prof-nuclei-sev').value = 'low,medium,high,critical';
  document.getElementById('prof-nuclei-tags').value = 'panel,exposure,misconfig,default-login';
  document.getElementById('prof-rate-limit').value = '50';
  document.getElementById('prof-auto-scan').checked = true;
  document.getElementById('prof-non-http').checked = true;
  document.getElementById('prof-enable-vulscan').checked = false;
}

function loadProfileIntoForm(profileId) {
  const p = state.profiles[profileId];
  if (!p) return;
  document.getElementById('prof-edit-mode').value = 'edit';
  document.getElementById('profile-form-title').textContent = `Edit Profile: ${p.id}`;
  document.getElementById('prof-id').value = p.id;
  document.getElementById('prof-id').disabled = true;
  document.getElementById('prof-name').value = p.name;
  document.getElementById('prof-desc').value = p.description || '';
  document.getElementById('prof-ports').value = p.ports || '80,443';
  document.getElementById('prof-nmap-args').value = p.nmap_extra_args || '-sV --version-intensity 5 -T4';
  document.getElementById('prof-nuclei-sev').value = p.nuclei_severities || 'low,medium,high,critical';
  document.getElementById('prof-nuclei-tags').value = p.nuclei_tags || 'panel,exposure,misconfig,default-login';
  document.getElementById('prof-auto-scan').checked = (p.nuclei_args || []).includes('-as');
  document.getElementById('prof-non-http').checked = Boolean(p.include_non_http_nuclei);
  document.getElementById('prof-enable-vulscan').checked = Boolean(p.enable_vulscan);
}

async function handleProfileFormSubmit(e) {
  e.preventDefault();
  const mode = document.getElementById('prof-edit-mode').value;
  const id = document.getElementById('prof-id').value.trim();
  const payload = {
    id,
    name: document.getElementById('prof-name').value.trim(),
    description: document.getElementById('prof-desc').value.trim(),
    ports: document.getElementById('prof-ports').value.trim(),
    nmap_extra_args: document.getElementById('prof-nmap-args').value.trim(),
    nuclei_severities: document.getElementById('prof-nuclei-sev').value.trim(),
    nuclei_tags: document.getElementById('prof-nuclei-tags').value.trim(),
    rate_limit: Number(document.getElementById('prof-rate-limit').value || 50),
    automatic_scan: document.getElementById('prof-auto-scan').checked,
    include_non_http_nuclei: document.getElementById('prof-non-http').checked,
    enable_vulscan: document.getElementById('prof-enable-vulscan').checked
  };

  try {
    const res = await fetch(mode === 'edit' ? `/api/profiles/${encodeURIComponent(id)}` : '/api/profiles', {
      method: mode === 'edit' ? 'PUT' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to save profile', 'error');
      return;
    }
    showToast(`Saved scan profile "${data.name}" (Ports: ${data.ports})`, 'success');
    resetProfileForm();
    await fetchProfiles();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deleteProfileById(id) {
  if (!confirm(`Delete custom scan profile "${id}"?`)) return;
  try {
    const res = await fetch(`/api/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to delete profile', 'error');
      return;
    }
    showToast(`Deleted profile ${id}`, 'info');
    await fetchProfiles();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function renderProfilesList() {
  const container = document.getElementById('profiles-list-container');
  if (!container) return;
  const list = Object.values(state.profiles);

  container.innerHTML = list
    .map((p) => {
      return `
        <div class="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col gap-2">
          <div class="flex flex-wrap items-start justify-between gap-2">
            <div>
              <div class="flex items-center gap-2">
                <span class="text-sm font-bold text-white">${escapeHtml(p.name)}</span>
                <span class="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">${escapeHtml(p.id)}</span>
                ${
                  p.is_builtin
                    ? `<span class="text-[10px] uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">Preset</span>`
                    : `<span class="text-[10px] uppercase px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">Custom</span>`
                }
                ${
                  p.enable_vulscan
                    ? `<span class="text-[10px] uppercase px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">+NSE Vulscan</span>`
                    : ''
                }
              </div>
              <p class="text-xs text-slate-400 mt-0.5">${escapeHtml(p.description || '')}</p>
            </div>
            <div class="flex items-center gap-1.5">
              <button onclick="loadProfileIntoForm('${escapeHtml(p.id)}')" class="px-2.5 py-1 rounded text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700">
                Customize / Edit Ports
              </button>
              ${
                !p.is_builtin
                  ? `<button onclick="deleteProfileById('${escapeHtml(p.id)}')" class="px-2 py-1 rounded text-xs font-medium bg-rose-950/60 hover:bg-rose-900 text-rose-300 border border-rose-800">Delete</button>`
                  : ''
              }
            </div>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 text-[11px] font-mono">
            <div class="bg-slate-900 px-2.5 py-1.5 rounded border border-slate-800/80 text-emerald-300 truncate" title="${escapeHtml(p.ports)}">
              <span class="text-slate-500">Ports:</span> ${escapeHtml(p.ports)}
            </div>
            <div class="bg-slate-900 px-2.5 py-1.5 rounded border border-slate-800/80 text-slate-300 truncate" title="${escapeHtml((p.nmap_args || []).join(' '))}">
              <span class="text-slate-500">Nmap:</span> ${escapeHtml((p.nmap_args || []).join(' '))}
            </div>
          </div>
        </div>
      `;
    })
    .join('');
}

// ==================== TAB 5: SCHEDULED RUNS, ALERTS & SYSLOG JSON ====================

function handleSchedTargetTypeChange() {
  const type = document.getElementById('sched-target-type').value;
  const valInput = document.getElementById('sched-target-value');
  if (type === 'all') {
    valInput.disabled = true;
    valInput.value = '';
    valInput.placeholder = 'All Monitored Assets';
  } else if (type === 'tag') {
    valInput.disabled = false;
    valInput.placeholder = 'Tag name (e.g. LAN, Infra)';
  } else {
    valInput.disabled = false;
    valInput.placeholder = 'Target IP or FQDN';
  }
}

async function fetchSchedules() {
  try {
    const res = await fetch('/api/schedules');
    if (!res.ok) return;
    state.schedules = await res.json();
    renderSchedulesList();
  } catch (err) {
    console.error('Failed to fetch schedules:', err);
  }
}

async function handleScheduleFormSubmit(e) {
  e.preventDefault();
  const name = document.getElementById('sched-name').value.trim();
  const target_type = document.getElementById('sched-target-type').value;
  const target_value = document.getElementById('sched-target-value').value.trim();
  const profile = document.getElementById('sched-profile').value;
  const interval_minutes = Number(document.getElementById('sched-interval').value || 1440);
  const concurrency = Number(document.getElementById('sched-concurrency').value || 3);

  try {
    const res = await fetch('/api/schedules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name,
        target_type,
        target_value,
        profile,
        interval_minutes,
        concurrency,
        enabled: true
      })
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to create schedule', 'error');
      return;
    }
    showToast(`Created schedule "${data.name}"`, 'success');
    document.getElementById('sched-name').value = '';
    await fetchSchedules();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function toggleScheduleEnabled(id, enabled) {
  try {
    await fetch(`/api/schedules/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled })
    });
    await fetchSchedules();
  } catch (_) {}
}

async function runScheduleNow(id) {
  try {
    const res = await fetch(`/api/schedules/${id}/run`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to trigger schedule', 'error');
      return;
    }
    showToast(`Triggered schedule "${data.schedule?.name}" now!`, 'success');
    await fetchSchedules();
    await refreshRecentScans();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deleteScheduleById(id) {
  if (!confirm('Delete this scheduled scan job?')) return;
  try {
    await fetch(`/api/schedules/${id}`, { method: 'DELETE' });
    await fetchSchedules();
  } catch (_) {}
}

function renderSchedulesList() {
  const container = document.getElementById('schedules-list-container');
  if (!container) return;

  if (state.schedules.length === 0) {
    container.innerHTML = `<div class="p-6 text-center text-xs text-slate-500">No scheduled scan jobs configured yet. Add one above to automate recurring audits.</div>`;
    return;
  }

  container.innerHTML = state.schedules
    .map((s) => {
      const scopeLabel =
        s.target_type === 'all'
          ? 'All Monitored Assets'
          : s.target_type === 'tag'
          ? `Tag: ${s.target_value}`
          : `Host: ${s.target_value}`;

      const freqLabel =
        s.interval_minutes === 60
          ? 'Hourly'
          : s.interval_minutes === 360
          ? 'Every 6h'
          : s.interval_minutes === 720
          ? 'Every 12h'
          : s.interval_minutes === 1440
          ? 'Daily (24h)'
          : s.interval_minutes === 10080
          ? 'Weekly (7d)'
          : `Every ${s.interval_minutes}m`;

      return `
        <div class="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div class="flex items-center gap-2">
              <span class="text-sm font-bold text-white">${escapeHtml(s.name)}</span>
              <span class="text-[11px] px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">${escapeHtml(freqLabel)}</span>
              <span class="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300">${escapeHtml(s.profile)} (${s.concurrency}x parallel)</span>
            </div>
            <div class="text-xs text-slate-400 mt-1">
              Scope: <span class="text-slate-200 font-medium">${escapeHtml(scopeLabel)}</span>
              • Last Run: <span class="text-slate-300">${escapeHtml(formatRelativeTime(s.last_run_at))}</span>
              • Next Run: <span class="text-emerald-300">${escapeHtml(s.enabled ? formatRelativeTime(s.next_run_at) : 'Paused')}</span>
            </div>
          </div>

          <div class="flex items-center gap-2">
            <label class="inline-flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer">
              <input type="checkbox" ${s.enabled ? 'checked' : ''} onchange="toggleScheduleEnabled(${s.id}, this.checked)" class="rounded bg-slate-900 border-slate-700 text-cyan-500" />
              <span>Enabled</span>
            </label>
            <button onclick="runScheduleNow(${s.id})" class="px-2.5 py-1 rounded text-xs font-semibold bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30">
              Run Now
            </button>
            <button onclick="deleteScheduleById(${s.id})" class="px-2 py-1 rounded text-xs text-rose-400 hover:bg-rose-950/50">
              Delete
            </button>
          </div>
        </div>
      `;
    })
    .join('');
}

// Syslog JSON & Alerts Config
async function fetchSyslogData() {
  try {
    const res = await fetch('/api/system/syslog');
    if (!res.ok) return;
    const data = await res.json();
    state.syslogConfig = data.config || {};
    state.syslogEvents = data.recent_events || [];
    populateSyslogForm();
    renderSyslogEvents();
  } catch (err) {
    console.error('Failed to fetch syslog data:', err);
  }
}

function populateSyslogForm() {
  const c = state.syslogConfig;
  if (!c) return;
  document.getElementById('syslog-enabled').checked = c.enabled !== false;
  document.getElementById('syslog-local').checked = c.local_syslog !== false;
  document.getElementById('syslog-remote-enabled').checked = Boolean(c.remote_enabled);
  document.getElementById('syslog-remote-host').value = c.remote_host || '';
  document.getElementById('syslog-remote-port').value = c.remote_port || 514;
  document.getElementById('syslog-remote-proto').value = c.remote_protocol || 'udp';
  document.getElementById('syslog-log-scans').checked = c.log_scans !== false;
  document.getElementById('syslog-log-ports').checked = c.log_ports !== false;
  document.getElementById('syslog-log-vulns').checked = c.log_vulns !== false;
  document.getElementById('syslog-log-diffs').checked = c.log_diffs !== false;

  document.getElementById('alert-webhook-enabled').checked = Boolean(c.webhook_enabled);
  document.getElementById('alert-webhook-url').value = c.webhook_url || '';
  document.getElementById('alert-smtp-enabled').checked = Boolean(c.smtp_enabled);
  document.getElementById('alert-smtp-to').value = c.smtp_to || '';
  document.getElementById('alert-on-new-port').checked = c.alert_on_new_port !== false;
  document.getElementById('alert-on-new-vuln').checked = c.alert_on_new_vuln !== false;
  document.getElementById('alert-min-severity').value = c.alert_min_severity || 'high';
}

async function handleSyslogFormSubmit(e) {
  e.preventDefault();
  const payload = {
    enabled: document.getElementById('syslog-enabled').checked,
    local_syslog: document.getElementById('syslog-local').checked,
    remote_enabled: document.getElementById('syslog-remote-enabled').checked,
    remote_host: document.getElementById('syslog-remote-host').value.trim(),
    remote_port: Number(document.getElementById('syslog-remote-port').value || 514),
    remote_protocol: document.getElementById('syslog-remote-proto').value,
    log_scans: document.getElementById('syslog-log-scans').checked,
    log_ports: document.getElementById('syslog-log-ports').checked,
    log_vulns: document.getElementById('syslog-log-vulns').checked,
    log_diffs: document.getElementById('syslog-log-diffs').checked,
    webhook_enabled: document.getElementById('alert-webhook-enabled').checked,
    webhook_url: document.getElementById('alert-webhook-url').value.trim(),
    smtp_enabled: document.getElementById('alert-smtp-enabled').checked,
    smtp_to: document.getElementById('alert-smtp-to').value.trim(),
    alert_on_new_port: document.getElementById('alert-on-new-port').checked,
    alert_on_new_vuln: document.getElementById('alert-on-new-vuln').checked,
    alert_min_severity: document.getElementById('alert-min-severity').value
  };

  try {
    const res = await fetch('/api/system/syslog', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to save syslog & alert config', 'error');
      return;
    }
    showToast('Saved JSON Syslog & Alert configuration', 'success');
    await fetchSyslogData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function sendTestSyslogEvent() {
  try {
    const res = await fetch('/api/system/syslog/test', { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      state.syslogEvents = data.recent_events || [];
      renderSyslogEvents();
      showToast('Emitted test JSON Syslog & Alert event!', 'success');
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function renderSyslogEvents() {
  const container = document.getElementById('syslog-events-preview');
  if (!container) return;
  if (!state.syslogEvents || state.syslogEvents.length === 0) {
    container.innerHTML = `<div class="text-slate-500">No JSON syslog events emitted in this session yet. Click "Test Syslog &amp; Alerts" or run a scan.</div>`;
    return;
  }
  container.innerHTML = state.syslogEvents
    .map((ev) => `<div class="border-b border-slate-900 pb-1 break-all">${escapeHtml(JSON.stringify(ev))}</div>`)
    .join('');
}

// Asset Add / Edit / Delete Modals
function openAddAssetModal() {
  document.getElementById('asset-modal-id').value = '';
  document.getElementById('asset-modal-title').textContent = 'Add Monitored Asset';
  document.getElementById('asset-modal-target').value = '';
  document.getElementById('asset-modal-target').disabled = false;
  document.getElementById('asset-modal-tags').value = 'LAN';
  populateProfileDropdowns();
  document.getElementById('asset-modal-profile').value = 'standard';
  document.getElementById('asset-modal').classList.remove('hidden');
}

function openEditAssetModal(assetId) {
  const asset = state.assets.find((a) => a.id === assetId);
  if (!asset) return;
  populateProfileDropdowns();
  document.getElementById('asset-modal-id').value = String(asset.id);
  document.getElementById('asset-modal-title').textContent = `Edit Asset: ${asset.target}`;
  document.getElementById('asset-modal-target').value = asset.target;
  document.getElementById('asset-modal-target').disabled = true;
  document.getElementById('asset-modal-tags').value = (asset.tags || []).join(', ');
  document.getElementById('asset-modal-profile').value = asset.default_profile || 'standard';
  document.getElementById('asset-modal').classList.remove('hidden');
}

function closeAssetModal() {
  document.getElementById('asset-modal').classList.add('hidden');
}

function addTagChip(tag) {
  const input = document.getElementById('asset-modal-tags');
  const existing = input.value
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);
  if (!existing.includes(tag)) {
    existing.push(tag);
  }
  input.value = existing.join(', ');
}

async function handleAssetModalSubmit(e) {
  e.preventDefault();
  const id = document.getElementById('asset-modal-id').value;
  const target = document.getElementById('asset-modal-target').value.trim();
  const tags = document
    .getElementById('asset-modal-tags')
    .value.split(',')
    .map((t) => t.trim())
    .filter(Boolean);
  const default_profile = document.getElementById('asset-modal-profile').value;

  try {
    let res;
    if (id) {
      res = await fetch(`/api/assets/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tags, default_profile })
      });
    } else {
      res = await fetch('/api/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, tags, default_profile })
      });
    }
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Failed to save asset', 'error');
      return;
    }
    showToast(`Saved asset ${data.target}`, 'success');
    closeAssetModal();
    await fetchAssets();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deleteAssetById(id, target) {
  if (!confirm(`Remove monitored asset ${target} and all its scan history?`)) return;
  try {
    const res = await fetch(`/api/assets/${id}`, { method: 'DELETE' });
    if (!res.ok) {
      showToast('Failed to delete asset', 'error');
      return;
    }
    showToast(`Removed asset ${target}`, 'info');
    await fetchAssets();
    await fetchDiffs();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Asset History Modal
async function openAssetHistoryModal(assetId, target) {
  document.getElementById('history-modal-title').textContent = `History & Drift — ${target}`;
  const body = document.getElementById('history-modal-body');
  body.innerHTML = `<div class="text-xs text-slate-400">Loading history...</div>`;
  document.getElementById('history-modal').classList.remove('hidden');

  try {
    const [scansRes, diffsRes] = await Promise.all([
      fetch(`/api/assets/${assetId}/scans`),
      fetch(`/api/assets/${assetId}/diffs`)
    ]);
    const scans = scansRes.ok ? await scansRes.json() : [];
    const diffs = diffsRes.ok ? await diffsRes.json() : [];

    const scansHtml =
      scans.length > 0
        ? scans
            .map(
              (s) => `
          <div class="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-2 text-xs">
            <div>
              <span class="font-mono text-cyan-400 font-bold">#${s.id}</span>
              <span class="ml-2 uppercase font-semibold text-slate-300">${escapeHtml(s.profile)}</span>
              <span class="ml-2 text-slate-400">${s.open_port_count || 0} open ports, ${s.vuln_count || 0} vulns</span>
              <span class="ml-2 text-slate-500">${escapeHtml(formatDateTime(s.started_at))}</span>
            </div>
            <div class="flex items-center gap-2">
              ${scanStatusBadge(s.status)}
              <button onclick="closeHistoryModal(); openScanInTab(${s.id})" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 font-medium">View</button>
            </div>
          </div>
        `
            )
            .join('')
        : `<div class="text-xs text-slate-500">No scans recorded for this asset yet.</div>`;

    const diffsHtml =
      diffs.length > 0
        ? diffs
            .map(
              (d) => `
          <div class="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
            <div class="flex items-center justify-between text-xs text-slate-400">
              <span class="font-mono text-white">Scan #${d.old_scan_id} → Scan #${d.new_scan_id}</span>
              <span>${escapeHtml(formatDateTime(d.created_at))}</span>
            </div>
            <div class="space-y-1 font-mono text-xs">
              ${renderDiffEventRows(target, d.summary || {})}
            </div>
          </div>
        `
            )
            .join('')
        : `<div class="text-xs text-slate-500">No consecutive scan diffs calculated for this asset yet.</div>`;

    body.innerHTML = `
      <div>
        <h4 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Scan History (${scans.length})</h4>
        <div class="space-y-2">${scansHtml}</div>
      </div>
      <div>
        <h4 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Consecutive Scan Diffs (${diffs.length})</h4>
        <div class="space-y-2">${diffsHtml}</div>
      </div>
    `;
  } catch (err) {
    body.innerHTML = `<div class="text-xs text-rose-400">Error loading history: ${escapeHtml(err.message)}</div>`;
  }
}

function closeHistoryModal() {
  document.getElementById('history-modal').classList.add('hidden');
}

// Signature & Template Updater Modal
async function openSignatureModal(autoTrigger = false) {
  document.getElementById('signature-modal').classList.remove('hidden');
  await pollSignatureStatus();
  if (autoTrigger) {
    await startSignatureUpdate();
  }
}

function closeSignatureModal() {
  document.getElementById('signature-modal').classList.add('hidden');
  if (state.sigPollTimer) {
    clearInterval(state.sigPollTimer);
    state.sigPollTimer = null;
  }
}

async function startSignatureUpdate() {
  try {
    const res = await fetch('/api/system/update-signatures', { method: 'POST' });
    const data = await res.json();
    renderSignatureModalState(data);

    if (!state.sigPollTimer) {
      state.sigPollTimer = setInterval(pollSignatureStatus, 1500);
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function pollSignatureStatus() {
  try {
    const res = await fetch('/api/system/update-signatures');
    if (!res.ok) return;
    const data = await res.json();
    state.signatures = data;
    renderSignatureModalState(data);
    updateSignatureBadges();

    if (data.status === 'running' && !state.sigPollTimer) {
      state.sigPollTimer = setInterval(pollSignatureStatus, 1500);
    } else if (data.status !== 'running' && state.sigPollTimer) {
      clearInterval(state.sigPollTimer);
      state.sigPollTimer = null;
    }
  } catch (_) {}
}

function renderSignatureModalState(data) {
  const badge = document.getElementById('sig-modal-status-badge');
  const logEl = document.getElementById('sig-modal-log');
  const btn = document.getElementById('btn-start-sig-update');

  if (data.status === 'running') {
    badge.className = 'px-2.5 py-0.5 text-xs font-semibold rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse';
    badge.textContent = 'Running Update...';
    btn.disabled = true;
    btn.classList.add('opacity-50', 'cursor-not-allowed');
  } else if (data.status === 'completed') {
    badge.className = 'px-2.5 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
    badge.textContent = 'Completed';
    btn.disabled = false;
    btn.classList.remove('opacity-50', 'cursor-not-allowed');
  } else if (data.status === 'failed') {
    badge.className = 'px-2.5 py-0.5 text-xs font-semibold rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40';
    badge.textContent = 'Completed with Warnings';
    btn.disabled = false;
    btn.classList.remove('opacity-50', 'cursor-not-allowed');
  } else {
    badge.className = 'px-2.5 py-0.5 text-xs font-semibold rounded-full bg-slate-800 text-slate-300';
    badge.textContent = 'Idle';
    btn.disabled = false;
    btn.classList.remove('opacity-50', 'cursor-not-allowed');
  }

  if (data.output_log) {
    logEl.textContent = data.output_log;
    logEl.scrollTop = logEl.scrollHeight;
  }
}

// Background Polling Loop
async function backgroundPollTick() {
  await fetchSystemStatus();
  await refreshRecentScans();

  const hasActiveScan = state.recentScans.some(
    (s) => s.status === 'queued' || s.status === 'running_nmap' || s.status === 'running_nuclei'
  );

  if (state.activeTab === 'active-scan' && state.currentScanId) {
    const curr = state.currentScan;
    if (
      hasActiveScan ||
      !curr ||
      curr.status === 'queued' ||
      curr.status === 'running_nmap' ||
      curr.status === 'running_nuclei'
    ) {
      await fetchScanDetail(state.currentScanId);
    }
  }

  if (hasActiveScan && state.activeTab === 'assets') {
    await fetchAssets();
  }
}

window.addEventListener('DOMContentLoaded', async () => {
  await Promise.all([
    fetchSystemStatus(),
    fetchProfiles(),
    fetchAssets(),
    refreshRecentScans(),
    fetchDiffs()
  ]);
  state.pollTimer = setInterval(backgroundPollTick, 2500);
});
