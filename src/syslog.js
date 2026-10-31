const dgram = require('dgram');
const net = require('net');
const os = require('os');
const http = require('http');
const https = require('https');
const { spawn } = require('child_process');
const db = require('./db');

const HOSTNAME = os.hostname() || 'nucmap';
const APP_NAME = 'nucmap';

const recentSyslogEvents = [];

function getSyslogConfig() {
  const raw = db.getSystemMeta('syslog_config');
  const defaults = {
    enabled: true,
    local_syslog: true,
    remote_enabled: false,
    remote_host: '',
    remote_port: 514,
    remote_protocol: 'udp',
    facility: 16,
    log_ports: true,
    log_vulns: true,
    log_diffs: true,
    log_scans: true,
    // Webhook & Email Alert settings
    webhook_enabled: false,
    webhook_url: '',
    smtp_enabled: false,
    smtp_to: '',
    smtp_from: `nucmap@${HOSTNAME}.local`,
    alert_on_new_port: true,
    alert_on_new_vuln: true,
    alert_min_severity: 'high' // 'critical', 'high', 'medium', 'low'
  };

  if (!raw || !raw.value) return defaults;
  try {
    return { ...defaults, ...JSON.parse(raw.value) };
  } catch (_) {
    return defaults;
  }
}

function saveSyslogConfig(newConfig) {
  const current = getSyslogConfig();
  const merged = {
    ...current,
    ...newConfig,
    enabled: Boolean(newConfig.enabled ?? current.enabled),
    local_syslog: Boolean(newConfig.local_syslog ?? current.local_syslog),
    remote_enabled: Boolean(newConfig.remote_enabled ?? current.remote_enabled),
    remote_host: String(newConfig.remote_host ?? current.remote_host).trim(),
    remote_port: parseInt(newConfig.remote_port ?? current.remote_port, 10) || 514,
    remote_protocol: newConfig.remote_protocol === 'tcp' ? 'tcp' : 'udp',
    facility: parseInt(newConfig.facility ?? current.facility, 10) || 16,
    log_ports: Boolean(newConfig.log_ports ?? current.log_ports),
    log_vulns: Boolean(newConfig.log_vulns ?? current.log_vulns),
    log_diffs: Boolean(newConfig.log_diffs ?? current.log_diffs),
    log_scans: Boolean(newConfig.log_scans ?? current.log_scans),
    webhook_enabled: Boolean(newConfig.webhook_enabled ?? current.webhook_enabled),
    webhook_url: String(newConfig.webhook_url ?? current.webhook_url).trim(),
    smtp_enabled: Boolean(newConfig.smtp_enabled ?? current.smtp_enabled),
    smtp_to: String(newConfig.smtp_to ?? current.smtp_to).trim(),
    smtp_from: String(newConfig.smtp_from ?? current.smtp_from).trim() || `nucmap@${HOSTNAME}.local`,
    alert_on_new_port: Boolean(newConfig.alert_on_new_port ?? current.alert_on_new_port),
    alert_on_new_vuln: Boolean(newConfig.alert_on_new_vuln ?? current.alert_on_new_vuln),
    alert_min_severity: String(newConfig.alert_min_severity ?? current.alert_min_severity).toLowerCase()
  };
  db.setSystemMeta('syslog_config', JSON.stringify(merged));
  return merged;
}

function mapSeverityToSyslogCode(severity) {
  const s = String(severity || 'info').toLowerCase();
  switch (s) {
    case 'critical':
      return 2;
    case 'high':
    case 'error':
      return 3;
    case 'medium':
    case 'warning':
    case 'warn':
      return 4;
    case 'low':
    case 'notice':
      return 5;
    case 'info':
    default:
      return 6;
  }
}

function severityRank(sev) {
  const s = String(sev || 'info').toLowerCase();
  if (s === 'critical') return 4;
  if (s === 'high') return 3;
  if (s === 'medium') return 2;
  if (s === 'low') return 1;
  return 0;
}

function sendLocalSyslog(severityCode, jsonString) {
  const pri = `local0.${
    severityCode <= 2
      ? 'crit'
      : severityCode === 3
      ? 'err'
      : severityCode === 4
      ? 'warning'
      : severityCode === 5
      ? 'notice'
      : 'info'
  }`;

  try {
    const child = spawn('/usr/bin/logger', ['-t', APP_NAME, '-p', pri, '--', jsonString], {
      shell: false,
      stdio: 'ignore'
    });
    child.on('error', () => {
      console.log(`[SYSLOG-JSON] ${jsonString}`);
    });
  } catch (_) {
    console.log(`[SYSLOG-JSON] ${jsonString}`);
  }
}

function sendRemoteSyslog(config, pri, timestamp, jsonString) {
  if (!config.remote_enabled || !config.remote_host) return;
  const syslogLine = `<${pri}>1 ${timestamp} ${HOSTNAME} ${APP_NAME} ${process.pid} - - ${jsonString}`;

  if (config.remote_protocol === 'tcp') {
    const client = new net.Socket();
    client.setTimeout(3000);
    client.connect(config.remote_port, config.remote_host, () => {
      client.write(syslogLine + '\n', () => {
        client.end();
      });
    });
    client.on('error', () => client.destroy());
    client.on('timeout', () => client.destroy());
  } else {
    const client = dgram.createSocket('udp4');
    const buf = Buffer.from(syslogLine, 'utf8');
    client.send(buf, 0, buf.length, config.remote_port, config.remote_host, () => {
      client.close();
    });
    client.on('error', () => {
      try {
        client.close();
      } catch (_) {}
    });
  }
}

// Send HTTP/HTTPS Webhook (compatible with Slack, Discord, Ntfy, Gotify, Home Assistant, Generic JSON)
function dispatchWebhookAlert(webhookUrl, title, message, record) {
  if (!webhookUrl) return;
  try {
    const u = new URL(webhookUrl);
    const bodyObj = {
      title,
      text: `${title}\n${message}`,
      content: `**${title}**\n${message}`,
      message,
      event: record
    };
    const bodyStr = JSON.stringify(bodyObj);
    const mod = u.protocol === 'https:' ? https : http;

    const req = mod.request(
      {
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr),
          Title: title
        },
        timeout: 5000
      },
      (res) => {
        res.resume();
      }
    );
    req.on('error', () => {});
    req.on('timeout', () => req.destroy());
    req.write(bodyStr);
    req.end();
  } catch (_) {}
}

// Send Local SMTP Email via 127.0.0.1:25 (Postfix)
function dispatchLocalSmtpAlert(fromAddr, toAddr, subject, bodyText) {
  if (!toAddr) return;
  try {
    const client = new net.Socket();
    client.setTimeout(5000);
    let step = 0;

    client.connect(25, '127.0.0.1', () => {});

    client.on('data', (chunk) => {
      const line = chunk.toString('utf8');
      if (step === 0 && line.startsWith('220')) {
        step = 1;
        client.write(`HELO ${HOSTNAME}\r\n`);
      } else if (step === 1 && line.startsWith('250')) {
        step = 2;
        client.write(`MAIL FROM:<${fromAddr}>\r\n`);
      } else if (step === 2 && line.startsWith('250')) {
        step = 3;
        client.write(`RCPT TO:<${toAddr}>\r\n`);
      } else if (step === 3 && line.startsWith('250')) {
        step = 4;
        client.write('DATA\r\n');
      } else if (step === 4 && line.startsWith('354')) {
        step = 5;
        const msg = [
          `From: NucMap ASM <${fromAddr}>`,
          `To: <${toAddr}>`,
          `Subject: ${subject}`,
          `Date: ${new Date().toUTCString()}`,
          'Content-Type: text/plain; charset=utf-8',
          '',
          bodyText,
          '.',
          'QUIT',
          ''
        ].join('\r\n');
        client.write(msg);
      } else if (step === 5) {
        client.end();
      }
    });

    client.on('error', () => client.destroy());
    client.on('timeout', () => client.destroy());
  } catch (_) {}
}

function maybeSendExternalAlert(config, eventType, payload, severity, record) {
  if (!config.webhook_enabled && !config.smtp_enabled) return;

  let shouldAlert = false;
  let subject = '';
  let text = '';

  if (eventType === 'SYSLOG_TEST') {
    shouldAlert = true;
    subject = `[NucMap] Test Alert & JSON Syslog Verified`;
    text = `NucMap on ${HOSTNAME} successfully dispatched a test alert at ${record.timestamp}.`;
  } else if (eventType === 'DRIFT_DETECTED') {
    const dt = payload.drift_type;
    const d = payload.details || {};
    if (dt === 'NEW_PORT' && config.alert_on_new_port) {
      shouldAlert = true;
      subject = `[NucMap Drift] New Open Port ${d.port}/${d.protocol} on ${payload.target}`;
      text = `Target: ${payload.target}\nEvent: NEW_PORT\nPort: ${d.port}/${d.protocol} (${d.service_name || ''} ${d.service_product || ''} ${d.service_version || ''})\nScan: #${payload.scan_id}`;
    } else if (dt === 'NEW_VULN' && config.alert_on_new_vuln) {
      if (severityRank(d.severity) >= severityRank(config.alert_min_severity)) {
        shouldAlert = true;
        subject = `[NucMap Vuln] [${String(d.severity).toUpperCase()}] ${d.template_id} on ${payload.target}`;
        text = `Target: ${payload.target}\nFinding: ${d.name} (${d.template_id})\nSeverity: ${String(d.severity).toUpperCase()}\nMatched At: ${d.matched_at || payload.target}\nScan: #${payload.scan_id}`;
      }
    }
  }

  if (!shouldAlert) return;

  if (config.webhook_enabled && config.webhook_url) {
    dispatchWebhookAlert(config.webhook_url, subject, text, record);
  }
  if (config.smtp_enabled && config.smtp_to) {
    dispatchLocalSmtpAlert(config.smtp_from, config.smtp_to, subject, text);
  }
}

function logEvent(eventType, payload = {}, severity = 'info') {
  const config = getSyslogConfig();

  const timestamp = new Date().toISOString();
  const record = {
    timestamp,
    host: HOSTNAME,
    app: APP_NAME,
    event_type: eventType,
    severity: String(severity || 'info').toLowerCase(),
    ...payload
  };

  const jsonString = JSON.stringify(record);

  recentSyslogEvents.unshift(record);
  if (recentSyslogEvents.length > 200) {
    recentSyslogEvents.pop();
  }

  maybeSendExternalAlert(config, eventType, payload, severity, record);

  if (!config.enabled) return record;

  if (eventType.startsWith('SCAN_') && !config.log_scans) return record;
  if (eventType === 'PORT_DISCOVERED' && !config.log_ports) return record;
  if (eventType === 'VULN_FOUND' && !config.log_vulns) return record;
  if (eventType === 'DRIFT_DETECTED' && !config.log_diffs) return record;

  const sevCode = mapSeverityToSyslogCode(severity);
  const facility = config.facility || 16;
  const pri = facility * 8 + sevCode;

  if (config.local_syslog) {
    sendLocalSyslog(sevCode, jsonString);
  }

  if (config.remote_enabled && config.remote_host) {
    sendRemoteSyslog(config, pri, timestamp, jsonString);
  }

  return record;
}

function getRecentSyslogEvents(limit = 50) {
  return recentSyslogEvents.slice(0, limit);
}

module.exports = {
  getSyslogConfig,
  saveSyslogConfig,
  logEvent,
  getRecentSyslogEvents
};
