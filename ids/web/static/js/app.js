/**
 * AEGIS // Network IDS - Cyber Defense SOC Console
 * Real-time event streaming, Canvas analytics, forensics triage & rule tuner.
 */

(() => {
  'use strict';

  // State
  const state = {
    events: [],
    summary: {
      total_events: 0,
      by_severity: {},
      by_type: {},
      top_sources: []
    },
    filter: {
      search: '',
      severity: '',
      type: ''
    },
    audioEnabled: true,
    isStreamPaused: false,
    sseConnection: null,
    audioCtx: null,
    targetUrl: localStorage.getItem('ids_target_url') || ''
  };

  // Helper for remote backend URL routing
  function apiUrl(path) {
    if (!state.targetUrl) return path;
    const base = state.targetUrl.replace(/\/+$/, '');
    return `${base}${path}`;
  }

  // DOM Elements
  const el = {
    clock: document.getElementById('live-clock'),
    sseStatus: document.getElementById('sse-status-pill'),
    btnChangeTarget: document.getElementById('btn-change-target'),
    hudTargetUrl: document.getElementById('hud-target-url'),
    totalCount: document.getElementById('stat-total-count'),
    criticalCount: document.getElementById('stat-critical-count'),
    highCount: document.getElementById('stat-high-count'),
    barCritical: document.getElementById('bar-critical'),
    barHigh: document.getElementById('bar-high'),
    tbody: document.getElementById('incident-tbody'),
    streamBadge: document.getElementById('incident-stream-badge'),
    topSources: document.getElementById('top-sources-container'),
    canvasVectors: document.getElementById('canvas-vectors'),
    canvasSeverity: document.getElementById('canvas-severity'),
    filterSearch: document.getElementById('filter-search'),
    filterSeverity: document.getElementById('filter-severity'),
    filterType: document.getElementById('filter-type'),
    btnSimulate: document.getElementById('btn-simulate'),
    btnConfig: document.getElementById('btn-config'),
    btnClear: document.getElementById('btn-clear-db'),
    btnPause: document.getElementById('btn-pause-stream'),
    btnAudio: document.getElementById('btn-audio-toggle'),
    iconSoundOn: document.getElementById('icon-sound-on'),
    iconSoundOff: document.getElementById('icon-sound-off'),
    toastContainer: document.getElementById('toast-container'),
    // Modals
    forensicsModal: document.getElementById('forensics-modal'),
    forensicBody: document.getElementById('forensic-body'),
    btnCloseForensic: document.getElementById('btn-close-forensic'),
    configModal: document.getElementById('config-modal'),
    btnCloseConfig: document.getElementById('btn-close-config'),
    btnCancelConfig: document.getElementById('btn-cancel-config'),
    btnSaveConfig: document.getElementById('btn-save-config'),
    // Config fields
    cfgPsPorts: document.getElementById('cfg-ps-ports'),
    cfgPsWindow: document.getElementById('cfg-ps-window'),
    cfgUdpPorts: document.getElementById('cfg-udp-ports'),
    cfgUdpWindow: document.getElementById('cfg-udp-window'),
    cfgSynThresh: document.getElementById('cfg-syn-thresh'),
    cfgSynWindow: document.getElementById('cfg-syn-window'),
    cfgAlertMin: document.getElementById('cfg-alert-min'),
    cfgAlertDedup: document.getElementById('cfg-alert-dedup'),
    cfgAlertRate: document.getElementById('cfg-alert-rate')
  };

  // ---------------------------------------------------------------------------
  // Audio Synthesizer (Zero External Audio Files)
  // ---------------------------------------------------------------------------
  function playAlertChime(severity) {
    if (!state.audioEnabled) return;
    try {
      if (!state.audioCtx) {
        state.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      }
      if (state.audioCtx.state === 'suspended') {
        state.audioCtx.resume();
      }

      const ctx = state.audioCtx;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      const now = ctx.currentTime;

      if (severity === 'CRITICAL') {
        // High urgency 2-tone pulse
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, now);
        osc.frequency.setValueAtTime(1174.66, now + 0.1);
        gain.gain.setValueAtTime(0.2, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
        osc.start(now);
        osc.stop(now + 0.35);
      } else if (severity === 'HIGH') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(659.25, now);
        gain.gain.setValueAtTime(0.15, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
        osc.start(now);
        osc.stop(now + 0.25);
      } else {
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(440, now);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
        osc.start(now);
        osc.stop(now + 0.15);
      }
    } catch (e) {
      console.warn('Audio chime warning:', e);
    }
  }

  // ---------------------------------------------------------------------------
  // Clock HUD
  // ---------------------------------------------------------------------------
  function initClock() {
    function update() {
      const now = new Date();
      el.clock.textContent = now.toTimeString().split(' ')[0] + ' UTC';
    }
    update();
    setInterval(update, 1000);
  }

  // ---------------------------------------------------------------------------
  // Toasts
  // ---------------------------------------------------------------------------
  function showToast(title, msg, severity = 'LOW') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${severity}`;
    toast.innerHTML = `
      <div>
        <div class="toast-title">${escapeHtml(title)}</div>
        <div class="toast-msg">${escapeHtml(msg)}</div>
      </div>
      <button class="modal-close" style="font-size:1.2rem;">&times;</button>
    `;

    toast.querySelector('button').addEventListener('click', () => toast.remove());
    el.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }

  // ---------------------------------------------------------------------------
  // Data Fetching & Rendering
  // ---------------------------------------------------------------------------
  async function fetchSummary() {
    try {
      const res = await fetch(apiUrl('/api/summary'));
      if (!res.ok) return;
      const data = await res.json();
      state.summary = data;
      renderKPIs();
      renderVectorChart();
      renderSeverityDonut();
      renderTopSources();
    } catch (e) {
      console.error('Failed to fetch summary:', e);
    }
  }

  async function fetchEvents() {
    try {
      const res = await fetch(apiUrl('/api/events?limit=100'));
      if (!res.ok) return;
      const data = await res.json();
      state.events = data.events || [];
      renderTable();
    } catch (e) {
      console.error('Failed to fetch events:', e);
    }
  }

  function renderKPIs() {
    const total = state.summary.total_events || 0;
    const sev = state.summary.by_severity || {};
    const crit = sev['CRITICAL'] || 0;
    const high = sev['HIGH'] || 0;

    animateCounter(el.totalCount, total);
    animateCounter(el.criticalCount, crit);
    animateCounter(el.highCount, high);

    const critPct = total > 0 ? Math.min(100, (crit / total) * 100) : 0;
    const highPct = total > 0 ? Math.min(100, (high / total) * 100) : 0;

    el.barCritical.style.width = `${critPct}%`;
    el.barHigh.style.width = `${highPct}%`;
  }

  function animateCounter(elem, target) {
    const start = parseInt(elem.textContent) || 0;
    if (start === target) return;
    const duration = 400;
    const startTime = performance.now();

    function step(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const val = Math.floor(start + (target - start) * progress);
      elem.textContent = val.toLocaleString();
      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        elem.textContent = target.toLocaleString();
      }
    }
    requestAnimationFrame(step);
  }

  function renderTopSources() {
    const sources = state.summary.top_sources || [];
    if (!sources.length) {
      el.topSources.innerHTML = '<div class="empty-state">No malicious sources logged yet. Run simulation to generate traffic.</div>';
      return;
    }

    const maxCount = Math.max(...sources.map(s => s.count), 1);
    el.topSources.innerHTML = sources.map(s => {
      const pct = Math.round((s.count / maxCount) * 100);
      return `
        <div class="source-item">
          <div class="source-info">
            <span class="source-ip">${escapeHtml(s.source_ip)}</span>
            <span class="source-count">${s.count} alerts</span>
          </div>
          <div class="source-bar">
            <div class="source-fill" style="width: ${pct}%"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  // ---------------------------------------------------------------------------
  // Canvas Charts (Zero External Dependencies)
  // ---------------------------------------------------------------------------
  function renderVectorChart() {
    const canvas = el.canvasVectors;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);

    const getCount = (keys) => keys.reduce((sum, k) => sum + (counts[k] || 0), 0);
    const types = [
      { keys: ['TCP_PORT_SCAN', 'PORT_SCAN'], label: 'Port Scan', color: '#00f2fe' },
      { keys: ['UDP_PORT_SCAN', 'UDP_SCAN'], label: 'UDP Probe', color: '#38bdf8' },
      { keys: ['TCP_SYN_FLOOD', 'SYN_FLOOD'], label: 'SYN Flood', color: '#ff0055' },
      { keys: ['ARP_SPOOFING', 'ARP_SPOOF'], label: 'ARP Spoof', color: '#f59e0b' },
      { keys: ['DNS_TUNNELING', 'DNS_NXDOMAIN_BURST', 'DNS_ANOMALY'], label: 'DNS Anomaly', color: '#a855f7' }
    ];

    const counts = state.summary.by_type || {};
    const maxVal = Math.max(...types.map(t => getCount(t.keys)), 10);

    const paddingX = 40;
    const paddingBottom = 40;
    const chartHeight = height - paddingBottom - 20;
    const barWidth = 36;
    const spacing = (width - paddingX * 2) / types.length;

    // Draw gridlines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = height - paddingBottom - (chartHeight / 4) * i;
      ctx.beginPath();
      ctx.moveTo(paddingX, y);
      ctx.lineTo(width - paddingX, y);
      ctx.stroke();

      // Axis label
      ctx.fillStyle = '#64748b';
      ctx.font = '10px JetBrains Mono';
      ctx.textAlign = 'right';
      ctx.fillText(Math.round((maxVal / 4) * i), paddingX - 8, y + 3);
    }

    // Draw Bars
    types.forEach((t, idx) => {
      const val = getCount(t.keys);
      const barH = (val / maxVal) * chartHeight;
      const x = paddingX + idx * spacing + (spacing - barWidth) / 2;
      const y = height - paddingBottom - barH;

      // Glow effect
      ctx.shadowColor = t.color;
      ctx.shadowBlur = val > 0 ? 10 : 0;

      // Bar fill gradient
      const grad = ctx.createLinearGradient(0, y, 0, y + barH);
      grad.addColorStop(0, t.color);
      grad.addColorStop(1, 'rgba(10, 20, 40, 0.3)');
      ctx.fillStyle = grad;

      // Rounded top bar
      ctx.beginPath();
      const r = Math.min(6, barH);
      ctx.roundRect ? ctx.roundRect(x, y, barWidth, barH, [r, r, 0, 0]) : ctx.rect(x, y, barWidth, barH);
      ctx.fill();

      // Reset shadow
      ctx.shadowBlur = 0;

      // Value label on top
      if (val > 0) {
        ctx.fillStyle = '#f8fafc';
        ctx.font = 'bold 11px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.fillText(val, x + barWidth / 2, y - 6);
      }

      // Category label at bottom
      ctx.fillStyle = '#94a3b8';
      ctx.font = '11px Outfit';
      ctx.textAlign = 'center';
      ctx.fillText(t.label, x + barWidth / 2, height - paddingBottom + 20);
    });
  }

  function renderSeverityDonut() {
    const canvas = el.canvasSeverity;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);

    const counts = state.summary.by_severity || {};
    const segments = [
      { label: 'Critical', val: counts['CRITICAL'] || 0, color: '#ff0055' },
      { label: 'High', val: counts['HIGH'] || 0, color: '#f59e0b' },
      { label: 'Medium', val: counts['MEDIUM'] || 0, color: '#eab308' },
      { label: 'Low', val: counts['LOW'] || 0, color: '#00f2fe' }
    ];

    const total = segments.reduce((sum, s) => sum + s.val, 0);
    const cx = width / 2;
    const cy = height / 2;
    const radius = 80;
    const innerRadius = 55;

    if (total === 0) {
      // Empty ring
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
      ctx.lineWidth = radius - innerRadius;
      ctx.beginPath();
      ctx.arc(cx, cy, (radius + innerRadius) / 2, 0, Math.PI * 2);
      ctx.stroke();

      ctx.fillStyle = '#64748b';
      ctx.font = '12px Outfit';
      ctx.textAlign = 'center';
      ctx.fillText('No alerts', cx, cy + 4);
      return;
    }

    let startAngle = -Math.PI / 2;
    segments.forEach(s => {
      if (s.val === 0) return;
      const sliceAngle = (s.val / total) * Math.PI * 2;
      const endAngle = startAngle + sliceAngle;

      ctx.save();
      ctx.shadowColor = s.color;
      ctx.shadowBlur = 8;

      ctx.beginPath();
      ctx.arc(cx, cy, radius, startAngle, endAngle);
      ctx.arc(cx, cy, innerRadius, endAngle, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = s.color;
      ctx.fill();
      ctx.restore();

      startAngle = endAngle;
    });

    // Center text: Total Count
    ctx.fillStyle = '#f8fafc';
    ctx.font = 'bold 22px JetBrains Mono';
    ctx.textAlign = 'center';
    ctx.fillText(total, cx, cy + 3);

    ctx.fillStyle = '#64748b';
    ctx.font = '10px Outfit';
    ctx.fillText('TOTAL', cx, cy + 18);
  }

  // ---------------------------------------------------------------------------
  // Incident Table & Filters
  // ---------------------------------------------------------------------------
  function renderTable() {
    const query = state.filter.search.toLowerCase();
    const filterSev = state.filter.severity;
    const filterType = state.filter.type;

    const filtered = state.events.filter(ev => {
      if (filterSev && ev.severity !== filterSev) return false;
      if (filterType && ev.event_type !== filterType) return false;
      if (query) {
        const text = `${ev.source_ip || ''} ${ev.destination_ip || ''} ${ev.event_type || ''} ${ev.description || ''} ${ev.detector || ''}`.toLowerCase();
        if (!text.includes(query)) return false;
      }
      return true;
    });

    el.streamBadge.textContent = `${filtered.length} / ${state.events.length} EVENTS`;

    if (!filtered.length) {
      el.tbody.innerHTML = `
        <tr class="empty-row">
          <td colspan="7">
            <div class="table-empty">
              <div class="pulse-radar-loader"></div>
              <div class="empty-text">No matching security events found.</div>
              <div class="empty-hint">Try adjusting search filters or simulate network traffic.</div>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    el.tbody.innerHTML = filtered.map(ev => {
      const timeStr = formatTimestamp(ev.timestamp);
      return `
        <tr class="${ev._isNew ? 'row-new' : ''}">
          <td class="font-mono" style="color: #94a3b8;">${timeStr}</td>
          <td><span class="badge badge-${ev.severity}">${ev.severity}</span></td>
          <td style="font-weight: 600;">${formatThreatType(ev.event_type)}</td>
          <td class="font-mono text-cyan" style="color: var(--accent-cyan); font-weight:600;">${escapeHtml(ev.source_ip || 'N/A')}</td>
          <td class="font-mono" style="color: #cbd5e1;">${escapeHtml(ev.destination_ip || 'Broadcast')}</td>
          <td style="max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(ev.description || '')}">
            ${escapeHtml(ev.description || 'Threat detected')}
          </td>
          <td style="text-align: center;">
            <button class="btn btn-secondary btn-sm" onclick="window.inspectForensics('${ev.id || ev.timestamp}')">
              Inspect
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function formatTimestamp(ts) {
    if (!ts) return 'N/A';
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString() + '.' + String(d.getMilliseconds()).padStart(3, '0');
    } catch {
      return ts.slice(11, 23);
    }
  }

  function formatThreatType(type) {
    const map = {
      'TCP_PORT_SCAN': 'TCP Port Scan',
      'PORT_SCAN': 'TCP Port Scan',
      'UDP_SCAN': 'UDP Port Probe',
      'UDP_PORT_SCAN': 'UDP Port Probe',
      'SYN_FLOOD': 'TCP SYN Flood',
      'TCP_SYN_FLOOD': 'TCP SYN Flood',
      'ARP_SPOOF': 'ARP Cache Poison',
      'ARP_SPOOFING': 'ARP Cache Poison',
      'DNS_ANOMALY': 'DNS Anomaly',
      'DNS_TUNNELING': 'DNS Tunneling C2',
      'DNS_NXDOMAIN_BURST': 'DNS NXDOMAIN Burst'
    };
    return map[type] || type;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, m => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[m]);
  }

  // ---------------------------------------------------------------------------
  // Server-Sent Events (SSE) Live Feed
  // ---------------------------------------------------------------------------
  function initSSE() {
    if (state.sseConnection) {
      state.sseConnection.close();
    }

    el.sseStatus.textContent = 'CONNECTING...';
    el.sseStatus.style.color = '#f59e0b';

    const source = new EventSource(apiUrl('/api/events/stream'));
    state.sseConnection = source;

    source.onopen = () => {
      el.sseStatus.textContent = 'LIVE FEED';
      el.sseStatus.style.color = '#10b981';
    };

    source.onmessage = (e) => {
      if (!e.data || e.data.startsWith(':')) return; // ignore comments
      try {
        const event = JSON.parse(e.data);
        handleIncomingEvent(event);
      } catch (err) {
        console.warn('Error parsing incoming SSE:', err);
      }
    };

    source.onerror = () => {
      el.sseStatus.textContent = 'RECONNECTING';
      el.sseStatus.style.color = '#ff0055';
    };
  }

  function handleIncomingEvent(event) {
    event._isNew = true;
    if (!state.isStreamPaused) {
      state.events.unshift(event);
      if (state.events.length > 300) {
        state.events.pop();
      }
      renderTable();
    }

    // Refresh summary metrics
    fetchSummary();

    // Trigger audio chime
    playAlertChime(event.severity);

    // Toast notification for critical/high threats
    if (event.severity === 'CRITICAL' || event.severity === 'HIGH') {
      showToast(
        `🚨 ${event.event_type} (${event.severity})`,
        `Source: ${event.source_ip || 'Unknown'} -> ${event.description || ''}`,
        event.severity
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Forensics Inspector Modal
  // ---------------------------------------------------------------------------
  window.inspectForensics = function(identifier) {
    const ev = state.events.find(e => (e.id && String(e.id) === String(identifier)) || e.timestamp === identifier);
    if (!ev) return;

    const evidenceJson = JSON.stringify(ev.evidence || {}, null, 2);

    el.forensicBody.innerHTML = `
      <div class="forensic-metric-grid">
        <div class="forensic-metric">
          <div class="forensic-label">THREAT TYPE</div>
          <div class="forensic-val" style="color:var(--accent-cyan);">${formatThreatType(ev.event_type)}</div>
        </div>
        <div class="forensic-metric">
          <div class="forensic-label">SEVERITY LEVEL</div>
          <div class="forensic-val"><span class="badge badge-${ev.severity}">${ev.severity}</span></div>
        </div>
        <div class="forensic-metric">
          <div class="forensic-label">SOURCE ATTACKER IP</div>
          <div class="forensic-val font-mono" style="color:#38bdf8;">${escapeHtml(ev.source_ip || 'Unknown')}</div>
        </div>
        <div class="forensic-metric">
          <div class="forensic-label">TARGET DESTINATION IP</div>
          <div class="forensic-val font-mono">${escapeHtml(ev.destination_ip || 'Broadcast')}</div>
        </div>
      </div>

      <div class="forensic-metric">
        <div class="forensic-label">DETECTOR ENGINE</div>
        <div class="forensic-val">${escapeHtml(ev.detector)}</div>
      </div>

      <div class="forensic-metric">
        <div class="forensic-label">INCIDENT SUMMARY</div>
        <div class="forensic-val">${escapeHtml(ev.description)}</div>
      </div>

      <div>
        <div class="forensic-label" style="margin-bottom:6px;">DEEP PACKET EVIDENCE & TELEMETRY (JSON)</div>
        <div class="forensic-json-box">${escapeHtml(evidenceJson)}</div>
      </div>
    `;

    el.forensicsModal.classList.remove('hidden');
  };

  function closeForensics() {
    el.forensicsModal.classList.add('hidden');
  }

  // ---------------------------------------------------------------------------
  // Rule Configuration Modal
  // ---------------------------------------------------------------------------
  async function openConfigModal() {
    try {
      const res = await fetch(apiUrl('/api/config'));
      if (!res.ok) return;
      const cfg = await res.json();

      if (cfg.port_scan) {
        el.cfgPsPorts.value = cfg.port_scan.unique_ports || 15;
        el.cfgPsWindow.value = cfg.port_scan.window_seconds || 5;
      }
      if (cfg.udp_scan) {
        el.cfgUdpPorts.value = cfg.udp_scan.unique_ports || 10;
        el.cfgUdpWindow.value = cfg.udp_scan.window_seconds || 5;
      }
      if (cfg.syn_flood) {
        el.cfgSynThresh.value = cfg.syn_flood.syn_threshold || 100;
        el.cfgSynWindow.value = cfg.syn_flood.window_seconds || 3;
      }
      if (cfg.alerts) {
        el.cfgAlertMin.value = cfg.alerts.min_severity || 'LOW';
        el.cfgAlertDedup.value = cfg.alerts.dedup_window_seconds || 2.0;
        el.cfgAlertRate.value = cfg.alerts.max_rate_per_minute || 500;
      }

      el.configModal.classList.remove('hidden');
    } catch (e) {
      showToast('Error', 'Failed to load configuration rules.', 'HIGH');
    }
  }

  function closeConfigModal() {
    el.configModal.classList.add('hidden');
  }

  async function saveConfig() {
    try {
      const currentRes = await fetch(apiUrl('/api/config'));
      const cfg = currentRes.ok ? await currentRes.json() : {};

      cfg.port_scan = {
        enabled: true,
        unique_ports: parseInt(el.cfgPsPorts.value) || 15,
        window_seconds: parseFloat(el.cfgPsWindow.value) || 5
      };
      cfg.udp_scan = {
        enabled: true,
        unique_ports: parseInt(el.cfgUdpPorts.value) || 10,
        window_seconds: parseFloat(el.cfgUdpWindow.value) || 5
      };
      cfg.syn_flood = {
        enabled: true,
        syn_threshold: parseInt(el.cfgSynThresh.value) || 100,
        window_seconds: parseFloat(el.cfgSynWindow.value) || 3
      };
      cfg.alerts = {
        min_severity: el.cfgAlertMin.value,
        dedup_window_seconds: parseFloat(el.cfgAlertDedup.value) || 2.0,
        max_rate_per_minute: parseInt(el.cfgAlertRate.value) || 500
      };

      const saveRes = await fetch(apiUrl('/api/config'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg)
      });

      if (saveRes.ok) {
        showToast('Success', 'IDS detection rules updated and saved!', 'LOW');
        closeConfigModal();
      } else {
        showToast('Error', 'Failed to save detection rules.', 'HIGH');
      }
    } catch (e) {
      showToast('Error', 'Network error while saving rules.', 'HIGH');
    }
  }

  // ---------------------------------------------------------------------------
  // Action Handlers (Simulate, Clear DB, Sound Toggle)
  // ---------------------------------------------------------------------------
  async function triggerSimulation() {
    el.btnSimulate.disabled = true;
    el.btnSimulate.innerHTML = '<span class="pulse-dot"></span> Replaying PCAP...';

    showToast('Simulation Initiated', 'Replaying multi-vector attack traffic in background...', 'LOW');

    try {
      const res = await fetch(apiUrl('/api/simulate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pcap: 'samples/multi_vector_attack.pcap' })
      });
      const data = await res.json();
      if (!res.ok) {
        showToast('Simulation Error', data.error || 'Failed to start simulation', 'HIGH');
      }
    } catch (e) {
      showToast('Simulation Error', 'Failed to connect to simulation runner', 'HIGH');
    } finally {
      setTimeout(() => {
        el.btnSimulate.disabled = false;
        el.btnSimulate.innerHTML = `
          <svg class="btn-icon" viewBox="0 0 24 24" fill="currentColor">
            <polygon points="5 3 19 12 5 21 5 3"/>
          </svg>
          <span>Simulate Attack</span>
        `;
      }, 3000);
    }
  }

  async function clearDatabase() {
    if (!confirm('Are you sure you want to purge all historical security events from the database?')) {
      return;
    }
    try {
      const res = await fetch(apiUrl('/api/clear'), { method: 'POST' });
      if (res.ok) {
        state.events = [];
        showToast('Database Purged', 'All security events cleared.', 'LOW');
        fetchSummary();
        renderTable();
      }
    } catch (e) {
      showToast('Error', 'Failed to clear database.', 'HIGH');
    }
  }

  function toggleAudio() {
    state.audioEnabled = !state.audioEnabled;
    el.iconSoundOn.classList.toggle('hidden', !state.audioEnabled);
    el.iconSoundOff.classList.toggle('hidden', state.audioEnabled);
    showToast('Audio Alert', state.audioEnabled ? 'Sound notifications enabled' : 'Sound notifications muted', 'LOW');
  }

  function togglePauseStream() {
    state.isStreamPaused = !state.isStreamPaused;
    el.btnPause.innerHTML = state.isStreamPaused ? '<span>▶️ Resume</span>' : '<span>⏸️ Pause</span>';
  }

  function changeTarget() {
    const current = state.targetUrl || 'LOCAL (same host)';
    const next = prompt('Enter remote Linux IDS Sensor address (e.g. http://192.168.1.50:8080) or leave empty for LOCAL:', state.targetUrl || '');
    if (next !== null) {
      const trimmed = next.trim().replace(/\/+$/, '');
      if (!trimmed || trimmed === window.location.origin) {
        state.targetUrl = '';
        localStorage.removeItem('ids_target_url');
        if (el.hudTargetUrl) el.hudTargetUrl.textContent = 'LOCAL';
      } else {
        state.targetUrl = trimmed;
        localStorage.setItem('ids_target_url', trimmed);
        if (el.hudTargetUrl) el.hudTargetUrl.textContent = trimmed.replace(/^https?:\/\//, '');
      }
      showToast('Sensor Target Changed', `Now connecting to: ${state.targetUrl || 'LOCAL'}`, 'LOW');
      fetchSummary();
      fetchEvents();
      initSSE();
    }
  }

  // ---------------------------------------------------------------------------
  // Event Listeners Initialization
  // ---------------------------------------------------------------------------
  function initListeners() {
    if (el.btnChangeTarget) el.btnChangeTarget.addEventListener('click', changeTarget);

    el.filterSearch.addEventListener('input', (e) => {
      state.filter.search = e.target.value;
      renderTable();
    });

    el.filterSeverity.addEventListener('change', (e) => {
      state.filter.severity = e.target.value;
      renderTable();
    });

    el.filterType.addEventListener('change', (e) => {
      state.filter.type = e.target.value;
      renderTable();
    });

    el.btnSimulate.addEventListener('click', triggerSimulation);
    el.btnConfig.addEventListener('click', openConfigModal);
    el.btnClear.addEventListener('click', clearDatabase);
    el.btnAudio.addEventListener('click', toggleAudio);
    el.btnPause.addEventListener('click', togglePauseStream);

    el.btnCloseForensic.addEventListener('click', closeForensics);
    el.forensicsModal.addEventListener('click', (e) => {
      if (e.target === el.forensicsModal) closeForensics();
    });

    el.btnCloseConfig.addEventListener('click', closeConfigModal);
    el.btnCancelConfig.addEventListener('click', closeConfigModal);
    el.btnSaveConfig.addEventListener('click', saveConfig);
    el.configModal.addEventListener('click', (e) => {
      if (e.target === el.configModal) closeConfigModal();
    });

    // Resize listener to re-draw canvas charts
    window.addEventListener('resize', () => {
      renderVectorChart();
      renderSeverityDonut();
    });
  }

  // ---------------------------------------------------------------------------
  // App Bootstrapper
  // ---------------------------------------------------------------------------
  function init() {
    if (state.targetUrl && el.hudTargetUrl) {
      el.hudTargetUrl.textContent = state.targetUrl.replace(/^https?:\/\//, '');
    }
    initClock();
    initListeners();
    fetchSummary();
    fetchEvents();
    initSSE();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
